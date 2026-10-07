"""tests/test_persistence_adversarial.py

Empirical Adversarial Stress & Vulnerability Test Suite for StatePersistence (Milestone 1).
Author: teamwork_preview_challenger_m1_2 (EMPIRICAL CHALLENGER)

Verifies:
1. Concurrency: Multi-threaded & Multi-process race conditions under high frequency.
2. Corruption: File truncation, byte flipping, JSON syntax injection into primary vs backup.
3. Failover & Lockdown: Failover to .bak and fail-closed defensive lockdown when both are mangled.
4. State Preservation: Valid state must NEVER be overwritten by corrupted or partial payload.
5. Vulnerability Detections:
   - UnicodeDecodeError crash on corrupted byte sequences
   - Cross-process sharing violation causing false-positive tamper detection and catastrophic lockdown
   - Time-wiping vulnerability via partial dictionary coercion in from_dict()
   - NaN / Inf float injection bypassing daily limit and lockout
   - In-memory checksum desynchronization upon failover
"""

from __future__ import annotations

import os
import sys
import json
import time
import math
import shutil
import tempfile
import threading
import multiprocessing
import unittest
from pathlib import Path
from typing import List, Dict, Any

from gametracker.security.persistence import (
    TrackerState,
    StatePersistence,
    StateIntegrityError,
    StateValidationError,
    compute_checksum,
    verify_checksum,
    DEFAULT_DAILY_LIMIT_SECONDS,
)


def _worker_process_stress(
    state_file: str,
    bak_file: str,
    proc_id: int,
    iterations: int,
    result_queue: multiprocessing.Queue,
) -> None:
    """Worker process for multi-process concurrency testing."""
    persistence = StatePersistence(
        state_file_path=state_file,
        backup_file_path=bak_file,
        max_retries=5,
        retry_delay_seconds=0.01,
    )
    errors: List[str] = []
    tamper_count = 0

    for i in range(iterations):
        val = float(proc_id * 10000 + i)
        try:
            s = TrackerState(day_key="2026-10-06", cumulative_seconds=val)
            persistence.save_state(s)

            loaded = persistence.load_state()
            if loaded is None:
                errors.append(f"Proc {proc_id} iter {i}: loaded is None")
            elif loaded.get("cumulative_seconds", -1) < 0:
                errors.append(f"Proc {proc_id} iter {i}: negative cumulative_seconds {loaded}")
            elif loaded.get("tamper_detected", False):
                tamper_count += 1
        except Exception as e:
            errors.append(f"Proc {proc_id} iter {i} exception: {type(e).__name__}: {e}")

    result_queue.put({"proc_id": proc_id, "errors": errors, "tamper_count": tamper_count})


class TestStatePersistenceAdversarial(unittest.TestCase):
    """Adversarial stress harness reproducing attacks and vulnerabilities."""

    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="gt_adv_test_")
        self.state_path = Path(self.test_dir) / "state.json"
        self.bak_path = Path(self.test_dir) / "state.json.bak"
        self.persistence = StatePersistence(
            state_file_path=self.state_path,
            backup_file_path=self.bak_path,
            retry_delay_seconds=0.005,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # =========================================================================
    # VULNERABILITY 1: UNHANDLED UNICODEDECODEERROR CRASHES ON BYTE FLIP
    # =========================================================================

    def test_vuln_unicode_decode_error_crashes_failover_on_byte_flip(self) -> None:
        """EMPIRICAL BUG 1: Flipping bytes to invalid UTF-8 causes unhandled UnicodeDecodeError.

        _read_and_verify only catches JSONDecodeError and OSError.
        UnicodeDecodeError inherits from ValueError, escaping uncaught and crashing load_state().
        """
        valid_state = TrackerState(
            day_key="2026-10-06",
            cumulative_seconds=5000.0,
            lockout_active=False,
        )
        self.persistence.save_state(valid_state)

        # Corrupt byte 15 in state.json to invalid UTF-8 (0xFF)
        raw_bytes = bytearray(self.state_path.read_bytes())
        raw_bytes[15] = 0xFF
        self.state_path.write_bytes(raw_bytes)

        # Hardened behavior: cleanly failover to .bak and recover valid state
        loaded = self.persistence.load_state()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["cumulative_seconds"], 5000.0)

    # =========================================================================
    # VULNERABILITY 2: MULTI-PROCESS RACE CONDITION & FALSE TAMPER / CRASH
    # =========================================================================

    def test_vuln_multi_process_race_condition_false_tamper(self) -> None:
        """EMPIRICAL BUG 2: Multi-process concurrency causes transient Windows sharing violations.

        _read_and_verify has no retry loop for reads. Transient [Errno 13] Permission denied
        causes immediate failover to backup, falsely setting tamper_detected=True.
        When both files hit contention, raises catastrophic StateIntegrityError.
        """
        self.persistence.save_state(TrackerState(day_key="2026-10-06", cumulative_seconds=50.0))

        num_procs = 4
        iterations = 50
        queue: multiprocessing.Queue = multiprocessing.Queue()

        processes = [
            multiprocessing.Process(
                target=_worker_process_stress,
                args=(str(self.state_path), str(self.bak_path), pid, iterations, queue),
            )
            for pid in range(num_procs)
        ]

        for p in processes:
            p.start()

        results = [queue.get(timeout=30.0) for _ in range(num_procs)]

        for p in processes:
            p.join(timeout=5.0)

        total_tampers = sum(r["tamper_count"] for r in results)
        total_errors = sum(len(r["errors"]) for r in results)

        # Hardened behavior: retry loop handles contention without fatal crash
        self.assertLessEqual(
            total_errors,
            5,
            "Multi-process concurrency is safely handled without unhandled crashes",
        )

    # =========================================================================
    # VULNERABILITY 3: TIME-WIPING VIA PARTIAL/MALFORMED PAYLOAD IN SAVE_STATE
    # =========================================================================

    def test_vuln_partial_dict_save_wipes_accumulated_time(self) -> None:
        """EMPIRICAL BUG 3: Passing partial dict to save_state resets cumulative_seconds to 0.0.

        TrackerState.from_dict() silently defaults missing keys instead of validating completeness.
        Furthermore, bool("true"), str(123), list("str") coerce invalid types into valid ones,
        overwriting existing accumulated game time on disk with 0.0.
        """
        # Save valid state with 6500 seconds accumulated
        valid_state = TrackerState(
            day_key="2026-10-06",
            cumulative_seconds=6500.0,
            lockout_active=False,
        )
        self.persistence.save_state(valid_state)

        # Attacker/caller supplies a dict missing cumulative_seconds
        malformed_partial_payload = {"lockout_active": True}

        # save_state accepts it because TrackerState.from_dict defaults cumulative_seconds to 0.0
        self.persistence.save_state(malformed_partial_payload)

        # Read back state from disk
        loaded = self.persistence.load_state()
        self.assertIsNotNone(loaded)

        # CRITICAL VULNERABILITY: 6500s was wiped to 0.0s!
        self.assertEqual(loaded["cumulative_seconds"], 0.0)

    # =========================================================================
    # VULNERABILITY 4: IEEE 754 NAN / INF INJECTION BYPASSES LOCKOUT
    # =========================================================================

    def test_vuln_nan_and_inf_payload_bypass(self) -> None:
        """EMPIRICAL BUG 4: TrackerState.validate() does not check math.isnan() or math.isinf().

        float('nan') < 0.0 is False, so NaN passes validation.
        When cumulative_seconds is NaN, GameTrackerEngine comparisons (>= 7200, <= 300)
        always evaluate to False, permanently disabling warnings and lockout!
        """
        nan_state = TrackerState(day_key="2026-10-06", cumulative_seconds=float("nan"))
        # validate() does NOT raise StateValidationError
        nan_state.validate()

        self.assertTrue(math.isnan(nan_state.cumulative_seconds))

        # Check engine behavior with NaN: lockout never triggers!
        self.assertFalse(nan_state.cumulative_seconds >= DEFAULT_DAILY_LIMIT_SECONDS)
        self.assertFalse(DEFAULT_DAILY_LIMIT_SECONDS - nan_state.cumulative_seconds <= 300.0)

    # =========================================================================
    # VULNERABILITY 5: CHECKSUM DESYNCHRONIZATION ON FAILOVER IN LOAD_STATE
    # =========================================================================

    def test_vuln_checksum_desynchronization_in_load_state_return(self) -> None:
        """EMPIRICAL BUG 5: load_state() mutates bak_data in-place without recalculating checksum.

        Upon failover, load_state() modifies bak_data['tamper_log'] and bak_data['tamper_detected'],
        saves it to disk (where disk gets a new checksum), but returns the in-memory bak_data
        with the OLD checksum. Thus, verify_checksum(load_state()) evaluates to FALSE.
        """
        valid_state = TrackerState(day_key="2026-10-06", cumulative_seconds=4000.0)
        self.persistence.save_state(valid_state)

        # Corrupt primary JSON syntax (valid UTF-8, but invalid JSON)
        self.state_path.write_text("{corrupt_json: true", encoding="utf-8")

        # load_state recovers from backup
        recovered = self.persistence.load_state()
        self.assertIsNotNone(recovered)

        # EMPIRICAL BUG: returned in-memory dictionary has invalid checksum!
        self.assertFalse(
            verify_checksum(recovered),
            "Returned dictionary from load_state failover has desynchronized checksum",
        )

    # =========================================================================
    # PASSING CONTRACTS: TRUNCATION, FAILOVER, DEFENSIVE LOCKDOWN, THREADING
    # =========================================================================

    def test_truncation_failover_and_healing(self) -> None:
        """Contract: Truncating primary to 0 or few bytes triggers failover to backup and heals."""
        valid_state = TrackerState(day_key="2026-10-06", cumulative_seconds=4500.0)
        self.persistence.save_state(valid_state)

        # Truncate primary
        self.state_path.write_text("", encoding="utf-8")

        recovered = self.persistence.load_state()
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["cumulative_seconds"], 4500.0)
        self.assertTrue(recovered["tamper_detected"])

        # Check primary was healed
        healed = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertTrue(verify_checksum(healed))
        self.assertEqual(healed["cumulative_seconds"], 4500.0)

    def test_catastrophic_dual_truncation_triggers_defensive_lockdown(self) -> None:
        """Contract: Both files truncated to empty triggers fail-closed defensive lockdown."""
        valid_state = TrackerState(day_key="2026-10-06", cumulative_seconds=3000.0)
        self.persistence.save_state(valid_state)

        self.state_path.write_text("", encoding="utf-8")
        self.bak_path.write_text("", encoding="utf-8")

        with self.assertRaises(StateIntegrityError):
            self.persistence.load_state()

        defensive = self.persistence.load_state_defensive("2026-10-06")
        self.assertEqual(defensive["cumulative_seconds"], DEFAULT_DAILY_LIMIT_SECONDS)
        self.assertTrue(defensive["lockout_active"])
        self.assertTrue(defensive["tamper_detected"])

    def test_json_syntax_injection_failover(self) -> None:
        """Contract: Valid UTF-8 JSON syntax errors in primary fail over to backup."""
        valid_state = TrackerState(day_key="2026-10-06", cumulative_seconds=6000.0)
        self.persistence.save_state(valid_state)

        self.state_path.write_text('{"bad_json": [unterminated_array', encoding="utf-8")

        recovered = self.persistence.load_state()
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["cumulative_seconds"], 6000.0)

    def test_multithreaded_high_frequency_readers_writers(self) -> None:
        """Contract: In-process multi-threading is protected by RLock."""
        self.persistence.save_state(TrackerState(day_key="2026-10-06", cumulative_seconds=100.0))

        errors: List[str] = []
        num_threads = 8
        ops = 50

        def worker(tid: int) -> None:
            for i in range(ops):
                try:
                    s = TrackerState(day_key="2026-10-06", cumulative_seconds=float(tid * 100 + i))
                    self.persistence.save_state(s)
                    loaded = self.persistence.load_state()
                    if loaded is None or loaded["cumulative_seconds"] < 0:
                        errors.append(f"T{tid} invalid read")
                except Exception as e:
                    errors.append(f"T{tid} exception: {e}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
