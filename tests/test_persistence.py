"""tests/test_persistence.py

Unit test suite for GameTracker state persistence and crash resilience.
Validates:
- Schema initialization and validation invariants
- Canonical JSON normalization and checksum integrity (SHA-256 & HMAC-SHA256)
- Atomic file writes and .tmp cleanup
- Failover recovery from .bak on corruption or tampering
- Automatic primary/backup healing
- Catastrophic corruption handling and fail-closed defensive lockdown
- Multi-threaded concurrency safety
- Transient Windows file lock retry behavior
"""

from __future__ import annotations
import os
import json
import time
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from gametracker.security.persistence import (
    TrackerState,
    StatePersistence,
    StateIntegrityError,
    StateValidationError,
    compute_checksum,
    verify_checksum,
    canonical_json_bytes,
    SCHEMA_VERSION,
    DEFAULT_DAILY_LIMIT_SECONDS,
)


class TestPersistenceSchemaAndChecksum(unittest.TestCase):
    """Test schema dataclass and cryptographic checksum verification."""

    def test_tracker_state_default_invariants(self) -> None:
        state = TrackerState(day_key="2026-10-06")
        state.validate()
        self.assertEqual(state.version, SCHEMA_VERSION)
        self.assertEqual(state.cumulative_seconds, 0.0)
        self.assertEqual(state.daily_limit_seconds, DEFAULT_DAILY_LIMIT_SECONDS)
        self.assertFalse(state.lockout_active)
        self.assertFalse(state.notified_5min)
        self.assertFalse(state.notified_1min)
        self.assertFalse(state.tamper_detected)
        self.assertEqual(state.tamper_log, [])

    def test_schema_validation_rejects_negative_cumulative_time(self) -> None:
        state = TrackerState(day_key="2026-10-06", cumulative_seconds=-10.0)
        with self.assertRaises(StateValidationError):
            state.validate()

    def test_schema_validation_rejects_invalid_limit(self) -> None:
        state = TrackerState(day_key="2026-10-06", daily_limit_seconds=0.0)
        with self.assertRaises(StateValidationError):
            state.validate()

    def test_canonical_json_ignores_checksum_key_and_sorts(self) -> None:
        payload1 = {"b": 2, "a": 1, "checksum": "deadbeef"}
        payload2 = {"a": 1, "b": 2, "checksum": "foobar"}
        bytes1 = canonical_json_bytes(payload1)
        bytes2 = canonical_json_bytes(payload2)
        self.assertEqual(bytes1, bytes2)
        self.assertEqual(bytes1, b'{"a":1,"b":2}')

    def test_checksum_verification_sha256(self) -> None:
        payload = {
            "version": 1,
            "day_key": "2026-10-06",
            "cumulative_seconds": 3600.0,
            "daily_limit_seconds": 7200.0,
            "lockout_active": False,
        }
        ck = compute_checksum(payload)
        payload["checksum"] = ck
        self.assertTrue(verify_checksum(payload))

        # Modifying any single field must invalidate checksum
        payload_tampered = dict(payload, cumulative_seconds=0.0)
        self.assertFalse(verify_checksum(payload_tampered))

        payload_tampered2 = dict(payload, lockout_active=True)
        self.assertFalse(verify_checksum(payload_tampered2))

        payload_tampered3 = dict(payload, day_key="2026-10-07")
        self.assertFalse(verify_checksum(payload_tampered3))

    def test_checksum_verification_hmac_sha256(self) -> None:
        secret = b"ParentalSuperSecretKey2026"
        payload = {"version": 1, "cumulative_seconds": 5000.0}
        hmac_ck = compute_checksum(payload, secret_key=secret)
        payload["checksum"] = hmac_ck

        # Matches with valid key
        self.assertTrue(verify_checksum(payload, secret_key=secret))
        # Fails with wrong key
        self.assertFalse(verify_checksum(payload, secret_key=b"WrongKey"))
        # Fails with unkeyed verification
        self.assertFalse(verify_checksum(payload, secret_key=None))


class TestStatePersistenceFileOperations(unittest.TestCase):
    """Test disk operations: atomic writes, fsync, failover, and healing."""

    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="gametracker_test_")
        self.state_path = Path(self.test_dir) / "state.json"
        self.bak_path = Path(self.test_dir) / "state.json.bak"
        self.persistence = StatePersistence(
            state_file_path=self.state_path,
            backup_file_path=self.bak_path,
            retry_delay_seconds=0.005,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_fresh_installation_load_returns_none(self) -> None:
        self.assertIsNone(self.persistence.load_state())

    def test_fresh_installation_load_defensive_returns_clean_state(self) -> None:
        state_dict = self.persistence.load_state_defensive(fallback_day_key="2026-10-06")
        self.assertEqual(state_dict["day_key"], "2026-10-06")
        self.assertEqual(state_dict["cumulative_seconds"], 0.0)
        self.assertFalse(state_dict["lockout_active"])
        self.assertFalse(state_dict["tamper_detected"])

    def test_atomic_save_and_load_roundtrip(self) -> None:
        initial = TrackerState(
            day_key="2026-10-06",
            cumulative_seconds=4200.5,
            lockout_active=False,
            last_wall_time_utc=1791312000.0,
            last_uptime_seconds=5000.0,
        )
        saved = self.persistence.save_state(initial)
        self.assertTrue(saved)

        self.assertTrue(self.state_path.exists())
        self.assertTrue(self.bak_path.exists())

        # Verify no .tmp files were leaked
        all_files = list(Path(self.test_dir).glob("*.tmp"))
        self.assertEqual(len(all_files), 0)

        # Load and verify contents
        loaded = self.persistence.load_state()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["day_key"], "2026-10-06")
        self.assertEqual(loaded["cumulative_seconds"], 4200.5)
        self.assertEqual(loaded["last_wall_time_utc"], 1791312000.0)
        self.assertTrue(verify_checksum(loaded))

    def test_failover_to_backup_on_corrupt_primary_syntax(self) -> None:
        # Save valid state first
        state = TrackerState(day_key="2026-10-06", cumulative_seconds=6900.0, notified_5min=True)
        self.persistence.save_state(state)

        # Truncate / corrupt primary state file
        with open(self.state_path, "w", encoding="utf-8") as f:
            f.write("{\"corrupted_json_syntax: truncated...")

        # Load state must seamlessly failover to backup
        recovered = self.persistence.load_state()
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["cumulative_seconds"], 6900.0)
        self.assertTrue(recovered["notified_5min"])
        self.assertTrue(recovered["tamper_detected"])
        self.assertTrue(any("FAILOVER_TO_BACKUP" in log for log in recovered["tamper_log"]))

        # Primary must have been auto-healed
        with open(self.state_path, "r", encoding="utf-8") as f:
            healed_json = json.load(f)
        self.assertTrue(verify_checksum(healed_json))
        self.assertEqual(healed_json["cumulative_seconds"], 6900.0)

    def test_failover_to_backup_on_tampered_primary_checksum(self) -> None:
        # Save valid state
        state = TrackerState(day_key="2026-10-06", cumulative_seconds=7150.0, lockout_active=True)
        self.persistence.save_state(state)

        # Malicious user tampers with cumulative_seconds without updating checksum
        with open(self.state_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        raw_data["cumulative_seconds"] = 100.0  # Reset timer to 100s
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(raw_data, f)

        # Load state rejects tampered primary and restores legitimate counter from backup
        recovered = self.persistence.load_state()
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["cumulative_seconds"], 7150.0)
        self.assertTrue(recovered["lockout_active"])
        self.assertTrue(recovered["tamper_detected"])

    def test_primary_auto_heals_corrupt_backup(self) -> None:
        # Save valid state
        state = TrackerState(day_key="2026-10-06", cumulative_seconds=3000.0)
        self.persistence.save_state(state)

        # Corrupt backup file
        with open(self.bak_path, "w", encoding="utf-8") as f:
            f.write("corrupt backup bytes")

        # Loading valid primary should auto-heal backup
        loaded = self.persistence.load_state()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["cumulative_seconds"], 3000.0)

        # Check backup is healed
        with open(self.bak_path, "r", encoding="utf-8") as f:
            healed_bak = json.load(f)
        self.assertTrue(verify_checksum(healed_bak))
        self.assertEqual(healed_bak["cumulative_seconds"], 3000.0)

    def test_catastrophic_double_corruption_raises_integrity_error(self) -> None:
        # Both files contain corrupted data
        with open(self.state_path, "w", encoding="utf-8") as f:
            f.write("bad primary")
        with open(self.bak_path, "w", encoding="utf-8") as f:
            f.write("bad backup")

        with self.assertRaises(StateIntegrityError):
            self.persistence.load_state()

    def test_catastrophic_double_corruption_triggers_fail_closed_defensive_lockdown(self) -> None:
        with open(self.state_path, "w", encoding="utf-8") as f:
            f.write("bad primary")
        with open(self.bak_path, "w", encoding="utf-8") as f:
            f.write("bad backup")

        # In defensive mode, corruption must result in full lockdown to prevent unauthorized play
        defensive = self.persistence.load_state_defensive(
            fallback_day_key="2026-10-06",
            daily_limit=7200.0,
        )
        self.assertEqual(defensive["cumulative_seconds"], 7200.0)
        self.assertTrue(defensive["lockout_active"])
        self.assertTrue(defensive["tamper_detected"])
        self.assertTrue(any("DEFENSIVE_LOCKDOWN" in log for log in defensive["tamper_log"]))

    def test_concurrent_multithreaded_save_and_load(self) -> None:
        """Verify thread safety under high-frequency concurrent writes and reads."""
        num_threads = 6
        iterations_per_thread = 25
        errors: list[str] = []

        def worker(thread_id: int) -> None:
            try:
                for i in range(iterations_per_thread):
                    seconds = float(thread_id * 1000 + i)
                    s = TrackerState(day_key="2026-10-06", cumulative_seconds=seconds)
                    self.persistence.save_state(s)
                    loaded = self.persistence.load_state()
                    if loaded is None or loaded["cumulative_seconds"] < 0:
                        errors.append(f"Invalid read: {loaded}")
                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"Thread {thread_id} error: {e}")

        threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Thread concurrency errors: {errors}")

    def test_safe_replace_retries_on_transient_permission_error(self) -> None:
        """Verify _safe_replace retries and succeeds when hitting transient PermissionError."""
        attempts = 0
        original_replace = os.replace

        def flaky_replace(src: os.PathLike, dst: os.PathLike) -> None:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise PermissionError("[WinError 5] Access is denied (simulated transient lock)")
            return original_replace(src, dst)

        state = TrackerState(day_key="2026-10-06", cumulative_seconds=123.0)
        try:
            os.replace = flaky_replace  # type: ignore[assignment]
            saved = self.persistence.save_state(state)
            self.assertTrue(saved)
            self.assertGreaterEqual(attempts, 3)
        finally:
            os.replace = original_replace

        loaded = self.persistence.load_state()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["cumulative_seconds"], 123.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
