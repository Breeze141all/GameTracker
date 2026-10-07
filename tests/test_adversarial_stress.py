"""tests/test_adversarial_stress.py

Adversarial Stress Test Suite for Milestone 1: ClockGuard and GameTrackerEngine.
Empirically stress-tests:
1. Erratic wall clock oscillations (+100s, -500s, +3600s, -7200s, etc.) over hundreds of cycles.
2. Rapid midnight crossing attempts and calendar day rollbacks.
3. Strict monotonicity verification: accumulator NEVER decrements under any attack.
4. Premature reset prevention under tampered conditions.
5. High-throughput performance benchmarking (<1.0 second SLA for hundreds of attack cycles).
"""

from __future__ import annotations
import unittest
import time
import random
from datetime import datetime, timedelta
from typing import List

from gametracker.interfaces import ProcessEntry, IProcessEnumerator, IProcessTerminator, INotificationDispatcher
from gametracker.security.clock_guard import ClockGuard, TamperType
from gametracker.engine import GameTrackerEngine
from tests.mock_clock import VirtualClock


class DummyProcessEnumerator(IProcessEnumerator):
    def __init__(self, processes: List[ProcessEntry] | None = None) -> None:
        self.processes = list(processes or [])

    def enumerate_processes(self) -> List[ProcessEntry]:
        return list(self.processes)


class DummyProcessTerminator(IProcessTerminator):
    def __init__(self) -> None:
        self.terminated_pids: List[int] = []

    def terminate(self, pid: int) -> bool:
        self.terminated_pids.append(pid)
        return True


class DummyNotificationDispatcher(INotificationDispatcher):
    def __init__(self) -> None:
        self.notifications: List[tuple[int, str, str]] = []

    def notify(self, remaining_minutes: int, title: str, message: str) -> bool:
        self.notifications.append((remaining_minutes, title, message))
        return True


class TestAdversarialStress(unittest.TestCase):
    """Adversarial challenge test harness for ClockGuard and GameTrackerEngine."""

    def setUp(self) -> None:
        self.start_wall = 1791312000.0  # 2026-10-06 18:40:00 UTC
        self.start_mono = 1000.0
        self.clock = VirtualClock(
            initial_wall_utc=self.start_wall,
            initial_uptime=self.start_mono,
            tz_offset_hours=0.0,
        )
        self.guard = ClockGuard(
            self.clock,
            backward_tolerance_seconds=5.0,
            forward_anomaly_threshold_seconds=60.0,
            monotonic_divergence_tolerance_seconds=1.0,
        )
        self.enumerator = DummyProcessEnumerator([
            ProcessEntry(pid=4001, name="doom.exe", exe_path="C:\\Games\\doom.exe"),
        ])
        self.terminator = DummyProcessTerminator()
        self.notifier = DummyNotificationDispatcher()
        self.engine = GameTrackerEngine(
            clock=self.clock,
            process_enumerator=self.enumerator,
            is_game_predicate=lambda p: p.name.endswith(".exe"),
            terminator=self.terminator,
            notifier=self.notifier,
            clock_guard=self.guard,
            daily_limit_seconds=7200.0,
            step_clamp_seconds=2.0,
        )

    def test_adv01_erratic_oscillations_stress(self) -> None:
        """Adversarial Test 1: Erratic wall clock oscillations (+100s, -500s, +3600s, -7200s).

        Verifies that:
        - Hundreds of erratic oscillation cycles execute in < 1 second.
        - Accumulator is strictly non-decreasing (never decrements).
        - Tamper state is permanently latched and detected.
        """
        attack_deltas = [+100.0, -500.0, +3600.0, -7200.0, +150.0, -250.0, +5000.0, -10000.0]
        num_cycles = 500  # 500 attack cycles

        prev_cumulative = self.engine.state.cumulative_seconds
        t_start = time.perf_counter()

        for cycle in range(num_cycles):
            # Advance monotonic realistically by 1s
            self.clock.advance(1.0)

            # Inject erratic wall clock warp
            warp = attack_deltas[cycle % len(attack_deltas)]
            self.clock.warp_wall_clock(warp)

            report = self.engine.tick()

            # Monotonic invariant: accumulator must never decrement
            self.assertGreaterEqual(
                report.cumulative_seconds,
                prev_cumulative,
                f"Cycle {cycle}: Accumulator decremented from {prev_cumulative} to {report.cumulative_seconds}!"
            )
            self.assertGreaterEqual(
                self.engine.state.cumulative_seconds,
                prev_cumulative,
                f"Cycle {cycle}: Engine state cumulative_seconds decremented!"
            )

            # Clamping invariant: step must not exceed step_clamp_seconds
            self.assertLessEqual(report.delta_clamped, 2.0)

            # Security invariant: tamper must be detected and latched
            self.assertTrue(self.guard.is_tamper_active)
            self.assertTrue(self.engine.state.tamper_detected)

            prev_cumulative = report.cumulative_seconds

        elapsed = time.perf_counter() - t_start
        # Performance invariant: 500 attack cycles must finish in < 1.0 second
        self.assertLess(elapsed, 1.0, f"500 attack cycles took {elapsed:.4f}s, exceeding 1.0s limit!")

    def test_adv02_rapid_midnight_crossing_attempts(self) -> None:
        """Adversarial Test 2: Rapid midnight crossing attempts and backward rollback across calendar days.

        Verifies that:
        - Fast-forwarding clock past midnight (e.g. +3600s, +86400s) does NOT trigger clean rollover.
        - Rolling back across calendar days (e.g. to yesterday or year 2000) does NOT reset or decrement counter.
        - Lockout remains fully active and unbypassed throughout the attack.
        """
        # First, accrue 7200s to enter active lockout
        self.engine.state.cumulative_seconds = 7200.0
        self.engine.state.lockout_active = True
        self.clock.advance(1.0)
        self.engine.tick()
        self.assertTrue(self.engine.state.lockout_active)
        self.assertEqual(self.engine.state.cumulative_seconds, 7200.0)
        self.assertEqual(self.engine.state.day_key, "2026-10-06")

        t_start = time.perf_counter()

        # Attack sequence: alternating violent forward leaps across midnight and backward day rollbacks
        attack_dates = [
            ("2026-10-07", +21600.0),   # 6 hours forward into tomorrow
            ("2026-10-06", -21600.0),   # Jump back to today
            ("2026-10-05", -86400.0),   # Roll back to yesterday
            ("2026-10-08", +259200.0),  # Leap forward 3 days
            ("2026-10-01", -604800.0),  # Roll back 1 week
            ("2020-01-01", -200000000.0), # Roll back years
            ("2030-12-31", +300000000.0), # Leap years ahead
            ("2026-10-07", -133000000.0), # Roll back to next day
        ]

        for target_date, wall_delta in attack_dates * 20:  # 160 attack cycles
            self.clock.advance(1.0)
            self.clock.warp_wall_clock(wall_delta)
            year, month, day = map(int, target_date.split("-"))
            self.clock.set_local_date(year, month, day)

            report = self.engine.tick()

            # Under NO attack pattern should rollover succeed or lockout be cleared
            self.assertFalse(
                report.rollover_occurred,
                f"Premature midnight reset succeeded during attack to {target_date}!"
            )
            self.assertTrue(
                report.lockout_active,
                f"Lockout bypassed during attack to {target_date}!"
            )
            self.assertEqual(
                report.cumulative_seconds,
                7200.0,
                f"Accumulator altered during attack to {target_date}: {report.cumulative_seconds}"
            )
            self.assertTrue(self.guard.is_tamper_active)
            self.assertTrue(self.engine.state.tamper_detected)

        elapsed = time.perf_counter() - t_start
        self.assertLess(elapsed, 1.0, f"Rapid midnight crossing attacks took {elapsed:.4f}s, exceeding 1.0s!")

    def test_adv03_randomized_fuzzing_clock_chaos(self) -> None:
        """Adversarial Test 3: High-entropy randomized chaos fuzzing of clock inputs.

        Applies random monotonic deltas, random wall warps, random dates over 300 cycles.
        Assures cumulative_seconds is monotonically non-decreasing and bounds are preserved.
        """
        rng = random.Random(0xDEADBEEF)
        prev_cum = self.engine.state.cumulative_seconds

        t_start = time.perf_counter()

        for cycle in range(300):
            dt_mono = rng.uniform(-10.0, 50.0)  # Monotonic drift (including negative anomaly)
            dt_wall = rng.uniform(-50000.0, 50000.0)  # Massive wall shifts
            target_year = rng.randint(2020, 2030)
            target_month = rng.randint(1, 12)
            target_day = rng.randint(1, 28)

            # Advance or skew monotonic
            if dt_mono >= 0:
                self.clock.advance(dt_mono)
            else:
                self.clock.corrupt_monotonic(dt_mono)

            # Skew wall and date
            self.clock.warp_wall_clock(dt_wall)
            self.clock.set_local_date(target_year, target_month, target_day)

            report = self.engine.tick()

            # Monotonicity check
            self.assertGreaterEqual(
                report.cumulative_seconds,
                prev_cum,
                f"Cycle {cycle}: Accumulator decremented from {prev_cum} to {report.cumulative_seconds}!"
            )
            prev_cum = report.cumulative_seconds

        elapsed = time.perf_counter() - t_start
        self.assertLess(elapsed, 1.0, f"Chaos fuzzing took {elapsed:.4f}s, exceeding 1.0s!")

    def test_adv04_legitimate_midnight_rollover_after_admin_override(self) -> None:
        """Adversarial Test 4: Verify tamper latch blocks rollover until explicit admin authorization.

        Once admin clears tamper via acknowledge_admin_override, legitimate midnight rollover
        must succeed cleanly without deadlocking.
        """
        self.engine.state.cumulative_seconds = 7200.0
        self.engine.state.lockout_active = True

        # 1. Attacker tampers clock
        self.clock.warp_wall_clock(-3600.0)
        self.clock.advance(1.0)
        self.engine.tick()
        self.assertTrue(self.guard.is_tamper_active)
        self.assertTrue(self.engine.state.tamper_detected)

        # 2. Advance to legitimate next day without clearing tamper
        self.clock.advance(86400.0)
        self.clock.set_local_date(2026, 10, 7)
        report = self.engine.tick()
        self.assertFalse(report.rollover_occurred)
        self.assertTrue(self.engine.state.lockout_active)

        # 3. Admin acknowledges and overrides
        self.guard.acknowledge_admin_override()
        self.engine.state.tamper_detected = False
        self.enumerator.processes = []

        # 4. Next tick legitimately rolls over with 0 seconds accrued
        self.clock.advance(1.0)
        report = self.engine.tick()
        self.assertTrue(report.rollover_occurred)
        self.assertEqual(self.engine.state.day_key, "2026-10-07")
        self.assertEqual(self.engine.state.cumulative_seconds, 0.0)
        self.assertFalse(self.engine.state.lockout_active)

    def test_adv05_vulnerability_incremental_forward_creep(self) -> None:
        """Adversarial Test 5 (VULNERABILITY): Incremental forward creep (+54s/tick) bypasses ClockGuard.

        Attack Vector:
        An attacker increments wall clock by +54s each tick (55s total wall delta).
        Because delta_wall (55s) < delta_mono (1s) + forward_threshold (60s), ClockGuard
        never detects tamper per-step. In 349 ticks (~350s of monotonic time), the wall clock
        crosses midnight into tomorrow and triggers an unauthorized midnight reset,
        clearing the active lockout 5.5 hours prematurely.
        """
        self.engine.state.cumulative_seconds = 7200.0
        self.engine.state.lockout_active = True

        premature_rollover = False
        # Stepping forward by 55s per tick (under 60s forward anomaly threshold)
        # 6 hours until midnight = 21,600s. 21,600 / 55 ~= 393 ticks.
        for tick in range(400):
            self.clock.advance(1.0)
            self.clock.warp_wall_clock(54.0)  # total wall delta = 55s per tick
            report = self.engine.tick()
            if report.rollover_occurred:
                premature_rollover = True
                break

        self.assertFalse(
            premature_rollover,
            f"CRITICAL VULNERABILITY: Premature midnight reset succeeded at tick {tick}! "
            f"ClockGuard failed to detect cumulative drift; lockout was cleared after only "
            f"{self.clock.monotonic() - 1000.0:.1f}s of monotonic uptime."
        )

    def test_adv06_vulnerability_timezone_advancement(self) -> None:
        """Adversarial Test 6 (VULNERABILITY): Timezone advancement to tomorrow bypasses lockout.

        Attack Vector:
        User changes system timezone forward (e.g. UTC-4 to UTC+12), advancing local date
        to tomorrow without modifying UTC wall time or monotonic uptime.
        ClockGuard.can_reset_midnight accepts the date string advancement and clears lockout.
        """
        from datetime import timezone

        self.engine.state.cumulative_seconds = 7200.0
        self.engine.state.lockout_active = True

        # User changes timezone forward so local date becomes tomorrow
        self.clock._tz_offset = 12.0
        tz = timezone(timedelta(hours=12.0))
        self.clock._local_dt = datetime.fromtimestamp(self.clock._wall_utc, tz=tz).replace(tzinfo=None)

        self.clock.advance(1.0)
        report = self.engine.tick()

        self.assertFalse(
            report.rollover_occurred,
            "CRITICAL VULNERABILITY: Premature midnight reset succeeded via timezone advancement! "
            "Lockout was bypassed without legitimate time passage."
        )


if __name__ == "__main__":
    unittest.main()
