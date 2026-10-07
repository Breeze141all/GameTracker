"""tests/test_anti_tamper.py

Unit tests for ClockGuard anti-tamper security supervisor using VirtualClock.
"""

from __future__ import annotations
import unittest
import threading

from gametracker.security.clock_guard import (
    ClockGuard,
    TamperType,
)
from tests.mock_clock import VirtualClock


class TestAntiTamper(unittest.TestCase):
    def setUp(self) -> None:
        # 2026-10-06 18:40:00 UTC, uptime 1000s, UTC offset 0
        self.clock = VirtualClock(initial_wall_utc=1791312000.0, initial_uptime=1000.0, tz_offset_hours=0.0)
        self.guard = ClockGuard(self.clock, backward_tolerance_seconds=5.0, forward_anomaly_threshold_seconds=60.0)

    def test_tc_at01_monotonic_parity_normal(self) -> None:
        """TC-AT1: Monotonic clock matches Win32 uptime within tolerance."""
        res_boot = self.guard.verify_boot_state(None)
        self.assertTrue(res_boot.valid)
        self.clock.advance(5.0)
        res = self.guard.evaluate_tick()
        self.assertFalse(res.tamper_detected)
        self.assertFalse(res.tamper_active)

    def test_tc_at02_monotonic_divergence_tamper(self) -> None:
        """TC-AT2: Divergence between monotonic clock and Win32 GetTickCount64 flags tampering."""
        self.guard.verify_boot_state(None)
        self.clock.advance(1.0)
        self.guard.evaluate_tick()

        # Simulate hooked monotonic clock deviating by 2.5s
        self.clock.corrupt_monotonic(2.5)
        res = self.guard.evaluate_tick()
        self.assertTrue(res.tamper_detected)
        self.assertTrue(res.tamper_active)
        self.assertEqual(res.events[0].tamper_type, TamperType.MONOTONIC_DIVERGENCE)
        self.assertIn("GetTickCount64", res.events[0].message)

    def test_tc_at03_runtime_backward_shift_detected(self) -> None:
        """TC-AT3: Backward wall clock shift > 5s flags tamper and blocks midnight reset."""
        self.guard.verify_boot_state(None)
        self.clock.advance(1.0)
        self.guard.evaluate_tick()

        # Roll back wall clock by 3600 seconds
        self.clock.warp_wall_clock(-3600.0)
        res = self.guard.evaluate_tick()
        self.assertTrue(res.tamper_detected)
        self.assertTrue(res.tamper_active)
        self.assertEqual(res.events[0].tamper_type, TamperType.BACKWARD_SHIFT_RUNTIME)
        self.assertFalse(res.allow_midnight_reset)
        self.assertFalse(self.guard.can_reset_midnight("2026-10-07", "2026-10-06"))

    def test_tc_at04_runtime_backward_shift_within_tolerance(self) -> None:
        """TC-AT4: Minor backward NTP slew <= 5s is tolerated without alarm."""
        self.guard.verify_boot_state(None)
        self.clock.advance(1.0)
        self.guard.evaluate_tick()

        # Minor slew of -3.0s
        self.clock.warp_wall_clock(-3.0)
        res = self.guard.evaluate_tick()
        self.assertFalse(res.tamper_detected)
        self.assertFalse(res.tamper_active)

    def test_tc_at05_runtime_forward_jump_anomaly_detected(self) -> None:
        """TC-AT5: Runtime forward leap > monotonic + 60s flags tamper and blocks midnight reset."""
        self.guard.verify_boot_state(None)
        self.clock.advance(1.0)
        self.guard.evaluate_tick()

        # Leap forward 7200s (2 hours) while monotonic only increments 1s
        self.clock.advance(1.0)
        self.clock.warp_wall_clock(7200.0)
        res = self.guard.evaluate_tick()
        self.assertTrue(res.tamper_detected)
        self.assertTrue(res.tamper_active)
        self.assertEqual(res.events[0].tamper_type, TamperType.FORWARD_JUMP_ANOMALY)
        self.assertFalse(res.allow_midnight_reset)
        self.assertFalse(self.guard.can_reset_midnight("2026-10-07", "2026-10-06"))

    def test_tc_at06_runtime_forward_progression_within_threshold(self) -> None:
        """TC-AT6: Forward progression <= 60s leap does not trigger anomaly."""
        self.guard.verify_boot_state(None)
        self.clock.advance(1.0)
        self.guard.evaluate_tick()

        # Leap forward 30s
        self.clock.advance(1.0)
        self.clock.warp_wall_clock(30.0)
        res = self.guard.evaluate_tick()
        self.assertFalse(res.tamper_detected)
        self.assertFalse(res.tamper_active)

    def test_tc_at07_boot_backward_shift_detected(self) -> None:
        """TC-AT7: Boot wall clock earlier than persisted timestamp flags tamper."""
        persisted = {
            "last_wall_time_utc": 1791312000.0,
            "cumulative_seconds": 3600.0,
            "lockout_active": False,
            "tamper_detected": False,
            "day_key": "2026-10-06",
        }
        # Boot clock rolled back 10,000 seconds
        self.clock.warp_wall_clock(-10000.0)
        res = self.guard.verify_boot_state(persisted)
        self.assertFalse(res.valid)
        self.assertTrue(res.tamper_detected)
        self.assertEqual(res.events[0].tamper_type, TamperType.BACKWARD_SHIFT_BOOT)
        self.assertFalse(res.allow_midnight_reset)

    def test_tc_at08_boot_backward_shift_restores_accumulator_and_lockout(self) -> None:
        """TC-AT8: Boot backward shift restores accumulator and enforces active lockout."""
        persisted = {
            "last_wall_time_utc": 1791312000.0,
            "cumulative_seconds": 7200.0,
            "lockout_active": True,
            "tamper_detected": False,
            "day_key": "2026-10-06",
        }
        # User rolls back clock by 5 hours across reboot to try clearing lockout
        self.clock.warp_wall_clock(-18000.0)
        res = self.guard.verify_boot_state(persisted, daily_limit_seconds=7200.0)
        self.assertEqual(res.cumulative_seconds, 7200.0)
        self.assertTrue(res.lockout_active)
        self.assertFalse(res.allow_midnight_reset)

    def test_tc_at09_boot_normal_forward_same_day(self) -> None:
        """TC-AT9: Normal reboot 10 minutes later within same day is valid."""
        persisted = {
            "last_wall_time_utc": 1791312000.0,
            "cumulative_seconds": 4000.0,
            "lockout_active": False,
            "tamper_detected": False,
            "day_key": "2026-10-06",
        }
        self.clock.warp_wall_clock(600.0)  # +10 minutes
        res = self.guard.verify_boot_state(persisted)
        self.assertTrue(res.valid)
        self.assertFalse(res.tamper_detected)
        self.assertEqual(res.cumulative_seconds, 4000.0)
        self.assertFalse(res.lockout_active)

    def test_tc_at10_high_watermark_blocks_reset_during_rollback(self) -> None:
        """TC-AT10: While wall time remains below high-watermark, tamper state persists."""
        self.guard.verify_boot_state(None)
        self.clock.advance(10.0)
        self.guard.evaluate_tick()

        # Shift backward 1000s
        self.clock.warp_wall_clock(-1000.0)
        self.guard.evaluate_tick()
        self.assertTrue(self.guard.is_tamper_active)

        # Subsequent normal tick in rolled-back timeline
        self.clock.advance(1.0)
        res = self.guard.evaluate_tick()
        self.assertTrue(self.guard.is_tamper_active)
        self.assertFalse(res.allow_midnight_reset)

    def test_tc_at11_can_reset_midnight_valid_progression(self) -> None:
        """TC-AT11: Legitimate midnight rollover with forward progress succeeds."""
        self.guard.verify_boot_state(None)
        self.clock.advance(10.0)
        self.guard.evaluate_tick()
        self.assertTrue(self.guard.can_reset_midnight("2026-10-07", "2026-10-06"))

    def test_tc_at12_can_reset_midnight_blocks_date_rollback(self) -> None:
        """TC-AT12: Rolling back calendar date rejects midnight reset."""
        self.guard.verify_boot_state(None)
        self.assertFalse(self.guard.can_reset_midnight("2026-10-06", "2026-10-07"))

    def test_tc_at13_system_power_resume_notification(self) -> None:
        """TC-AT13: Power resume notification updates references preventing false forward anomaly."""
        self.guard.verify_boot_state(None)
        self.clock.advance(1.0)
        self.guard.evaluate_tick()

        # Simulate laptop lid closed for 8 hours
        self.clock.warp_wall_clock(28800.0)
        # Windows Service receives power resume broadcast and notifies clock guard
        self.guard.notify_system_resume(self.clock.wall_time_utc(), self.clock.monotonic())

        # Next tick does NOT trigger forward anomaly
        self.clock.advance(1.0)
        res = self.guard.evaluate_tick()
        self.assertFalse(res.tamper_detected)
        self.assertFalse(res.tamper_active)

    def test_tc_at14_admin_override_clears_tamper(self) -> None:
        """TC-AT14: Authenticated admin override clears tamper latch."""
        self.guard.verify_boot_state(None)
        self.clock.warp_wall_clock(-500.0)
        self.guard.evaluate_tick()
        self.assertTrue(self.guard.is_tamper_active)

        self.guard.acknowledge_admin_override()
        self.assertFalse(self.guard.is_tamper_active)

        # Can now reset midnight if legitimate
        self.assertTrue(self.guard.can_reset_midnight("2026-10-07", "2026-10-06"))

    def test_tc_at15_thread_safety_concurrent_ticks(self) -> None:
        """TC-AT15: Concurrent tick evaluations across multiple threads do not corrupt state."""
        self.guard.verify_boot_state(None)
        exceptions = []

        def worker():
            try:
                for _ in range(50):
                    self.guard.evaluate_tick()
            except Exception as e:
                exceptions.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(exceptions), 0)


if __name__ == "__main__":
    unittest.main()
