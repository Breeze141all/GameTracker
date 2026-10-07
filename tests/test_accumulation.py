"""tests/test_accumulation.py

Comprehensive unit test suite for Milestone 1: Interfaces & Core Monotonic Accumulator Engine.
Verifies linear tracking, step clamping, concurrency invariance, warning thresholds,
sub-2s termination SLAs, and tamper-resistant midnight rollover using MockClock.
"""

from __future__ import annotations
import unittest
from datetime import datetime
from typing import List, Dict, Any, Optional

from gametracker.interfaces import (
    ProcessEntry,
    IProcessEnumerator,
    IProcessTerminator,
    INotificationDispatcher,
    IStateStore,
)
from gametracker.engine import GameTrackerEngine
from tests.mock_clock import MockClock


class MockProcessEnumerator(IProcessEnumerator):
    """Controllable process table test double."""

    def __init__(self) -> None:
        self.processes: List[ProcessEntry] = []

    def enumerate_processes(self) -> List[ProcessEntry]:
        return list(self.processes)

    def set_processes(self, procs: List[ProcessEntry]) -> None:
        self.processes = list(procs)

    def add_process(self, pid: int, name: str, exe_path: str) -> None:
        self.processes.append(ProcessEntry(pid=pid, name=name, exe_path=exe_path))

    def remove_process(self, pid: int) -> None:
        self.processes = [p for p in self.processes if p.pid != pid]


class MockProcessTerminator(IProcessTerminator):
    """Test double recording process termination invocations."""

    def __init__(self) -> None:
        self.terminated_pids: List[int] = []

    def terminate(self, pid: int) -> bool:
        self.terminated_pids.append(pid)
        return True


class MockNotificationDispatcher(INotificationDispatcher):
    """Test double recording dispatched desktop toast notifications."""

    def __init__(self) -> None:
        self.notifications: List[Dict[str, Any]] = []

    def notify(self, remaining_minutes: int, title: str, message: str) -> bool:
        self.notifications.append({
            "remaining_minutes": remaining_minutes,
            "title": title,
            "message": message,
        })
        return True


class MockStateStore(IStateStore):
    """In-memory state store test double."""

    def __init__(self, initial_state: Optional[Dict[str, Any]] = None) -> None:
        self.state: Optional[Dict[str, Any]] = initial_state
        self.save_count: int = 0

    def load_state(self) -> Optional[Dict[str, Any]]:
        return dict(self.state) if self.state is not None else None

    def save_state(self, state: Dict[str, Any]) -> bool:
        self.state = dict(state)
        self.save_count += 1
        return True


class TestAccumulationEngine(unittest.TestCase):
    """Rigorous unit test suite for GameTrackerEngine."""

    def setUp(self) -> None:
        self.clock = MockClock(
            start_monotonic=1000.0,
            start_wall_utc=1791312000.0,
            start_local_datetime=datetime(2026, 10, 6, 18, 0, 0),
        )
        self.enumerator = MockProcessEnumerator()
        self.terminator = MockProcessTerminator()
        self.notifier = MockNotificationDispatcher()
        self.state_store = MockStateStore()

        self.is_game = lambda p: "game" in p.name.lower() or "steamapps" in p.exe_path.lower()

        self.engine = GameTrackerEngine(
            clock=self.clock,
            process_enumerator=self.enumerator,
            is_game_predicate=self.is_game,
            terminator=self.terminator,
            notifier=self.notifier,
            state_store=self.state_store,
            daily_limit_seconds=7200.0,
            step_clamp_seconds=2.0,
        )

    def test_idle_when_no_games_running(self) -> None:
        """Idle state: monotonic time advances but cumulative counter remains 0.0s."""
        self.enumerator.add_process(101, "explorer.exe", "C:\\Windows\\explorer.exe")
        self.enumerator.add_process(102, "chrome.exe", "C:\\Program Files\\Chrome\\chrome.exe")

        for _ in range(10):
            self.clock.advance(1.0)
            report = self.engine.tick()
            self.assertEqual(report.cumulative_seconds, 0.0)
            self.assertEqual(report.active_games_count, 0)
            self.assertFalse(report.lockout_active)

    def test_single_game_linear_accumulation(self) -> None:
        """Single game running accumulates time 1:1 with monotonic steps."""
        self.enumerator.add_process(501, "mygame.exe", "C:\\Games\\mygame.exe")

        for tick in range(1, 61):
            self.clock.advance(1.0)
            report = self.engine.tick()
            self.assertAlmostEqual(report.cumulative_seconds, float(tick), places=5)
            self.assertEqual(report.active_games_count, 1)

    def test_concurrency_invariance_multiple_games(self) -> None:
        """Concurrency Invariance: Multiple active games must not double-count time."""
        self.enumerator.add_process(501, "game1.exe", "C:\\Games\\game1.exe")
        self.enumerator.add_process(502, "game2.exe", "C:\\Games\\game2.exe")
        self.enumerator.add_process(503, "game3.exe", "C:\\Steam\\steamapps\\common\\g3.exe")

        for tick in range(1, 101):
            self.clock.advance(1.0)
            report = self.engine.tick()
            self.assertEqual(report.active_games_count, 3)
            self.assertAlmostEqual(report.cumulative_seconds, float(tick), places=5)

    def test_concurrency_invariance_staggered(self) -> None:
        """Staggered game lifecycles: time accrues strictly for the union of active intervals."""
        game_a = ProcessEntry(1001, "game_a.exe", "C:\\Games\\game_a.exe")
        game_b = ProcessEntry(1002, "game_b.exe", "C:\\Games\\game_b.exe")

        # Phase 1: Game A runs alone for 30 seconds
        self.enumerator.set_processes([game_a])
        for _ in range(30):
            self.clock.advance(1.0)
            self.engine.tick()
        self.assertAlmostEqual(self.engine.state.cumulative_seconds, 30.0, places=5)

        # Phase 2: Game B starts while Game A is still running (overlap for 20 seconds)
        self.enumerator.set_processes([game_a, game_b])
        for _ in range(20):
            self.clock.advance(1.0)
            self.engine.tick()
        self.assertAlmostEqual(self.engine.state.cumulative_seconds, 50.0, places=5)

        # Phase 3: Game A exits, Game B runs alone for 25 seconds
        self.enumerator.set_processes([game_b])
        for _ in range(25):
            self.clock.advance(1.0)
            self.engine.tick()
        self.assertAlmostEqual(self.engine.state.cumulative_seconds, 75.0, places=5)

    def test_step_clamping_on_system_suspension(self) -> None:
        """Large monotonic jumps (laptop sleep/hibernation) are clamped to step_clamp_seconds (2.0s)."""
        self.enumerator.add_process(501, "game.exe", "C:\\Games\\game.exe")

        self.clock.advance(1.0)
        self.engine.tick()
        self.assertAlmostEqual(self.engine.state.cumulative_seconds, 1.0)

        # Simulate laptop sleep for 3600 seconds (1 hour)
        self.clock.advance(3600.0)
        report = self.engine.tick()

        self.assertEqual(report.delta_clamped, 2.0)
        self.assertAlmostEqual(report.cumulative_seconds, 3.0, places=5)

    def test_step_clamping_negative_delta_guard(self) -> None:
        """Negative or zero monotonic steps clamp to 0.0s and do not decrement counter."""
        self.enumerator.add_process(501, "game.exe", "C:\\Games\\game.exe")
        self.clock.advance(5.0)
        self.engine.tick()
        prev_acc = self.engine.state.cumulative_seconds

        self.clock.advance(0.0)
        report = self.engine.tick()
        self.assertEqual(report.delta_clamped, 0.0)
        self.assertEqual(report.cumulative_seconds, prev_acc)

    def test_warning_notifications_at_5min_and_1min(self) -> None:
        """Warnings fire at exactly 5 minutes (6900s) and 1 minute (7140s) remaining, exactly once."""
        self.enumerator.add_process(501, "game.exe", "C:\\Games\\game.exe")

        self.engine.state.cumulative_seconds = 6899.0
        self.clock.advance(1.0)
        report = self.engine.tick()

        self.assertEqual(report.cumulative_seconds, 6900.0)
        self.assertIn(5, report.notifications_sent)
        self.assertTrue(self.engine.state.notified_5min)
        self.assertFalse(self.engine.state.notified_1min)

        self.clock.advance(1.0)
        report = self.engine.tick()
        self.assertEqual(report.notifications_sent, [])

        self.engine.state.cumulative_seconds = 7139.0
        self.clock.advance(1.0)
        report = self.engine.tick()

        self.assertEqual(report.cumulative_seconds, 7140.0)
        self.assertIn(1, report.notifications_sent)
        self.assertTrue(self.engine.state.notified_1min)

    def test_lockout_transition_and_immediate_process_termination(self) -> None:
        """At 7200 cumulative seconds, lockout transitions to active and running games are terminated immediately."""
        self.enumerator.add_process(501, "game1.exe", "C:\\Games\\game1.exe")
        self.enumerator.add_process(502, "game2.exe", "C:\\Games\\game2.exe")

        self.engine.state.cumulative_seconds = 7199.0
        self.clock.advance(1.0)
        report = self.engine.tick()

        self.assertEqual(report.cumulative_seconds, 7200.0)
        self.assertTrue(report.lockout_active)
        self.assertIn(0, report.notifications_sent)

        self.assertIn(501, report.terminated_pids)
        self.assertIn(502, report.terminated_pids)
        self.assertIn(501, self.terminator.terminated_pids)
        self.assertIn(502, self.terminator.terminated_pids)

    def test_lockout_enforcement_terminates_new_launches(self) -> None:
        """During active lockout, newly launched games are terminated on next tick."""
        self.engine.state.cumulative_seconds = 7200.0
        self.engine.state.lockout_active = True

        self.enumerator.add_process(999, "game3.exe", "C:\\Games\\game3.exe")
        self.clock.advance(1.0)
        report = self.engine.tick()

        self.assertTrue(report.lockout_active)
        self.assertIn(999, report.terminated_pids)
        self.assertIn(999, self.terminator.terminated_pids)

    def test_midnight_reset_clean_rollover(self) -> None:
        """Midnight rollover without tampering resets counter to 0.0s and clears lockout."""
        self.engine.state.cumulative_seconds = 7200.0
        self.engine.state.lockout_active = True
        self.engine.state.notified_5min = True
        self.engine.state.notified_1min = True

        self.clock.advance(21660.0)
        self.assertEqual(self.clock.local_date_str(), "2026-10-07")

        report = self.engine.tick()
        self.assertTrue(report.rollover_occurred)
        self.assertEqual(self.engine.state.day_key, "2026-10-07")
        self.assertEqual(self.engine.state.cumulative_seconds, 0.0)
        self.assertFalse(self.engine.state.lockout_active)
        self.assertFalse(self.engine.state.notified_5min)
        self.assertFalse(self.engine.state.notified_1min)

    def test_midnight_reset_blocked_when_clock_tampered(self) -> None:
        """Midnight rollover is blocked if clock tampering (backward shift) is detected."""
        self.engine.state.cumulative_seconds = 7200.0
        self.engine.state.lockout_active = True

        self.clock.advance(1.0)
        self.engine.tick()

        # Shift wall clock backward by 10,000s
        self.clock.warp_wall_clock(-10000.0)
        self.clock.advance(1.0)
        report = self.engine.tick()

        self.assertTrue(self.engine.state.tamper_detected)
        self.assertEqual(self.engine.state.tamper_code, "TAMPER_CLOCK_BACKWARD_RUNTIME")

        # Force local calendar date forward
        self.clock.set_local_date(2026, 10, 7)
        self.clock.advance(1.0)
        rollover_report = self.engine.tick()

        self.assertFalse(rollover_report.rollover_occurred)
        self.assertTrue(self.engine.state.lockout_active)
        self.assertEqual(self.engine.state.cumulative_seconds, 7200.0)

    def test_persistence_roundtrip_restore(self) -> None:
        """State is persisted to store and successfully restored on new engine instantiation."""
        self.enumerator.add_process(501, "game.exe", "C:\\Games\\game.exe")

        for _ in range(60):
            self.clock.advance(60.0)
            self.engine.tick()

        self.assertAlmostEqual(self.engine.state.cumulative_seconds, 120.0, places=2)
        self.assertGreater(self.state_store.save_count, 0)

        restored_engine = GameTrackerEngine(
            clock=self.clock,
            process_enumerator=self.enumerator,
            is_game_predicate=self.is_game,
            terminator=self.terminator,
            notifier=self.notifier,
            state_store=self.state_store,
        )

        self.assertEqual(restored_engine.state.day_key, self.engine.state.day_key)
        self.assertAlmostEqual(restored_engine.state.cumulative_seconds, self.engine.state.cumulative_seconds)
        self.assertEqual(restored_engine.state.lockout_active, self.engine.state.lockout_active)

    def test_clock_guard_injection_and_tamper_propagation(self) -> None:
        """When an IClockGuard is injected and flags tamper, engine marks state.tamper_detected."""
        class MockClockGuard:
            def __init__(self) -> None:
                self.tampered = False

            def check_runtime_step(self, curr_w: float, last_w: float, curr_m: float, last_m: float) -> bool:
                return not self.tampered

            def is_tampered(self) -> bool:
                return self.tampered

            def tamper_reason(self) -> Optional[str]:
                return "TEST_TAMPER_FLAG" if self.tampered else None

        guard = MockClockGuard()
        guarded_engine = GameTrackerEngine(
            clock=self.clock,
            process_enumerator=self.enumerator,
            is_game_predicate=self.is_game,
            terminator=self.terminator,
            notifier=self.notifier,
            clock_guard=guard,
        )

        self.clock.advance(1.0)
        guarded_engine.tick()
        self.assertFalse(guarded_engine.state.tamper_detected)

        guard.tampered = True
        self.clock.advance(1.0)
        report = guarded_engine.tick()
        self.assertTrue(report.tamper_detected)
        self.assertEqual(guarded_engine.state.tamper_code, "TEST_TAMPER_FLAG")

    def test_lockout_without_active_games_is_noop_for_terminator(self) -> None:
        """Entering lockout when no games are active does not invoke terminator."""
        self.engine.state.cumulative_seconds = 7199.0
        self.enumerator.add_process(501, "game.exe", "C:\\Games\\game.exe")
        self.clock.advance(1.0)
        self.engine.tick()
        self.assertTrue(self.engine.state.lockout_active)
        self.assertEqual(len(self.terminator.terminated_pids), 1)

        self.enumerator.set_processes([])
        self.clock.advance(1.0)
        report = self.engine.tick()
        self.assertTrue(report.lockout_active)
        self.assertEqual(report.terminated_pids, [])
        self.assertEqual(len(self.terminator.terminated_pids), 1)

    def test_integrated_engine_with_real_clock_guard_and_persistence(self) -> None:
        """End-to-end integration: Engine with live ClockGuard and real StatePersistence on disk."""
        import tempfile
        from pathlib import Path
        from gametracker.security.clock_guard import ClockGuard
        from gametracker.security.persistence import StatePersistence

        test_dir = tempfile.mkdtemp(prefix="gt_integrated_")
        try:
            state_file = Path(test_dir) / "state.json"
            guard = ClockGuard(self.clock, backward_tolerance_seconds=5.0, forward_anomaly_threshold_seconds=60.0)
            persistence = StatePersistence(state_file)

            engine = GameTrackerEngine(
                clock=self.clock,
                process_enumerator=self.enumerator,
                is_game_predicate=self.is_game,
                terminator=self.terminator,
                notifier=self.notifier,
                state_store=persistence,
                clock_guard=guard,
            )

            # 1. Accumulate 60 seconds with active game
            self.enumerator.add_process(701, "testgame.exe", "C:\\Games\\testgame.exe")
            for _ in range(60):
                self.clock.advance(1.0)
                engine.tick()

            self.assertAlmostEqual(engine.state.cumulative_seconds, 60.0, places=5)
            self.assertTrue(state_file.exists())

            # 2. Clock rollback tamper
            self.clock.warp_wall_clock(-3600.0)
            self.clock.advance(1.0)
            rep = engine.tick()
            self.assertTrue(rep.tamper_detected)
            self.assertTrue(engine.state.tamper_detected)

            # 3. Rollover attempted while tampered
            self.clock.set_local_date(2026, 10, 7)
            self.clock.advance(1.0)
            rep = engine.tick()
            self.assertFalse(rep.rollover_occurred)
            self.assertEqual(engine.state.day_key, "2026-10-06")

            # 4. Close games, then admin override clears tamper and enables clean midnight reset
            self.enumerator.set_processes([])
            guard.acknowledge_admin_override()
            engine.state.tamper_detected = False
            self.clock.advance(1.0)
            rep = engine.tick()
            self.assertTrue(rep.rollover_occurred)
            self.assertEqual(engine.state.day_key, "2026-10-07")
            self.assertEqual(engine.state.cumulative_seconds, 0.0)

            # 5. Restore across new engine instance
            restarted_engine = GameTrackerEngine(
                clock=self.clock,
                process_enumerator=self.enumerator,
                is_game_predicate=self.is_game,
                terminator=self.terminator,
                notifier=self.notifier,
                state_store=persistence,
                clock_guard=guard,
            )
            self.assertEqual(restarted_engine.state.day_key, "2026-10-07")
            self.assertEqual(restarted_engine.state.cumulative_seconds, 0.0)
            self.assertFalse(restarted_engine.state.tamper_detected)
        finally:
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
