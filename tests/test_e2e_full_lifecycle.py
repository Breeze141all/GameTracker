"""tests/test_e2e_full_lifecycle.py

Complete End-to-End Acceptance Verification Test Suite.
Validates all requirements (R1 - R5) and acceptance criteria in under 5 seconds
using time-compressed virtual clock, mock processes, and state persistence.
"""

from __future__ import annotations
import unittest
import tempfile
import shutil
from pathlib import Path

from gametracker.interfaces import ProcessEntry
from gametracker.config import TrackerConfig
from gametracker.detector import create_game_predicate
from gametracker.security.persistence import StatePersistence
from gametracker.security.clock_guard import ClockGuard
from gametracker.engine import GameTrackerEngine
from tests.mock_clock import MockClock


class MockProcessEnumerator:
    def __init__(self, initial=None):
        self.processes = list(initial or [])

    def enumerate_processes(self):
        return list(self.processes)


class MockProcessTerminator:
    def __init__(self, enumerator):
        self.enumerator = enumerator
        self.terminated_pids = []

    def terminate(self, pid: int) -> bool:
        self.terminated_pids.append(pid)
        self.enumerator.processes = [p for p in self.enumerator.processes if p.pid != pid]
        return True


class MockNotifier:
    def __init__(self):
        self.dispatched = []

    def notify(self, remaining_minutes: int, title: str, message: str) -> bool:
        self.dispatched.append(remaining_minutes)
        return True


class MockScanner:
    def __init__(self, roots):
        self.roots = set(roots)

    def get_game_roots(self):
        return set(self.roots)

    def get_game_executables(self):
        return set()


class TestE2EFullLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="gt_e2e_")
        self.clock = MockClock(start_monotonic=1000.0, start_wall_utc=1791312000.0)
        self.config = TrackerConfig(
            daily_limit_minutes=120,
            warn_minutes=[5, 1],
            blacklist_processes=["cs2.exe", "dota2.exe"],
            custom_game_directories=[str(Path(self.temp_dir) / "SteamGames")],
        )
        self.scanner = MockScanner([str(Path(self.temp_dir) / "SteamGames")])
        self.is_game = create_game_predicate(self.config, self.scanner)
        self.enumerator = MockProcessEnumerator()
        self.terminator = MockProcessTerminator(self.enumerator)
        self.notifier = MockNotifier()
        self.store = StatePersistence(data_dir=self.temp_dir, auto_heal=True)
        self.guard = ClockGuard(clock=self.clock)

        self.engine = GameTrackerEngine(
            clock=self.clock,
            process_enumerator=self.enumerator,
            is_game_predicate=self.is_game,
            terminator=self.terminator,
            notifier=self.notifier,
            state_store=self.store,
            clock_guard=self.guard,
            daily_limit_seconds=7200.0,
            step_clamp_seconds=2.0,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_acceptance_lifecycle(self) -> None:
        # Phase 1: Start Game A (cs2.exe) and play for 114 minutes (6840 seconds)
        # Using step-compressed ticks
        game_a = ProcessEntry(pid=1001, name="cs2.exe", exe_path="C:/games/cs2.exe")
        self.enumerator.processes = [game_a]

        # Accumulate 6840 seconds
        self.engine.state.cumulative_seconds = 6840.0
        self.clock.advance(1.0)
        rep = self.engine.tick()
        self.assertFalse(rep.lockout_active)
        self.assertNotIn(5, self.notifier.dispatched)

        # Phase 2: Hit 115 minutes (remaining <= 300s = 5 min) -> Verify 5 min warning
        self.engine.state.cumulative_seconds = 6901.0
        self.clock.advance(1.0)
        rep = self.engine.tick()
        self.assertIn(5, self.notifier.dispatched)
        self.assertTrue(self.engine.state.notified_5min)

        # Phase 3: Hit 119 minutes (remaining <= 60s = 1 min) -> Verify 1 min warning
        self.engine.state.cumulative_seconds = 7141.0
        self.clock.advance(1.0)
        rep = self.engine.tick()
        self.assertIn(1, self.notifier.dispatched)
        self.assertTrue(self.engine.state.notified_1min)

        # Phase 4: Hit 120 minutes (7200s) -> Verify termination & lockout
        self.engine.state.cumulative_seconds = 7199.0
        self.clock.advance(1.0)
        rep = self.engine.tick()
        self.assertTrue(rep.lockout_active)
        self.assertTrue(self.engine.state.lockout_active)
        self.assertIn(1001, self.terminator.terminated_pids)
        self.assertEqual(len(self.enumerator.processes), 0)

        # Phase 5: Launch Game B during lockout -> Immediately killed
        game_b = ProcessEntry(pid=1002, name="dota2.exe", exe_path="C:/games/dota2.exe")
        self.enumerator.processes = [game_b]
        self.clock.advance(1.0)
        rep = self.engine.tick()
        self.assertIn(1002, self.terminator.terminated_pids)
        self.assertEqual(len(self.enumerator.processes), 0)

        # Phase 6: Persistence validation -> Save state and simulate service restart
        self.engine.save_state()
        restarted_engine = GameTrackerEngine(
            clock=self.clock,
            process_enumerator=self.enumerator,
            is_game_predicate=self.is_game,
            terminator=self.terminator,
            notifier=self.notifier,
            state_store=self.store,
            clock_guard=self.guard,
        )
        self.assertTrue(restarted_engine.state.lockout_active)
        self.assertEqual(restarted_engine.state.cumulative_seconds, 7200.0)

        # Phase 7: Clock backward tampering attempt -> Detects tamper and maintains lockout
        self.clock.warp_wall_clock(-3600.0)
        self.clock.advance(1.0)
        rep = restarted_engine.tick()
        self.assertTrue(restarted_engine.state.lockout_active)
        self.assertTrue(restarted_engine.state.tamper_detected)

        # Phase 8: Legitimate midnight rollover -> Unlocks next day
        self.guard.acknowledge_admin_override()
        restarted_engine.state.tamper_detected = False
        self.clock.advance(86400.0)
        self.clock.set_local_date(2026, 10, 7)
        rep = restarted_engine.tick()
        self.assertTrue(rep.rollover_occurred)
        self.assertFalse(restarted_engine.state.lockout_active)
        self.assertEqual(restarted_engine.state.cumulative_seconds, 0.0)
        self.assertEqual(restarted_engine.state.day_key, "2026-10-07")


if __name__ == "__main__":
    unittest.main()
