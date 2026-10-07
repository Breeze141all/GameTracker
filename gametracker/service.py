"""gametracker/service.py

Main Service Daemon orchestrating all GameTracker subsystems.
Runs as a resilient Windows background daemon or Windows Service.
"""

from __future__ import annotations
import os
import sys
import time
import signal
import logging
from pathlib import Path
from typing import Optional

from gametracker.clock import SystemClock
from gametracker.config import ConfigManager, TrackerConfig
from gametracker.detector import (
    Win32ProcessEnumerator,
    LauncherScanner,
    create_game_predicate,
)
from gametracker.terminator import Win32ProcessTerminator
from gametracker.notifier import WindowsNotificationDispatcher
from gametracker.security.persistence import StatePersistence
from gametracker.security.clock_guard import ClockGuard
from gametracker.engine import GameTrackerEngine, TickReport

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("gametracker.service")


class GameTrackerDaemon:
    """The central daemon loop coordinating tracking, enforcement, and persistence."""

    def __init__(self, config_dir: Optional[str] = None) -> None:
        if config_dir:
            self.base_dir = Path(config_dir)
        else:
            appdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
            self.base_dir = Path(appdata) / "GameTracker"

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.config_manager = ConfigManager(str(self.base_dir / "config.json"))
        self.config = self.config_manager.load()

        self.clock = SystemClock()
        self.enumerator = Win32ProcessEnumerator()
        self.scanner = LauncherScanner(self.config)
        self.is_game = create_game_predicate(self.config, self.scanner)
        self.terminator = Win32ProcessTerminator()
        self.notifier = WindowsNotificationDispatcher()

        self.state_store = StatePersistence(
            data_dir=str(self.base_dir),
            auto_heal=True,
        )
        self.clock_guard = ClockGuard(clock=self.clock)

        daily_limit_sec = float(self.config.daily_limit_minutes * 60)
        self.engine = GameTrackerEngine(
            clock=self.clock,
            process_enumerator=self.enumerator,
            is_game_predicate=self.is_game,
            terminator=self.terminator,
            notifier=self.notifier,
            state_store=self.state_store,
            clock_guard=self.clock_guard,
            daily_limit_seconds=daily_limit_sec,
            step_clamp_seconds=2.0,
        )

        self._running = False
        self._last_save_time = 0.0

    def start(self) -> None:
        """Run the main daemon tracking loop."""
        self._running = True
        logger.info(
            f"GameTracker Service started. Daily limit: {self.config.daily_limit_minutes} minutes. "
            f"State storage: {self.base_dir}"
        )

        # Register OS signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        tick_counter = 0
        while self._running:
            try:
                report: TickReport = self.engine.tick()

                # Refresh game roots periodically (every ~60 seconds)
                tick_counter += 1
                if tick_counter % 60 == 0:
                    self.scanner.refresh()

                # Log important state changes
                if report.rollover_occurred:
                    logger.info(f"Midnight rollover executed for date: {report.local_date}")
                if report.terminated_pids:
                    logger.warning(f"Lockout enforcement terminated PIDs: {report.terminated_pids}")
                if report.notifications_sent:
                    logger.info(f"Warning notifications dispatched for remaining mins: {report.notifications_sent}")

                # Save state periodically every 10 seconds or immediately on lockout / notifications
                now = time.monotonic()
                if (
                    (now - self._last_save_time >= 10.0)
                    or report.rollover_occurred
                    or bool(report.terminated_pids)
                    or bool(report.notifications_sent)
                ):
                    self.engine.save_state()
                    self._last_save_time = now

                time.sleep(1.0)
            except Exception as e:
                logger.error(f"Error in tracking loop iteration: {e}", exc_info=True)
                time.sleep(1.0)

        # Final save before shutdown
        self.engine.save_state()
        logger.info("GameTracker Service shut down cleanly.")

    def stop(self) -> None:
        """Signal the daemon loop to stop."""
        self._running = False

    def _handle_signal(self, signum, frame) -> None:
        logger.info(f"Received termination signal ({signum}). Initiating shutdown...")
        self.stop()


def run_daemon() -> None:
    daemon = GameTrackerDaemon()
    daemon.start()


if __name__ == "__main__":
    run_daemon()
