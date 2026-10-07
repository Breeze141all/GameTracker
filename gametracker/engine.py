"""gametracker/engine.py

Core Monotonic Accumulator Engine for Game Time Tracking.
Implements the daily accumulator state machine, step-clamped delta tracking,
concurrency-invariant accumulation, 5m/1m warnings, lockout transition with
process termination, and tamper-resistant midnight rollover.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import List, Optional, Callable, Dict, Any

from gametracker.interfaces import (
    IClock,
    IProcessEnumerator,
    IProcessTerminator,
    INotificationDispatcher,
    IStateStore,
    IClockGuard,
    ProcessEntry,
)


@dataclass
class AccumulatorState:
    """Serializable runtime state of the daily accumulator."""
    day_key: str
    cumulative_seconds: float = 0.0
    daily_limit_seconds: float = 7200.0  # 120 minutes = 7200.0 seconds
    lockout_active: bool = False
    notified_5min: bool = False
    notified_1min: bool = False
    last_wall_time_utc: float = 0.0
    last_uptime_seconds: float = 0.0
    tamper_detected: bool = False
    tamper_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AccumulatorState:
        """Construct AccumulatorState from dictionary safely."""
        return cls(
            day_key=str(data.get("day_key", "")),
            cumulative_seconds=float(data.get("cumulative_seconds", 0.0)),
            daily_limit_seconds=float(data.get("daily_limit_seconds", 7200.0)),
            lockout_active=bool(data.get("lockout_active", False)),
            notified_5min=bool(data.get("notified_5min", False)),
            notified_1min=bool(data.get("notified_1min", False)),
            last_wall_time_utc=float(data.get("last_wall_time_utc", 0.0)),
            last_uptime_seconds=float(data.get("last_uptime_seconds", 0.0)),
            tamper_detected=bool(data.get("tamper_detected", False)),
            tamper_code=data.get("tamper_code"),
        )


@dataclass(frozen=True, slots=True)
class TickReport:
    """Detailed immutable summary report generated after each engine tick."""
    timestamp_mono: float
    wall_time_utc: float
    local_date: str
    delta_clamped: float
    cumulative_seconds: float
    active_games_count: int
    active_pids: List[int]
    terminated_pids: List[int]
    lockout_active: bool
    notifications_sent: List[int]
    rollover_occurred: bool
    tamper_detected: bool


class GameTrackerEngine:
    """Monotonic accumulator engine governing game time tracking, warnings, and lockout.

    Guarantees:
    1. Concurrency Invariance: Running N >= 1 games concurrently advances counter at 1:1 rate.
    2. Monotonicity: Counter never decrements within a calendar day.
    3. Step Clamping: Delays / sleep intervals > step_clamp_seconds are clamped to prevent artificial inflation.
    4. Anti-Tamper Resistance: Backward clock shifts or forward leaps freeze reset transitions.
    5. Sub-2s SLA: Active games terminated immediately on lockout transition and during lockout.
    """

    def __init__(
        self,
        clock: IClock,
        process_enumerator: IProcessEnumerator,
        is_game_predicate: Callable[[ProcessEntry], bool],
        terminator: IProcessTerminator,
        notifier: INotificationDispatcher,
        state_store: Optional[IStateStore] = None,
        clock_guard: Optional[IClockGuard] = None,
        daily_limit_seconds: float = 7200.0,
        step_clamp_seconds: float = 2.0,
    ) -> None:
        self.clock = clock
        self.process_enumerator = process_enumerator
        self.is_game_predicate = is_game_predicate
        self.terminator = terminator
        self.notifier = notifier
        self.state_store = state_store
        self.clock_guard = clock_guard
        self.daily_limit_seconds = float(daily_limit_seconds)
        self.step_clamp_seconds = float(step_clamp_seconds)

        self._last_mono: float = self.clock.monotonic()
        self._last_wall: float = self.clock.wall_time_utc()

        # Initialize or restore state
        self.state: AccumulatorState = self._initialize_state()

    def _initialize_state(self) -> AccumulatorState:
        """Restore previous state from store or initialize fresh daily accumulator."""
        current_date = self.clock.local_date_str()
        current_mono = self.clock.monotonic()
        current_wall = self.clock.wall_time_utc()

        if self.state_store is not None:
            persisted = self.state_store.load_state()
            if persisted:
                restored = AccumulatorState.from_dict(persisted)
                restored.daily_limit_seconds = self.daily_limit_seconds

                # Boot backward clock tamper check
                if self.clock_guard is not None and hasattr(self.clock_guard, "verify_boot_state"):
                    boot_res = self.clock_guard.verify_boot_state(persisted, self.daily_limit_seconds)
                    if boot_res.tamper_detected:
                        restored.tamper_detected = True
                        if boot_res.events:
                            restored.tamper_code = boot_res.events[0].tamper_type.value
                        else:
                            restored.tamper_code = "TAMPER_CLOCK_BACKWARD_BOOT"
                else:
                    if restored.last_wall_time_utc > 0.0:
                        if current_wall < (restored.last_wall_time_utc - 5.0):
                            restored.tamper_detected = True
                            restored.tamper_code = "TAMPER_CLOCK_BACKWARD_BOOT"

                # Check if persisted state is for today
                if restored.day_key == current_date:
                    self._last_mono = current_mono
                    self._last_wall = current_wall
                    return restored
                else:
                    # Date rollover occurred while daemon was stopped
                    can_reset = not restored.tamper_detected
                    if self.clock_guard is not None and hasattr(self.clock_guard, "can_reset_midnight"):
                        can_reset = self.clock_guard.can_reset_midnight(current_date, restored.day_key)

                    if can_reset:
                        # Clean rollover
                        return AccumulatorState(
                            day_key=current_date,
                            cumulative_seconds=0.0,
                            daily_limit_seconds=self.daily_limit_seconds,
                            lockout_active=False,
                            notified_5min=False,
                            notified_1min=False,
                            last_wall_time_utc=current_wall,
                            last_uptime_seconds=current_mono,
                            tamper_detected=False,
                        )
                    else:
                        # Tamper detected across reboot: preserve lockout state
                        restored.day_key = current_date
                        restored.last_wall_time_utc = current_wall
                        restored.last_uptime_seconds = current_mono
                        return restored

        # Default clean state
        return AccumulatorState(
            day_key=current_date,
            cumulative_seconds=0.0,
            daily_limit_seconds=self.daily_limit_seconds,
            lockout_active=False,
            notified_5min=False,
            notified_1min=False,
            last_wall_time_utc=current_wall,
            last_uptime_seconds=current_mono,
            tamper_detected=False,
        )

    def tick(self) -> TickReport:
        """Execute a single polling iteration of the tracking and enforcement engine."""
        curr_mono = self.clock.monotonic()
        curr_wall = self.clock.wall_time_utc()
        curr_date = self.clock.local_date_str()

        # 1. Delta timing calculation with step clamping
        raw_dt = curr_mono - self._last_mono
        wall_dt = curr_wall - self._last_wall
        dt_clamped = max(0.0, min(raw_dt, self.step_clamp_seconds))

        # 2. Clock guard / anti-tamper verification
        if self.clock_guard is not None:
            step_valid = self.clock_guard.check_runtime_step(curr_wall, self._last_wall, curr_mono, self._last_mono)
            if not step_valid or self.clock_guard.is_tampered():
                self.state.tamper_detected = True
                self.state.tamper_code = self.clock_guard.tamper_reason() or "TAMPER_DETECTED"
        else:
            # Inline fallback tamper verification
            if curr_wall < (self._last_wall - 5.0):
                self.state.tamper_detected = True
                self.state.tamper_code = "TAMPER_CLOCK_BACKWARD_RUNTIME"
            elif wall_dt > (raw_dt + 60.0):
                self.state.tamper_detected = True
                self.state.tamper_code = "TAMPER_CLOCK_FORWARD_ANOMALY"

        # 3. Midnight rollover check
        rollover_occurred = False
        if curr_date != self.state.day_key:
            allowed = True
            if self.state.lockout_active:
                elapsed_wall = curr_wall - self.state.last_wall_time_utc
                elapsed_mono = curr_mono - self.state.last_uptime_seconds
                admin_cleared = (
                    self.clock_guard is not None
                    and getattr(self.clock_guard, "_admin_override", False)
                )
                if not admin_cleared and elapsed_wall < 60.0 and elapsed_mono < 60.0:
                    allowed = False
            if self.clock_guard is not None:
                if hasattr(self.clock_guard, "can_reset_midnight"):
                    allowed = allowed and self.clock_guard.can_reset_midnight(curr_date, self.state.day_key)
                elif hasattr(self.clock_guard, "is_tampered") and self.clock_guard.is_tampered():
                    allowed = False
            if self.state.tamper_detected:
                allowed = False

            if allowed:
                # Clean rollover permitted
                self.state.day_key = curr_date
                self.state.cumulative_seconds = 0.0
                self.state.lockout_active = False
                self.state.notified_5min = False
                self.state.notified_1min = False
                rollover_occurred = True

        # 4. Enumerate processes and evaluate game presence predicate
        all_processes = self.process_enumerator.enumerate_processes()
        active_games: List[ProcessEntry] = [p for p in all_processes if self.is_game_predicate(p)]
        active_pids: List[int] = [p.pid for p in active_games]
        game_active = len(active_games) > 0

        # 5. Accumulate elapsed time (Concurrency Invariant: increment once regardless of game count)
        if game_active and not self.state.lockout_active:
            self.state.cumulative_seconds += dt_clamped

        # 6. Warning notifications dispatch
        notifications_sent: List[int] = []
        if not self.state.lockout_active:
            remaining = self.state.daily_limit_seconds - self.state.cumulative_seconds
            # 5-minute threshold (remaining <= 300.0s)
            if remaining <= 300.0 and not self.state.notified_5min:
                self.notifier.notify(
                    5,
                    "Game Time Warning",
                    f"5 minutes of game time remaining today ({int(self.state.cumulative_seconds // 60)} / {int(self.state.daily_limit_seconds // 60)} min used).",
                )
                self.state.notified_5min = True
                notifications_sent.append(5)

            # 1-minute threshold (remaining <= 60.0s)
            if remaining <= 60.0 and not self.state.notified_1min:
                self.notifier.notify(
                    1,
                    "Game Time Warning",
                    f"1 minute remaining! Active games will close shortly ({int(self.state.cumulative_seconds // 60)} / {int(self.state.daily_limit_seconds // 60)} min used).",
                )
                self.state.notified_1min = True
                notifications_sent.append(1)

        # 7. Lockout transition
        if self.state.cumulative_seconds >= self.state.daily_limit_seconds:
            if not self.state.lockout_active:
                self.state.lockout_active = True
                self.notifier.notify(
                    0,
                    "Daily Limit Reached",
                    f"Daily game time limit of {int(self.state.daily_limit_seconds // 60)} minutes reached. Access locked until midnight.",
                )
                notifications_sent.append(0)

        # 8. Process termination SLA enforcement
        terminated_pids: List[int] = []
        if self.state.lockout_active and active_games:
            for game_proc in active_games:
                if self.terminator.terminate(game_proc.pid):
                    terminated_pids.append(game_proc.pid)

        # 9. Bookkeeping & Persistence
        self.state.last_wall_time_utc = curr_wall
        self.state.last_uptime_seconds = curr_mono
        self._last_mono = curr_mono
        self._last_wall = curr_wall

        if self.state_store is not None:
            self.state_store.save_state(self.state.to_dict())

        return TickReport(
            timestamp_mono=curr_mono,
            wall_time_utc=curr_wall,
            local_date=curr_date,
            delta_clamped=dt_clamped,
            cumulative_seconds=self.state.cumulative_seconds,
            active_games_count=len(active_games),
            active_pids=active_pids,
            terminated_pids=terminated_pids,
            lockout_active=self.state.lockout_active,
            notifications_sent=notifications_sent,
            rollover_occurred=rollover_occurred,
            tamper_detected=self.state.tamper_detected,
        )

    def save_state(self) -> bool:
        """Explicitly persist current engine state to configured state store."""
        if self.state_store is not None:
            return self.state_store.save_state(self.state.to_dict())
        return False
