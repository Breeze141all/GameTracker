"""gametracker/interfaces.py

Strict programmatic protocols and data structures for the Game Time Tracker system.
Defines contracts for dependency injection across detection, timing, termination,
notification, persistence, and anti-tamper subsystems.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Set, Optional, Protocol, Dict, Any, runtime_checkable


@dataclass(frozen=True, slots=True)
class ProcessEntry:
    """Immutable representation of a running operating system process."""
    pid: int
    name: str
    exe_path: str
    parent_pid: int = 0


@runtime_checkable
class IClock(Protocol):
    """Abstract clock interface providing monotonic uptime, wall clock UTC, and local date."""

    def monotonic(self) -> float:
        """Return system monotonic uptime in seconds (unaffected by wall clock shifts)."""
        ...

    def wall_time_utc(self) -> float:
        """Return current Unix epoch timestamp in UTC seconds."""
        ...

    def local_date_str(self) -> str:
        """Return local calendar date formatted as YYYY-MM-DD."""
        ...


@runtime_checkable
class IProcessEnumerator(Protocol):
    """Abstract process discovery interface."""

    def enumerate_processes(self) -> List[ProcessEntry]:
        """Enumerate active processes currently running on the host system."""
        ...


@runtime_checkable
class ILauncherScanner(Protocol):
    """Abstract scanner for game launchers and library directories."""

    def get_game_roots(self) -> Set[str]:
        """Return set of normalized absolute directory paths containing game installations."""
        ...

    def get_game_executables(self) -> Set[str]:
        """Return set of normalized absolute executable paths recognized as games."""
        ...


@runtime_checkable
class IProcessTerminator(Protocol):
    """Abstract process termination interface."""

    def terminate(self, pid: int) -> bool:
        """Terminate process identified by PID. Returns True if terminated or dead, False if failed."""
        ...


@runtime_checkable
class INotificationDispatcher(Protocol):
    """Abstract notification delivery interface across session boundaries."""

    def notify(self, remaining_minutes: int, title: str, message: str) -> bool:
        """Dispatch desktop notification. remaining_minutes indicates threshold (e.g. 5, 1, 0)."""
        ...


@runtime_checkable
class IStateStore(Protocol):
    """Abstract atomic persistence store for service state."""

    def load_state(self) -> Optional[Dict[str, Any]]:
        """Load persisted state dictionary, or None if no valid persisted state exists."""
        ...

    def save_state(self, state: Dict[str, Any]) -> bool:
        """Atomically persist state dictionary to disk. Returns True on success."""
        ...


@runtime_checkable
class IClockGuard(Protocol):
    """Abstract anti-tamper clock guard interface."""

    def check_runtime_step(
        self,
        curr_wall: float,
        last_wall: float,
        curr_mono: float,
        last_mono: float,
    ) -> bool:
        """Verify runtime timing integrity. Returns False and flags tampering on anomaly."""
        ...

    def is_tampered(self) -> bool:
        """Return True if any clock tampering or backward shift has been flagged."""
        ...

    def tamper_reason(self) -> Optional[str]:
        """Return the reason/code for clock tampering, or None if clean."""
        ...
