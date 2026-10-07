"""gametracker package.

Windows Game Time Tracking Background Service.
"""

from gametracker.interfaces import (
    ProcessEntry,
    IClock,
    IProcessEnumerator,
    ILauncherScanner,
    IProcessTerminator,
    INotificationDispatcher,
    IStateStore,
    IClockGuard,
)
from gametracker.engine import (
    GameTrackerEngine,
    AccumulatorState,
    TickReport,
)

__all__ = [
    "ProcessEntry",
    "IClock",
    "IProcessEnumerator",
    "ILauncherScanner",
    "IProcessTerminator",
    "INotificationDispatcher",
    "IStateStore",
    "IClockGuard",
    "GameTrackerEngine",
    "AccumulatorState",
    "TickReport",
]
