"""gametracker/clock.py

Production implementation of IClock interface using native Windows OS timers.
Leverages time.monotonic(), time.time(), and Win32 kernel32.GetTickCount64().
"""

from __future__ import annotations
import time
import datetime
import ctypes
from typing import Optional
from gametracker.interfaces import IClock


class SystemClock(IClock):
    """Production clock querying native OS timers and Win32 API."""

    def __init__(self) -> None:
        self._kernel32 = None
        try:
            self._kernel32 = ctypes.windll.kernel32
        except Exception:
            pass

    def monotonic(self) -> float:
        """Return system monotonic uptime in seconds."""
        return time.monotonic()

    def wall_time_utc(self) -> float:
        """Return current Unix epoch timestamp in UTC seconds."""
        return time.time()

    def local_date_str(self) -> str:
        """Return local calendar date formatted as YYYY-MM-DD."""
        return datetime.date.today().isoformat()

    def get_win32_uptime(self) -> Optional[float]:
        """Query kernel32.GetTickCount64() in seconds."""
        if self._kernel32 and hasattr(self._kernel32, "GetTickCount64"):
            try:
                self._kernel32.GetTickCount64.restype = ctypes.c_uint64
                ticks = self._kernel32.GetTickCount64()
                return float(ticks) / 1000.0
            except Exception:
                pass
        return None
