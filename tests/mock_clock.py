"""tests/mock_clock.py

High-performance virtual clock test harness for Game Time Tracker.
Enables instant time-compression simulation (thousands of virtual seconds in <1ms)
and fine-grained anti-tamper clock warping.
"""

from __future__ import annotations
import datetime
from typing import Optional

from gametracker.interfaces import IClock


class MockClock(IClock):
    """Virtual test clock implementing IClock.

    Supports synchronous advancement, natural calendar day rollover,
    and arbitrary wall-clock warping to simulate user tampering or NTP shifts.
    """

    def __init__(
        self,
        start_monotonic: float = 1000.0,
        start_wall_utc: float = 1791312000.0,  # 2026-10-06 18:40:00 UTC
        start_local_datetime: Optional[datetime.datetime] = None,
        initial_wall_utc: Optional[float] = None,
        initial_uptime: Optional[float] = None,
        tz_offset_hours: float = 0.0,
    ) -> None:
        if initial_uptime is not None:
            start_monotonic = initial_uptime
        if initial_wall_utc is not None:
            start_wall_utc = initial_wall_utc

        self._mono: float = float(start_monotonic)
        self._monotonic: float = self._mono
        self._wall_utc: float = float(start_wall_utc)
        self._win32_uptime: float = float(start_monotonic)
        self._tz_offset: float = float(tz_offset_hours)

        if start_local_datetime is not None:
            self._local_dt = start_local_datetime
        else:
            tz = datetime.timezone(datetime.timedelta(hours=self._tz_offset))
            self._local_dt = datetime.datetime.fromtimestamp(self._wall_utc, tz=tz).replace(tzinfo=None)

    def monotonic(self) -> float:
        """Return virtual monotonic uptime in seconds."""
        return self._mono

    def wall_time_utc(self) -> float:
        """Return virtual UTC epoch seconds."""
        return self._wall_utc

    def local_date_str(self) -> str:
        """Return virtual local calendar date string (YYYY-MM-DD)."""
        return self._local_dt.strftime("%Y-%m-%d")

    def advance(self, seconds: float) -> None:
        """Simulate passage of real time: advances monotonic uptime, UTC wall, and local datetime."""
        if seconds < 0:
            raise ValueError(f"advance() duration must be non-negative, got {seconds}")
        delta = float(seconds)
        self._mono += delta
        self._monotonic += delta
        self._wall_utc += delta
        self._win32_uptime += delta
        self._local_dt += datetime.timedelta(seconds=delta)

    def warp_wall_clock(self, delta_seconds: float) -> None:
        """Simulate user or NTP altering system wall clock without altering monotonic uptime."""
        delta = float(delta_seconds)
        self._wall_utc += delta
        self._local_dt += datetime.timedelta(seconds=delta)

    def corrupt_monotonic(self, delta_seconds: float) -> None:
        """Simulate hooked/manipulated monotonic clock diverging from OS uptime."""
        delta = float(delta_seconds)
        self._mono += delta
        self._monotonic += delta

    def get_win32_uptime(self) -> Optional[float]:
        """Return virtual Win32 GetTickCount64 uptime in seconds."""
        return self._win32_uptime

    def set_win32_uptime(self, val: float) -> None:
        """Explicitly set virtual Win32 GetTickCount64 uptime."""
        self._win32_uptime = float(val)

    def set_local_date(self, year: int, month: int, day: int) -> None:
        """Forcefully set the local calendar date, preserving time of day."""
        self._local_dt = self._local_dt.replace(year=year, month=month, day=day)

    def set_exact(
        self,
        mono: Optional[float] = None,
        wall_utc: Optional[float] = None,
        local_dt: Optional[datetime.datetime] = None,
    ) -> None:
        """Set exact clock values directly."""
        if mono is not None:
            self._mono = float(mono)
            self._monotonic = self._mono
            self._win32_uptime = self._mono
        if wall_utc is not None:
            self._wall_utc = float(wall_utc)
        if local_dt is not None:
            self._local_dt = local_dt


# VirtualClock alias for anti-tamper tests
VirtualClock = MockClock
