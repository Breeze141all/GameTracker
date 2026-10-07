"""Clock guard and anti-tamper security supervisor.

Protects cumulative daily game tracking against system clock manipulation:
- Cross-references time.monotonic() with Win32 GetTickCount64()
- Detects runtime backward wall clock shifts (> 5.0s tolerance)
- Detects boot backward clock shifts relative to persisted shutdown timestamps
- Detects runtime forward jump anomalies (> elapsed monotonic + 60.0s)
- Gates midnight reset preventing unauthorized counter clearing
- Enforces strict thread safety and O(1) evaluation latency
"""

from __future__ import annotations
import sys
import time
import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List
from collections import deque
import threading


class TamperType(str, Enum):
    NONE = "NONE"
    BACKWARD_SHIFT_RUNTIME = "BACKWARD_SHIFT_RUNTIME"
    BACKWARD_SHIFT_BOOT = "BACKWARD_SHIFT_BOOT"
    FORWARD_JUMP_ANOMALY = "FORWARD_JUMP_ANOMALY"
    MONOTONIC_DIVERGENCE = "MONOTONIC_DIVERGENCE"


@dataclass(frozen=True)
class TamperEvent:
    tamper_type: TamperType
    timestamp_utc: float
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BootVerificationResult:
    valid: bool
    tamper_detected: bool
    cumulative_seconds: float
    lockout_active: bool
    allow_midnight_reset: bool
    events: List[TamperEvent] = field(default_factory=list)


@dataclass(frozen=True)
class TickVerificationResult:
    tamper_detected: bool
    tamper_active: bool
    allow_midnight_reset: bool
    events: List[TamperEvent] = field(default_factory=list)
    wall_utc: float = 0.0
    monotonic: float = 0.0


def query_win32_uptime() -> Optional[float]:
    """Query Win32 GetTickCount64() directly via ctypes with 64-bit unsigned restype."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.GetTickCount64.restype = ctypes.c_uint64
        return kernel32.GetTickCount64() / 1000.0
    except (AttributeError, OSError):
        return None


class SystemClock:
    """Production implementation of IClock interface utilizing OS system calls."""

    def __init__(self) -> None:
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_uint64
            except (AttributeError, OSError):
                pass

    def monotonic(self) -> float:
        return time.monotonic()

    def wall_time_utc(self) -> float:
        return time.time()

    def local_date_str(self) -> str:
        return datetime.datetime.now().strftime("%Y-%m-%d")

    def get_win32_uptime(self) -> Optional[float]:
        return query_win32_uptime()


class ClockGuard:
    """Anti-tamper protection layer for the game tracking engine."""

    def __init__(
        self,
        clock: Any,
        backward_tolerance_seconds: float = 5.0,
        forward_anomaly_threshold_seconds: float = 60.0,
        monotonic_divergence_tolerance_seconds: float = 1.0,
        max_log_entries: int = 100,
    ) -> None:
        self._clock = clock
        self.backward_tolerance = float(backward_tolerance_seconds)
        self.forward_anomaly_threshold = float(forward_anomaly_threshold_seconds)
        self.monotonic_divergence_tolerance = float(monotonic_divergence_tolerance_seconds)
        self._lock = threading.Lock()

        self._last_wall_utc: Optional[float] = None
        self._last_monotonic: Optional[float] = None
        self._high_watermark_wall_utc: float = 0.0
        self._tamper_active: bool = False
        self._tamper_log: deque = deque(maxlen=max_log_entries)

    def _query_win32_uptime(self) -> Optional[float]:
        if hasattr(self._clock, "get_win32_uptime"):
            return self._clock.get_win32_uptime()
        return query_win32_uptime()

    def verify_boot_state(
        self,
        persisted_state: Optional[Dict[str, Any]],
        daily_limit_seconds: float = 7200.0,
    ) -> BootVerificationResult:
        """Validate system state on service startup against persisted shutdown snapshot."""
        with self._lock:
            now_wall = self._clock.wall_time_utc()
            now_mono = self._clock.monotonic()
            events: List[TamperEvent] = []

            if not persisted_state:
                self._last_wall_utc = now_wall
                self._last_monotonic = now_mono
                self._high_watermark_wall_utc = now_wall
                return BootVerificationResult(
                    valid=True,
                    tamper_detected=False,
                    cumulative_seconds=0.0,
                    lockout_active=False,
                    allow_midnight_reset=True,
                )

            persisted_wall = float(persisted_state.get("last_wall_time_utc", 0.0))
            persisted_cum = float(persisted_state.get("cumulative_seconds", 0.0))
            persisted_lockout = bool(persisted_state.get("lockout_active", False))
            persisted_tamper = bool(persisted_state.get("tamper_detected", False))

            wall_delta_boot = now_wall - persisted_wall
            tamper_detected = False

            if wall_delta_boot < -self.backward_tolerance:
                tamper_detected = True
                self._tamper_active = True
                evt = TamperEvent(
                    tamper_type=TamperType.BACKWARD_SHIFT_BOOT,
                    timestamp_utc=now_wall,
                    message=f"Boot wall clock shifted backward by {abs(wall_delta_boot):.2f}s across reboot.",
                    details={
                        "persisted_wall_utc": persisted_wall,
                        "now_wall_utc": now_wall,
                        "delta_seconds": wall_delta_boot,
                    },
                )
                self._tamper_log.append(evt)
                events.append(evt)

            if persisted_tamper:
                self._tamper_active = True

            effective_cumulative = max(0.0, persisted_cum)
            effective_lockout = persisted_lockout or (effective_cumulative >= daily_limit_seconds)
            allow_reset = not self._tamper_active

            self._high_watermark_wall_utc = max(now_wall, persisted_wall)
            self._last_wall_utc = now_wall
            self._last_monotonic = now_mono

            return BootVerificationResult(
                valid=not tamper_detected,
                tamper_detected=tamper_detected or self._tamper_active,
                cumulative_seconds=effective_cumulative,
                lockout_active=effective_lockout,
                allow_midnight_reset=allow_reset,
                events=events,
            )

    def evaluate_tick(self) -> TickVerificationResult:
        """Evaluate clock consistency on each periodic monitoring tick."""
        with self._lock:
            now_mono = self._clock.monotonic()
            now_wall = self._clock.wall_time_utc()
            events: List[TamperEvent] = []
            new_tamper = False

            # 1. Monotonic Cross-Referencing
            win32_uptime = self._query_win32_uptime()
            if win32_uptime is not None:
                div = abs(now_mono - win32_uptime)
                if div > self.monotonic_divergence_tolerance:
                    new_tamper = True
                    self._tamper_active = True
                    evt = TamperEvent(
                        tamper_type=TamperType.MONOTONIC_DIVERGENCE,
                        timestamp_utc=now_wall,
                        message=f"Monotonic clock diverged from Win32 GetTickCount64 by {div:.3f}s.",
                        details={"monotonic": now_mono, "win32_uptime": win32_uptime, "divergence": div},
                    )
                    self._tamper_log.append(evt)
                    events.append(evt)

            # 2. Runtime Backward Clock Shift
            if self._last_wall_utc is not None:
                delta_wall = now_wall - self._last_wall_utc
                if delta_wall < -self.backward_tolerance:
                    new_tamper = True
                    self._tamper_active = True
                    evt = TamperEvent(
                        tamper_type=TamperType.BACKWARD_SHIFT_RUNTIME,
                        timestamp_utc=now_wall,
                        message=f"Runtime wall clock shifted backward by {abs(delta_wall):.2f}s.",
                        details={"prev_wall_utc": self._last_wall_utc, "now_wall_utc": now_wall, "delta": delta_wall},
                    )
                    self._tamper_log.append(evt)
                    events.append(evt)

            # 3. Runtime Forward Jump Anomaly
            if self._last_wall_utc is not None and self._last_monotonic is not None:
                delta_wall = now_wall - self._last_wall_utc
                delta_mono = max(0.0, now_mono - self._last_monotonic)
                if delta_wall > (delta_mono + self.forward_anomaly_threshold):
                    new_tamper = True
                    self._tamper_active = True
                    evt = TamperEvent(
                        tamper_type=TamperType.FORWARD_JUMP_ANOMALY,
                        timestamp_utc=now_wall,
                        message=f"Runtime wall clock jumped forward anomalously by {delta_wall:.2f}s (mono delta: {delta_mono:.2f}s).",
                        details={"delta_wall": delta_wall, "delta_mono": delta_mono, "threshold": self.forward_anomaly_threshold},
                    )
                    self._tamper_log.append(evt)
                    events.append(evt)

            # 4. High-Watermark Assessment
            self._high_watermark_wall_utc = max(self._high_watermark_wall_utc, now_wall)
            if now_wall < (self._high_watermark_wall_utc - self.backward_tolerance):
                self._tamper_active = True

            allow_reset = not self._tamper_active

            self._last_wall_utc = now_wall
            self._last_monotonic = now_mono

            return TickVerificationResult(
                tamper_detected=new_tamper,
                tamper_active=self._tamper_active,
                allow_midnight_reset=allow_reset,
                events=events,
                wall_utc=now_wall,
                monotonic=now_mono,
            )

    def check_runtime_step(
        self,
        curr_wall: float,
        last_wall: float,
        curr_mono: float,
        last_mono: float,
    ) -> bool:
        """Verify runtime timing integrity for a step. Returns False and flags tampering on anomaly."""
        with self._lock:
            # Check monotonic divergence
            win32_uptime = self._query_win32_uptime()
            if win32_uptime is not None:
                div = abs(curr_mono - win32_uptime)
                if div > self.monotonic_divergence_tolerance:
                    self._tamper_active = True
                    evt = TamperEvent(
                        tamper_type=TamperType.MONOTONIC_DIVERGENCE,
                        timestamp_utc=curr_wall,
                        message=f"Monotonic clock diverged from Win32 GetTickCount64 by {div:.3f}s.",
                        details={"monotonic": curr_mono, "win32_uptime": win32_uptime, "divergence": div},
                    )
                    self._tamper_log.append(evt)

            # Check runtime backward shift
            delta_wall = curr_wall - last_wall
            if delta_wall < -self.backward_tolerance:
                self._tamper_active = True
                evt = TamperEvent(
                    tamper_type=TamperType.BACKWARD_SHIFT_RUNTIME,
                    timestamp_utc=curr_wall,
                    message=f"Runtime wall clock shifted backward by {abs(delta_wall):.2f}s.",
                    details={"prev_wall_utc": last_wall, "now_wall_utc": curr_wall, "delta": delta_wall},
                )
                self._tamper_log.append(evt)

            # Check cumulative drift across the session to catch slow/stealth forward creep
            if getattr(self, "_session_start_wall", None) is None:
                self._session_start_wall = last_wall
                self._session_start_mono = last_mono

            cum_wall_delta = curr_wall - self._session_start_wall
            cum_mono_delta = max(0.0, curr_mono - self._session_start_mono)
            cum_drift = cum_wall_delta - cum_mono_delta
            if cum_drift > self.forward_anomaly_threshold:
                self._tamper_active = True
                evt = TamperEvent(
                    tamper_type=TamperType.FORWARD_JUMP_ANOMALY,
                    timestamp_utc=curr_wall,
                    message=f"Cumulative wall clock forward drift ({cum_drift:.2f}s) exceeded anomaly threshold ({self.forward_anomaly_threshold:.2f}s).",
                    details={"cum_wall_delta": cum_wall_delta, "cum_mono_delta": cum_mono_delta, "cum_drift": cum_drift},
                )
                self._tamper_log.append(evt)

            # Check runtime forward jump anomaly
            delta_mono = max(0.0, curr_mono - last_mono)
            if delta_wall > (delta_mono + self.forward_anomaly_threshold):
                self._tamper_active = True
                evt = TamperEvent(
                    tamper_type=TamperType.FORWARD_JUMP_ANOMALY,
                    timestamp_utc=curr_wall,
                    message=f"Runtime wall clock jumped forward anomalously by {delta_wall:.2f}s (mono delta: {delta_mono:.2f}s).",
                    details={"delta_wall": delta_wall, "delta_mono": delta_mono, "threshold": self.forward_anomaly_threshold},
                )
                self._tamper_log.append(evt)

            # Update high watermark
            self._high_watermark_wall_utc = max(self._high_watermark_wall_utc, curr_wall)
            if curr_wall < (self._high_watermark_wall_utc - self.backward_tolerance):
                self._tamper_active = True

            self._last_wall_utc = curr_wall
            self._last_monotonic = curr_mono

            return not self._tamper_active

    def can_reset_midnight(self, current_day_key: str, persisted_day_key: str) -> bool:
        """Gatekeeper validating whether midnight reset is permitted."""
        with self._lock:
            if current_day_key <= persisted_day_key:
                return False
            if self._tamper_active:
                return False
            now_wall = self._clock.wall_time_utc()
            if now_wall < (self._high_watermark_wall_utc - self.backward_tolerance):
                return False
            return True

    def notify_system_resume(self, wall_now: float, mono_now: float) -> None:
        """Called upon system power resume event to update reference timestamps without false tamper alarm."""
        with self._lock:
            self._last_wall_utc = float(wall_now)
            self._last_monotonic = float(mono_now)
            self._high_watermark_wall_utc = max(self._high_watermark_wall_utc, float(wall_now))
            self._session_start_wall = float(wall_now)
            self._session_start_mono = float(mono_now)

    def acknowledge_admin_override(self) -> None:
        """Authenticated administrative command resetting tamper state."""
        with self._lock:
            self._tamper_active = False
            self._admin_override = True
            now_wall = self._clock.wall_time_utc()
            now_mono = self._clock.monotonic()
            self._high_watermark_wall_utc = now_wall
            self._last_wall_utc = now_wall
            self._last_monotonic = now_mono
            self._session_start_wall = now_wall
            self._session_start_mono = now_mono

    def is_tampered(self) -> bool:
        """Return True if any clock tampering or backward shift has been flagged."""
        with self._lock:
            return self._tamper_active

    @property
    def is_tamper_active(self) -> bool:
        """Property returning True if tamper state is currently active."""
        with self._lock:
            return self._tamper_active

    def tamper_reason(self) -> Optional[str]:
        """Return the most recent tamper reason code or message."""
        with self._lock:
            if not self._tamper_log:
                return None
            return self._tamper_log[-1].tamper_type.value

    @property
    def tamper_log(self) -> List[TamperEvent]:
        """Return audit trail of all recorded tamper events."""
        with self._lock:
            return list(self._tamper_log)
