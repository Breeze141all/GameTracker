"""gametracker.security package.

Provides anti-tamper clock monitoring and crash-resilient state persistence.
"""

from gametracker.security.clock_guard import (
    ClockGuard,
    SystemClock,
    TamperType,
    TamperEvent,
    BootVerificationResult,
    TickVerificationResult,
)
from gametracker.security.persistence import (
    StatePersistence,
    TrackerState,
    StateIntegrityError,
    StateValidationError,
    compute_checksum,
    verify_checksum,
)

__all__ = [
    "ClockGuard",
    "SystemClock",
    "TamperType",
    "TamperEvent",
    "BootVerificationResult",
    "TickVerificationResult",
    "StatePersistence",
    "TrackerState",
    "StateIntegrityError",
    "StateValidationError",
    "compute_checksum",
    "verify_checksum",
]
