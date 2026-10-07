"""gametracker/security/persistence.py

Crash-resilient, anti-tamper state persistence subsystem for GameTracker.
Implements atomic file updates, SHA-256/HMAC-SHA256 integrity sealing,
dual-copy backup replication (.bak), and auto-healing failover.
"""

from __future__ import annotations

import os
import time
import json
import hmac
import hashlib
import logging
import threading
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, Union, List

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
DEFAULT_DAILY_LIMIT_SECONDS = 7200.0  # 120 minutes


class StatePersistenceError(Exception):
    """Base exception for persistence failures."""
    pass


class StateIntegrityError(StatePersistenceError):
    """Raised when state data fails checksum or has been tampered with."""
    pass


class StateValidationError(StatePersistenceError):
    """Raised when state data fails schema validation."""
    pass


@dataclass
class TrackerState:
    """Strongly typed representation of tracker persistent state."""
    version: int = SCHEMA_VERSION
    day_key: str = ""
    cumulative_seconds: float = 0.0
    daily_limit_seconds: float = DEFAULT_DAILY_LIMIT_SECONDS
    lockout_active: bool = False
    notified_5min: bool = False
    notified_1min: bool = False
    last_wall_time_utc: float = 0.0
    last_uptime_seconds: float = 0.0
    tamper_detected: bool = False
    tamper_code: Optional[str] = None
    tamper_log: List[str] = field(default_factory=list)
    checksum: str = ""

    def validate(self) -> None:
        """Validate invariant constraints of the state."""
        if not isinstance(self.version, int) or self.version < 1:
            raise StateValidationError(f"Invalid schema version: {self.version}")
        if not isinstance(self.day_key, str):
            raise StateValidationError(f"Invalid day_key type: {type(self.day_key)}")
        if not isinstance(self.cumulative_seconds, (int, float)) or self.cumulative_seconds < 0.0:
            raise StateValidationError(f"Invalid cumulative_seconds: {self.cumulative_seconds} (must be >= 0.0)")
        if not isinstance(self.daily_limit_seconds, (int, float)) or self.daily_limit_seconds <= 0.0:
            raise StateValidationError(f"Invalid daily_limit_seconds: {self.daily_limit_seconds} (must be > 0.0)")
        if not isinstance(self.lockout_active, bool):
            raise StateValidationError(f"Invalid lockout_active type: {type(self.lockout_active)}")
        if not isinstance(self.notified_5min, bool) or not isinstance(self.notified_1min, bool):
            raise StateValidationError("Notification flags must be boolean")
        if not isinstance(self.last_wall_time_utc, (int, float)) or self.last_wall_time_utc < 0.0:
            raise StateValidationError(f"Invalid last_wall_time_utc: {self.last_wall_time_utc}")
        if not isinstance(self.last_uptime_seconds, (int, float)) or self.last_uptime_seconds < 0.0:
            raise StateValidationError(f"Invalid last_uptime_seconds: {self.last_uptime_seconds}")
        if not isinstance(self.tamper_detected, bool):
            raise StateValidationError(f"Invalid tamper_detected type: {type(self.tamper_detected)}")
        if not isinstance(self.tamper_log, list):
            raise StateValidationError(f"Invalid tamper_log type: {type(self.tamper_log)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TrackerState:
        """Construct TrackerState instance from dictionary with defensive typing."""
        if not isinstance(data, dict):
            raise StateValidationError(f"Expected dict, got {type(data).__name__}")
        return cls(
            version=int(data.get("version", SCHEMA_VERSION)),
            day_key=str(data.get("day_key", "")),
            cumulative_seconds=float(data.get("cumulative_seconds", 0.0)),
            daily_limit_seconds=float(data.get("daily_limit_seconds", DEFAULT_DAILY_LIMIT_SECONDS)),
            lockout_active=bool(data.get("lockout_active", False)),
            notified_5min=bool(data.get("notified_5min", False)),
            notified_1min=bool(data.get("notified_1min", False)),
            last_wall_time_utc=float(data.get("last_wall_time_utc", 0.0)),
            last_uptime_seconds=float(data.get("last_uptime_seconds", 0.0)),
            tamper_detected=bool(data.get("tamper_detected", False)),
            tamper_code=data.get("tamper_code"),
            tamper_log=list(data.get("tamper_log", [])),
            checksum=str(data.get("checksum", "")),
        )


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    """Normalize payload dictionary into deterministic canonical JSON bytes.

    Excludes the 'checksum' field so checksum computation does not recurse.
    Sorts all keys and enforces compact separators without whitespace.
    """
    clean_payload = {k: v for k, v in payload.items() if k != "checksum"}
    canonical_str = json.dumps(
        clean_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return canonical_str.encode("utf-8")


def compute_checksum(payload: Dict[str, Any], secret_key: Optional[bytes] = None) -> str:
    """Compute cryptographic integrity checksum over canonical JSON payload.

    If secret_key is provided, uses HMAC-SHA256 to resist unprivileged forgery.
    Otherwise, uses SHA-256 digest.
    """
    canon_bytes = canonical_json_bytes(payload)
    if secret_key:
        return hmac.new(secret_key, canon_bytes, hashlib.sha256).hexdigest()
    return hashlib.sha256(canon_bytes).hexdigest()


def verify_checksum(payload: Dict[str, Any], secret_key: Optional[bytes] = None) -> bool:
    """Constant-time verification of payload checksum."""
    if not isinstance(payload, dict) or "checksum" not in payload:
        return False
    provided_checksum = str(payload["checksum"])
    expected_checksum = compute_checksum(payload, secret_key)
    return hmac.compare_digest(provided_checksum, expected_checksum)


class StatePersistence:
    """Thread-safe, crash-resilient atomic state storage manager.

    Adheres to the IStateStore protocol:
      load_state() -> Optional[Dict[str, Any]]
      save_state(state: Dict[str, Any]) -> bool
    """

    def __init__(
        self,
        state_file_path: Optional[Union[str, Path]] = None,
        backup_file_path: Optional[Union[str, Path]] = None,
        secret_key: Optional[bytes] = None,
        max_retries: int = 10,
        retry_delay_seconds: float = 0.05,
        data_dir: Optional[Union[str, Path]] = None,
        auto_heal: bool = True,
    ) -> None:
        if data_dir is not None:
            p = Path(data_dir).resolve()
            p.mkdir(parents=True, exist_ok=True)
            self.state_file = (p / "state.json").resolve()
        elif state_file_path is not None:
            p = Path(state_file_path).resolve()
            if p.is_dir():
                p.mkdir(parents=True, exist_ok=True)
                self.state_file = (p / "state.json").resolve()
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                self.state_file = p
        else:
            self.state_file = Path("state.json").resolve()

        if backup_file_path:
            self.bak_file = Path(backup_file_path).resolve()
        else:
            self.bak_file = Path(str(self.state_file) + ".bak").resolve()
        self.secret_key = secret_key
        self.max_retries = max(1, max_retries)
        self.retry_delay = max(0.001, retry_delay_seconds)
        self.auto_heal = auto_heal
        self._lock = threading.RLock()

    def _safe_replace(self, src: Path, dst: Path) -> None:
        """Atomically replace dst with src on NTFS, handling transient Windows file locks."""
        for attempt in range(self.max_retries):
            try:
                os.replace(src, dst)
                return
            except PermissionError as err:
                if attempt == self.max_retries - 1:
                    logger.error("Failed to replace %s -> %s after %d retries: %s", src, dst, self.max_retries, err)
                    raise
                time.sleep(self.retry_delay)

    def _atomic_write_file(self, target_path: Path, data_str: str) -> None:
        """Write content to temporary file in target directory, fsync, and replace."""
        target_dir = target_path.parent
        target_dir.mkdir(parents=True, exist_ok=True)

        tmp_path = target_dir / f"{target_path.name}.{os.getpid()}.{time.perf_counter_ns()}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(data_str)
                f.flush()
                os.fsync(f.fileno())
            self._safe_replace(tmp_path, target_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def save_state(self, state: Union[Dict[str, Any], TrackerState]) -> bool:
        """Atomically persist state to primary and backup storage with integrity seal.

        Protocol steps:
        1. Validate schema invariants.
        2. Compute SHA-256 / HMAC-SHA256 checksum over canonical payload.
        3. Serialize formatted JSON payload.
        4. Atomic write + fsync to state.json.
        5. Atomic write + fsync to state.json.bak.
        """
        with self._lock:
            if isinstance(state, TrackerState):
                state.validate()
                payload = state.to_dict()
            elif isinstance(state, dict):
                temp_obj = TrackerState.from_dict(state)
                temp_obj.validate()
                payload = temp_obj.to_dict()
            else:
                raise StateValidationError("Invalid state type")

            payload["checksum"] = compute_checksum(payload, self.secret_key)
            serialized_payload = json.dumps(payload, indent=2, ensure_ascii=False)

            self._atomic_write_file(self.state_file, serialized_payload)
            self._atomic_write_file(self.bak_file, serialized_payload)
            return True

    def _read_and_verify(self, file_path: Path) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Read and verify a state file. Returns (data, error_reason)."""
        if not file_path.is_file():
            return None, "FILE_NOT_FOUND"

        raw_text = ""
        for attempt in range(self.max_retries):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    raw_text = f.read()
                break
            except (PermissionError, OSError) as err:
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                return None, f"OS_READ_ERROR: {err}"
            except (UnicodeDecodeError, ValueError) as err:
                return None, f"UNICODE_DECODE_ERROR: {err}"

        if not raw_text.strip():
            return None, "EMPTY_FILE"

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as err:
            return None, f"JSON_DECODE_ERROR: {err}"
        except OSError as err:
            return None, f"OS_READ_ERROR: {err}"

        if not isinstance(data, dict):
            return None, f"INVALID_JSON_ROOT_TYPE: {type(data).__name__}"

        if not verify_checksum(data, self.secret_key):
            return None, "CHECKSUM_INTEGRITY_MISMATCH"

        try:
            temp_obj = TrackerState.from_dict(data)
            temp_obj.validate()
        except StateValidationError as err:
            return None, f"SCHEMA_VALIDATION_ERROR: {err}"

        return data, None

    def load_state(self) -> Optional[Dict[str, Any]]:
        """Load persisted state dictionary, recovering from backup if primary is corrupted.

        Returns:
            Optional[Dict[str, Any]]: Valid state dict, or None if neither file exists.
        Raises:
            StateIntegrityError: If existing state files fail checksum / schema verification
                                 and cannot be recovered.
        """
        with self._lock:
            primary_data, primary_err = self._read_and_verify(self.state_file)

            if primary_data is not None:
                bak_data, bak_err = self._read_and_verify(self.bak_file)
                if bak_data is None:
                    logger.warning("Healing corrupt/missing backup from valid primary: %s", bak_err)
                    try:
                        self._atomic_write_file(self.bak_file, json.dumps(primary_data, indent=2, ensure_ascii=False))
                    except Exception as err:
                        logger.warning("Could not auto-heal backup: %s", err)
                return primary_data

            if primary_err == "FILE_NOT_FOUND" and not self.bak_file.is_file():
                return None

            logger.warning("Primary state file invalid (%s). Attempting failover to %s", primary_err, self.bak_file)
            bak_data, bak_err = self._read_and_verify(self.bak_file)

            if bak_data is not None:
                logger.info("Successfully recovered state from backup store.")
                bak_data.setdefault("tamper_log", [])
                bak_data["tamper_log"].append(f"FAILOVER_TO_BACKUP: primary failed with {primary_err}")
                bak_data["tamper_detected"] = True

                try:
                    self.save_state(bak_data)
                except Exception as err:
                    logger.error("Failed to auto-heal primary from backup: %s", err)

                return bak_data

            if primary_err == "FILE_NOT_FOUND" and bak_err == "FILE_NOT_FOUND":
                return None

            raise StateIntegrityError(
                f"Catastrophic state corruption detected! Primary: {primary_err}, Backup: {bak_err}"
            )

    def load_state_defensive(self, fallback_day_key: str, daily_limit: float = DEFAULT_DAILY_LIMIT_SECONDS) -> Dict[str, Any]:
        """Fail-closed loader returning defensive lockout state upon fatal corruption."""
        with self._lock:
            try:
                loaded = self.load_state()
                if loaded is not None:
                    return loaded
                return TrackerState(
                    day_key=fallback_day_key,
                    daily_limit_seconds=daily_limit,
                ).to_dict()
            except StateIntegrityError as err:
                logger.critical("Entering DEFENSIVE LOCKDOWN due to state integrity failure: %s", err)
                return TrackerState(
                    day_key=fallback_day_key,
                    cumulative_seconds=daily_limit,
                    daily_limit_seconds=daily_limit,
                    lockout_active=True,
                    notified_5min=True,
                    notified_1min=True,
                    tamper_detected=True,
                    tamper_log=[f"DEFENSIVE_LOCKDOWN: {err}"],
                ).to_dict()
