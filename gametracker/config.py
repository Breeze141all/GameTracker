"""gametracker/config.py

Configuration management for GameTracker.
Handles game process blacklists, directory roots, exempt processes,
and salted PBKDF2-HMAC-SHA256 password authentication for parental control.
"""

from __future__ import annotations
import os
import json
import hashlib
import secrets
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Set, Dict, Any, Optional

DEFAULT_BLACKLIST = [
    # Steam / Valve
    "cs2.exe",
    "csgo.exe",
    "dota2.exe",
    "hl2.exe",
    "left4dead2.exe",
    "tf_win64.exe",
    # Riot
    "valorant.exe",
    "league of legends.exe",
    "leagueclient.exe",
    # Epic / Fortnite
    "fortniteclient-win64-shipping.exe",
    # Blizzard
    "overwatch.exe",
    "worldofwarcraft.exe",
    "wow.exe",
    "diablo iv.exe",
    # Sandbox / Popular
    "robloxplayerbeta.exe",
    "minecraft.exe",
    "genshinimpact.exe",
    "starrail.exe",
    "gta5.exe",
    "playgtav.exe",
    "rdr2.exe",
    "cyberpunk2077.exe",
    "witcher3.exe",
    "baldursgate3.exe",
    "bg3.exe",
    "bg3_dx11.exe",
]

DEFAULT_EXEMPT = [
    "steam.exe",
    "steamservice.exe",
    "steamwebhelper.exe",
    "epicgameslauncher.exe",
    "galaxyclient.exe",
    "gog.com",
    "battlenet.exe",
    "agent.exe",
    "riotclientservices.exe",
    "vgc.exe",
    "vgtray.exe",
    "explorer.exe",
    "taskmgr.exe",
    "cmd.exe",
    "powershell.exe",
    "conhost.exe",
    "code.exe",
    "devenv.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "discord.exe",
    "spotify.exe",
]


@dataclass
class TrackerConfig:
    daily_limit_minutes: int = 120
    warn_minutes: List[int] = field(default_factory=lambda: [5, 1])
    blacklist_processes: List[str] = field(default_factory=lambda: list(DEFAULT_BLACKLIST))
    custom_game_directories: List[str] = field(default_factory=list)
    exempt_processes: List[str] = field(default_factory=lambda: list(DEFAULT_EXEMPT))
    password_hash: str = ""
    password_salt: str = ""
    auto_detect_launchers: bool = True

    def is_password_set(self) -> bool:
        return bool(self.password_hash and self.password_salt)

    def set_password(self, password: str) -> None:
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
        self.password_salt = salt
        self.password_hash = h.hex()

    def verify_password(self, password: str) -> bool:
        if not self.is_password_set():
            return True
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), self.password_salt.encode("utf-8"), 100_000)
        return secrets.compare_digest(h.hex(), self.password_hash)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TrackerConfig:
        return cls(
            daily_limit_minutes=int(data.get("daily_limit_minutes", 120)),
            warn_minutes=list(data.get("warn_minutes", [5, 1])),
            blacklist_processes=list(data.get("blacklist_processes", DEFAULT_BLACKLIST)),
            custom_game_directories=list(data.get("custom_game_directories", [])),
            exempt_processes=list(data.get("exempt_processes", DEFAULT_EXEMPT)),
            password_hash=str(data.get("password_hash", "")),
            password_salt=str(data.get("password_salt", "")),
            auto_detect_launchers=bool(data.get("auto_detect_launchers", True)),
        )


class ConfigManager:
    """Manages loading and saving tracker configuration file."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        if config_path:
            self.config_path = Path(config_path)
        else:
            appdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
            self.config_path = Path(appdata) / "GameTracker" / "config.json"

    def load(self) -> TrackerConfig:
        if not self.config_path.exists():
            cfg = TrackerConfig()
            self.save(cfg)
            return cfg
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return TrackerConfig.from_dict(data)
        except Exception:
            return TrackerConfig()

    def save(self, config: TrackerConfig) -> bool:
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.config_path.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(config.to_dict(), f, indent=2)
            temp_path.replace(self.config_path)
            return True
        except Exception:
            return False
