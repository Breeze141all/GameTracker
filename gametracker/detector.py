"""gametracker/detector.py

Hybrid Game Detection and Windows Process Enumeration Engine.
Discovers game installation roots across Steam, Epic Games, GOG Galaxy, and Xbox,
and enumerates active system processes using native Win32 APIs without third-party dependencies.
"""

from __future__ import annotations
import os
import re
import json
import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import List, Set, Optional, Callable, Dict, Any

from gametracker.interfaces import (
    ProcessEntry,
    IProcessEnumerator,
    ILauncherScanner,
)
from gametracker.config import TrackerConfig


# Win32 Constants
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
MAX_PATH = 260


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class Win32ProcessEnumerator(IProcessEnumerator):
    """Enumerate processes on Windows using native Toolhelp32 APIs."""

    def __init__(self) -> None:
        self._kernel32 = ctypes.windll.kernel32

    def _get_process_path(self, pid: int) -> str:
        """Query full executable path for a process handle."""
        h_process = self._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h_process:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(MAX_PATH * 4)
            size = wintypes.DWORD(len(buf))
            if hasattr(self._kernel32, "QueryFullProcessImageNameW"):
                if self._kernel32.QueryFullProcessImageNameW(h_process, 0, buf, ctypes.byref(size)):
                    return buf.value
            return ""
        finally:
            self._kernel32.CloseHandle(h_process)

    def enumerate_processes(self) -> List[ProcessEntry]:
        """Snapshot and enumerate all running processes on the system."""
        entries: List[ProcessEntry] = []
        h_snap = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if h_snap == -1 or not h_snap:
            return entries

        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)

            if not self._kernel32.Process32FirstW(h_snap, ctypes.byref(pe)):
                return entries

            while True:
                pid = int(pe.th32ProcessID)
                name = str(pe.szExeFile)
                parent_pid = int(pe.th32ParentProcessID)

                exe_path = ""
                if pid > 4:
                    exe_path = self._get_process_path(pid)

                entries.append(
                    ProcessEntry(
                        pid=pid,
                        name=name,
                        exe_path=exe_path,
                        parent_pid=parent_pid,
                    )
                )

                if not self._kernel32.Process32NextW(h_snap, ctypes.byref(pe)):
                    break
        finally:
            self._kernel32.CloseHandle(h_snap)

        return entries


class LauncherScanner(ILauncherScanner):
    """Auto-detects game library directories for Steam, Epic, GOG, and Xbox."""

    def __init__(self, config: TrackerConfig) -> None:
        self.config = config
        self._cached_roots: Set[str] = set()
        self.refresh()

    def refresh(self) -> None:
        """Scan system drives and manifest folders for game roots."""
        roots: Set[str] = set()

        # 1. Custom configured directories
        for p in self.config.custom_game_directories:
            p_obj = Path(p)
            if p_obj.exists():
                roots.add(str(p_obj.resolve()).lower())

        if self.config.auto_detect_launchers:
            # 2. Steam libraries
            roots.update(self._find_steam_libraries())

            # 3. Epic Games
            roots.update(self._find_epic_libraries())

            # 4. GOG Galaxy
            roots.update(self._find_gog_libraries())

            # 5. Xbox / WindowsApps
            roots.update(self._find_xbox_libraries())

        self._cached_roots = roots

    def _find_steam_libraries(self) -> Set[str]:
        steam_roots: Set[str] = set()
        common_candidates = [
            Path("C:/Program Files (x86)/Steam"),
            Path("C:/Program Files/Steam"),
            Path("D:/Steam"),
            Path("D:/SteamLibrary"),
            Path("E:/SteamLibrary"),
            Path("F:/SteamLibrary"),
        ]

        # Scan for libraryfolders.vdf
        for base in common_candidates:
            if not base.exists():
                continue
            common_dir = base / "steamapps" / "common"
            if common_dir.exists():
                steam_roots.add(str(common_dir.resolve()).lower())

            vdf_path = base / "steamapps" / "libraryfolders.vdf"
            if vdf_path.exists():
                try:
                    with open(vdf_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    matches = re.findall(r'"path"\s+"([^"]+)"', content)
                    for m in matches:
                        lib_common = Path(m) / "steamapps" / "common"
                        if lib_common.exists():
                            steam_roots.add(str(lib_common.resolve()).lower())
                except Exception:
                    pass

        return steam_roots

    def _find_epic_libraries(self) -> Set[str]:
        epic_roots: Set[str] = set()
        manifests_dir = Path("C:/ProgramData/Epic/EpicGamesLauncher/Data/Manifests")
        if manifests_dir.exists():
            for item in manifests_dir.glob("*.item"):
                try:
                    with open(item, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    install_loc = data.get("InstallLocation")
                    if install_loc and Path(install_loc).exists():
                        epic_roots.add(str(Path(install_loc).resolve()).lower())
                except Exception:
                    pass

        default_epic = Path("C:/Program Files/Epic Games")
        if default_epic.exists():
            epic_roots.add(str(default_epic.resolve()).lower())
        return epic_roots

    def _find_gog_libraries(self) -> Set[str]:
        gog_roots: Set[str] = set()
        candidates = [
            Path("C:/Program Files (x86)/GOG Galaxy/Games"),
            Path("C:/GOG Games"),
            Path("D:/GOG Games"),
        ]
        for c in candidates:
            if c.exists():
                gog_roots.add(str(c.resolve()).lower())
        return gog_roots

    def _find_xbox_libraries(self) -> Set[str]:
        xbox_roots: Set[str] = set()
        for drive in ["C:", "D:", "E:", "F:"]:
            xb = Path(f"{drive}/XboxGames")
            if xb.exists():
                xbox_roots.add(str(xb.resolve()).lower())
        return xbox_roots

    def get_game_roots(self) -> Set[str]:
        return set(self._cached_roots)

    def get_game_executables(self) -> Set[str]:
        return set()


def create_game_predicate(
    config: TrackerConfig,
    scanner: ILauncherScanner,
) -> Callable[[ProcessEntry], bool]:
    """Factory creating an is_game predicate evaluating blacklist and directory membership."""
    blacklist = {p.lower() for p in config.blacklist_processes}
    exempt = {p.lower() for p in config.exempt_processes}

    def is_game(entry: ProcessEntry) -> bool:
        name_lower = entry.name.lower()

        # 1. Check exempt list first
        if name_lower in exempt:
            return False

        # 2. Check blacklist process name
        if name_lower in blacklist:
            return True

        # 3. Check if executable lives inside any detected game library root
        if entry.exe_path:
            norm_exe = str(Path(entry.exe_path).resolve()).lower()
            for root in scanner.get_game_roots():
                norm_root = str(Path(root).resolve()).lower()
                if norm_exe.startswith(norm_root):
                    return True

        return False

    return is_game
