"""tests/test_detector_and_cli.py

Tests for hybrid launcher detection, process predicates, configuration management,
and salted password hashing.
"""

from __future__ import annotations
import unittest
import tempfile
import shutil
from pathlib import Path

from gametracker.interfaces import ProcessEntry
from gametracker.config import TrackerConfig, ConfigManager
from gametracker.detector import create_game_predicate, LauncherScanner


class MockLauncherScanner:
    def __init__(self, roots):
        self.roots = roots

    def get_game_roots(self):
        return set(self.roots)

    def get_game_executables(self):
        return set()


class TestDetectorAndConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="gt_test_cli_")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_password_hashing_and_verification(self) -> None:
        cfg = TrackerConfig()
        self.assertFalse(cfg.is_password_set())
        self.assertTrue(cfg.verify_password("any_password"))

        cfg.set_password("Secret1234!")
        self.assertTrue(cfg.is_password_set())
        self.assertTrue(cfg.verify_password("Secret1234!"))
        self.assertFalse(cfg.verify_password("WrongPassword"))
        self.assertFalse(cfg.verify_password(""))

    def test_config_persistence(self) -> None:
        cfg_path = Path(self.temp_dir) / "config.json"
        mgr = ConfigManager(str(cfg_path))
        cfg = mgr.load()
        cfg.daily_limit_minutes = 90
        cfg.blacklist_processes.append("custom_game.exe")
        cfg.set_password("AdminPass")

        self.assertTrue(mgr.save(cfg))

        loaded = mgr.load()
        self.assertEqual(loaded.daily_limit_minutes, 90)
        self.assertIn("custom_game.exe", loaded.blacklist_processes)
        self.assertTrue(loaded.verify_password("AdminPass"))

    def test_game_predicate_evaluation(self) -> None:
        cfg = TrackerConfig(
            blacklist_processes=["cs2.exe", "dota2.exe"],
            exempt_processes=["steam.exe", "explorer.exe"],
        )
        scanner = MockLauncherScanner(roots=["c:/games/steamapps/common"])
        is_game = create_game_predicate(cfg, scanner)

        # 1. Exempt process
        p_steam = ProcessEntry(pid=100, name="Steam.exe", exe_path="C:/Steam/Steam.exe")
        self.assertFalse(is_game(p_steam))

        # 2. Blacklisted process
        p_cs2 = ProcessEntry(pid=101, name="cs2.exe", exe_path="C:/custom/cs2.exe")
        self.assertTrue(is_game(p_cs2))

        # 3. Process inside game library directory
        p_witcher = ProcessEntry(pid=102, name="witcher.exe", exe_path="C:/Games/SteamApps/common/TheWitcher/witcher.exe")
        self.assertTrue(is_game(p_witcher))

        # 4. Standard non-game process
        p_code = ProcessEntry(pid=103, name="Code.exe", exe_path="C:/Users/AppData/Code.exe")
        self.assertFalse(is_game(p_code))


if __name__ == "__main__":
    unittest.main()
