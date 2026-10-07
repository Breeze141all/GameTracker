"""gametracker/cli.py

Command-Line Interface (CLI) for managing GameTracker.
Includes password authentication for parental control, configuration management,
live status reporting, manual unlock, and Windows auto-start task registration.
"""

from __future__ import annotations
import os
import sys
import getpass
import argparse
import subprocess
from pathlib import Path
from typing import Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from gametracker.config import ConfigManager, TrackerConfig
from gametracker.security.persistence import StatePersistence
from gametracker.service import GameTrackerDaemon


def get_base_dir() -> Path:
    appdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
    p = Path(appdata) / "GameTracker"
    p.mkdir(parents=True, exist_ok=True)
    return p


def authenticate(config: TrackerConfig) -> bool:
    """Prompt user for parental password if set."""
    if not config.is_password_set():
        return True
    entered = getpass.getpass("Введіть майстер-пароль: ")
    if config.verify_password(entered):
        return True
    print("Помилка: Невірний пароль! Доступ заборонено.", file=sys.stderr)
    return False


def cmd_status(args: argparse.Namespace) -> None:
    """Print current tracker state, elapsed time, and lockout info."""
    base_dir = get_base_dir()
    cfg_mgr = ConfigManager(str(base_dir / "config.json"))
    config = cfg_mgr.load()

    store = StatePersistence(data_dir=str(base_dir), auto_heal=False)
    state = store.load_state()

    print("=" * 55)
    print("               СТАТУС GAMETRACKER")
    print("=" * 55)

    if not state:
        print("Стан сервісу: ще не ініціалізовано або немає записів.")
        print(f"Встановлений денний ліміт: {config.daily_limit_minutes} хв.")
        return

    day = state.get("day_key", "Невідомо")
    cum_sec = float(state.get("cumulative_seconds", 0.0))
    limit_sec = float(state.get("daily_limit_seconds", config.daily_limit_minutes * 60))
    lockout = bool(state.get("lockout_active", False))
    tamper = bool(state.get("tamper_detected", False))

    played_min = int(cum_sec // 60)
    played_sec = int(cum_sec % 60)
    limit_min = int(limit_sec // 60)
    rem_sec = max(0.0, limit_sec - cum_sec)
    rem_min = int(rem_sec // 60)

    print(f"Поточна дата:             {day}")
    print(f"Зіграно сьогодні:         {played_min} хв {played_sec} с (з {limit_min} хв ліміту)")
    print(f"Залишилося часу:          {rem_min} хв {int(rem_sec % 60)} с")

    status_str = "БЛОКУВАННЯ АКТИВНЕ (Ігри заборонено до 00:00)" if lockout else "Дозволено грати"
    print(f"Статус блокування:        {status_str}")

    tamper_str = "ВИЯВЛЕНО МАНІПУЛЯЦІЮ ЧАСОМ" if tamper else "Норма"
    print(f"Цілісність годинника:     {tamper_str}")
    print(f"Парольний захист:         {'Увімкнено' if config.is_password_set() else 'Вимкнено'}")
    print("=" * 55)


def cmd_set_password(args: argparse.Namespace) -> None:
    """Set or update parental password."""
    base_dir = get_base_dir()
    cfg_mgr = ConfigManager(str(base_dir / "config.json"))
    config = cfg_mgr.load()

    if config.is_password_set():
        if not authenticate(config):
            return

    new_pw = getpass.getpass("Введіть новий пароль: ")
    confirm_pw = getpass.getpass("Підтвердіть новий пароль: ")
    if new_pw != confirm_pw:
        print("Помилка: Паролі не співпадають!")
        return

    config.set_password(new_pw)
    if cfg_mgr.save(config):
        print("Пароль успішно встановлено!")
    else:
        print("Помилка при збереженні конфігурації.", file=sys.stderr)


def cmd_unlock(args: argparse.Namespace) -> None:
    """Manually clear lockout state with authentication."""
    base_dir = get_base_dir()
    cfg_mgr = ConfigManager(str(base_dir / "config.json"))
    config = cfg_mgr.load()

    if not authenticate(config):
        return

    store = StatePersistence(data_dir=str(base_dir), auto_heal=False)
    state = store.load_state()
    if not state:
        print("Немає збереженого стану.")
        return

    state["lockout_active"] = False
    state["cumulative_seconds"] = 0.0
    state["tamper_detected"] = False
    state["notified_5min"] = False
    state["notified_1min"] = False

    if store.save_state(state):
        print("Блокування успішно знято! Лічильник скинуто на 0.")
    else:
        print("Помилка при збереженні стану.", file=sys.stderr)


def cmd_add_game(args: argparse.Namespace) -> None:
    """Add game process name to blacklist."""
    base_dir = get_base_dir()
    cfg_mgr = ConfigManager(str(base_dir / "config.json"))
    config = cfg_mgr.load()

    if not authenticate(config):
        return

    exe_name = args.name.strip().lower()
    if not exe_name.endswith(".exe"):
        exe_name += ".exe"

    if exe_name in config.blacklist_processes:
        print(f"Процес '{exe_name}' вже є у списку блокування.")
        return

    config.blacklist_processes.append(exe_name)
    cfg_mgr.save(config)
    print(f"Процес '{exe_name}' успішно додано до списку відстеження та блокування.")


def cmd_remove_game(args: argparse.Namespace) -> None:
    """Remove process from blacklist."""
    base_dir = get_base_dir()
    cfg_mgr = ConfigManager(str(base_dir / "config.json"))
    config = cfg_mgr.load()

    if not authenticate(config):
        return

    exe_name = args.name.strip().lower()
    if exe_name in config.blacklist_processes:
        config.blacklist_processes.remove(exe_name)
        cfg_mgr.save(config)
        print(f"Процес '{exe_name}' видалено зі списку.")
    else:
        print(f"Процес '{exe_name}' не знайдено.")


def cmd_list_games(args: argparse.Namespace) -> None:
    """List tracked games and directories."""
    base_dir = get_base_dir()
    cfg_mgr = ConfigManager(str(base_dir / "config.json"))
    config = cfg_mgr.load()

    print("--- Відстежувані процеси (чорний список) ---")
    for g in sorted(config.blacklist_processes):
        print(f"  • {g}")

    print("\n--- Кастомні папки ігор ---")
    if config.custom_game_directories:
        for d in config.custom_game_directories:
            print(f"  • {d}")
    else:
        print("  (Автоматичне виявлення бібліотек Steam, Epic Games, GOG, Xbox)")


def cmd_run(args: argparse.Namespace) -> None:
    """Run tracker in foreground."""
    daemon = GameTrackerDaemon(config_dir=str(get_base_dir()))
    print("Запуск GameTracker у фоновому режимі (Ctrl+C для виходу)...")
    daemon.start()


def cmd_install_task(args: argparse.Namespace) -> None:
    """Install Windows Scheduled Task with highest privileges."""
    python_exe = sys.executable
    script_path = str(Path(__file__).parent / "service.py")
    task_name = "GameTrackerService"

    cmd = [
        "schtasks",
        "/Create",
        "/F",
        "/SC", "ONSTART",
        "/TN", task_name,
        "/TR", f'"{python_exe}" "{script_path}"',
        "/RU", "SYSTEM",
        "/RL", "HIGHEST",
    ]

    try:
        ret = subprocess.run(cmd, capture_output=True, text=True)
        if ret.returncode == 0:
            print(f"Завдання '{task_name}' успішно зареєстровано в Планувальнику завдань Windows (запуск при старті системи з правами SYSTEM).")
        else:
            print(f"Помилка реєстрації завдання:\n{ret.stderr}", file=sys.stderr)
            print("Переконайтеся, що ви запускаєте термінал від імені Адміністратора.")
    except Exception as e:
        print(f"Помилка: {e}", file=sys.stderr)


def cmd_uninstall_task(args: argparse.Namespace) -> None:
    """Delete scheduled task."""
    base_dir = get_base_dir()
    cfg_mgr = ConfigManager(str(base_dir / "config.json"))
    config = cfg_mgr.load()

    if not authenticate(config):
        return

    task_name = "GameTrackerService"
    cmd = ["schtasks", "/Delete", "/F", "/TN", task_name]
    try:
        ret = subprocess.run(cmd, capture_output=True, text=True)
        if ret.returncode == 0:
            print(f"Завдання '{task_name}' успішно видалено.")
        else:
            print(f"Помилка: {ret.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"Помилка: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="gametracker",
        description="GameTracker — захищений таймер та блокувальник ігор для Windows",
    )
    subparsers = parser.add_subparsers(dest="command")

    # status
    p_status = subparsers.add_parser("status", help="Показати поточний стан, зіграний час та залишок")
    p_status.set_defaults(func=cmd_status)

    # set-password
    p_pw = subparsers.add_parser("set-password", help="Встановити або змінити майстер-пароль")
    p_pw.set_defaults(func=cmd_set_password)

    # unlock
    p_unlock = subparsers.add_parser("unlock", help="Аварійне розблокування ігор (вимагає пароль)")
    p_unlock.set_defaults(func=cmd_unlock)

    # add-game
    p_add = subparsers.add_parser("add-game", help="Додати процес до списку блокування")
    p_add.add_argument("name", help="Назва файлу .exe (наприклад cs2.exe)")
    p_add.set_defaults(func=cmd_add_game)

    # remove-game
    p_rm = subparsers.add_parser("remove-game", help="Видалити процес зі списку блокування")
    p_rm.add_argument("name", help="Назва файлу .exe")
    p_rm.set_defaults(func=cmd_remove_game)

    # list-games
    p_list = subparsers.add_parser("list-games", help="Показати список відстежуваних ігор")
    p_list.set_defaults(func=cmd_list_games)

    # run
    p_run = subparsers.add_parser("run", help="Запустити демон у консолі")
    p_run.set_defaults(func=cmd_run)

    # install-task
    p_inst = subparsers.add_parser("install-task", help="Зареєструвати автозапуск як системне завдання")
    p_inst.set_defaults(func=cmd_install_task)

    # uninstall-task
    p_uninst = subparsers.add_parser("uninstall-task", help="Видалити завдання автозапуску")
    p_uninst.set_defaults(func=cmd_uninstall_task)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
