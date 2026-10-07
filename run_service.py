"""run_service.py

Standalone entry point for compiling GameTrackerService.exe.
Runs the background tracking daemon without any console window.
"""

import sys
from gametracker.service import run_daemon

if __name__ == "__main__":
    run_daemon()
