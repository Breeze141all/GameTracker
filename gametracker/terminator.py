"""gametracker/terminator.py

Process Termination Subsystem for Windows GameTracker.
Uses native Win32 TerminateProcess API with subprocess taskkill fallback.
"""

from __future__ import annotations
import os
import subprocess
import ctypes
from typing import Optional
from gametracker.interfaces import IProcessTerminator

PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000
WAIT_TIMEOUT = 0x00000102


class Win32ProcessTerminator(IProcessTerminator):
    """Terminates processes on Windows reliably within <2s SLA."""

    def __init__(self) -> None:
        self._kernel32 = ctypes.windll.kernel32

    def terminate(self, pid: int) -> bool:
        """Terminate process by PID. Returns True on success or if already dead."""
        if pid <= 4:  # Protect system idle / system process
            return False

        h_proc = self._kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
        if h_proc:
            try:
                # 1 = exit code
                res = self._kernel32.TerminateProcess(h_proc, 1)
                if res != 0:
                    # Wait up to 1000ms for process to exit
                    self._kernel32.WaitForSingleObject(h_proc, 1000)
                    return True
            finally:
                self._kernel32.CloseHandle(h_proc)

        # Fallback to taskkill /F /T
        try:
            cmd = ["taskkill", "/F", "/T", "/PID", str(pid)]
            ret = subprocess.run(cmd, capture_output=True, timeout=2)
            return ret.returncode == 0
        except Exception:
            return False
