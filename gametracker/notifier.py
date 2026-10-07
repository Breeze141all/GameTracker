"""gametracker/notifier.py

Desktop Notification Subsystem for Windows GameTracker.
Delivers native Windows Toast Notifications asynchronously without blocking engine loops.
"""

from __future__ import annotations
import subprocess
import threading
import logging
from typing import Optional
from gametracker.interfaces import INotificationDispatcher

logger = logging.getLogger("gametracker.notifier")


class WindowsNotificationDispatcher(INotificationDispatcher):
    """Dispatches native Windows 10/11 Toast Notifications via PowerShell."""

    def __init__(self, app_id: str = "GameTimeTracker") -> None:
        self.app_id = app_id

    def notify(self, remaining_minutes: int, title: str, message: str) -> bool:
        """Dispatch desktop toast notification in background thread."""
        thread = threading.Thread(
            target=self._send_toast,
            args=(title, message),
            daemon=True,
        )
        thread.start()
        return True

    def _send_toast(self, title: str, message: str) -> None:
        """Execute toast notification PowerShell command."""
        # Clean special chars
        safe_title = title.replace('"', '""').replace("'", "''")
        safe_message = message.replace('"', '""').replace("'", "''")

        ps_script = (
            f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
            f"$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
            f"$textNodes = $template.GetElementsByTagName('text'); "
            f"$textNodes.Item(0).AppendChild($template.CreateTextNode('{safe_title}')) > $null; "
            f"$textNodes.Item(1).AppendChild($template.CreateTextNode('{safe_message}')) > $null; "
            f"$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
            f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{self.app_id}').Show($toast);"
        )

        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                timeout=5,
            )
        except Exception as e:
            logger.warning(f"Failed to dispatch Windows toast: {e}")
