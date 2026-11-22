"""Desktop notifications via notify-send (they never take keyboard focus)."""
from __future__ import annotations

import html
import logging
import shutil
import subprocess

from percy.safe_text import clean

log = logging.getLogger(__name__)


def notify(title: str, body: str, urgent: bool = False) -> None:
    if not shutil.which("notify-send"):
        log.info("notify-send missing; %s: %s", title, body)
        return
    args = ["notify-send", "--app-name=Percy", "--icon=network-wireless-encrypted",
            f"--urgency={'critical' if urgent else 'normal'}", "--",
            # notify-send bodies are markup and the text can quote LAN device names.
            html.escape(clean(title, 120)), html.escape(clean(body))]
    try:
        subprocess.run(args, timeout=5, check=False, capture_output=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("Could not show notification: %s", exc)
