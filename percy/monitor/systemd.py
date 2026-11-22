"""Install/remove the background monitor as a systemd *user* service (no root)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

UNIT_NAME = "percy-monitor.service"
UNIT_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd" / "user"


def quote_exec_path(path: str) -> str:
    """Quote a path for ExecStart: spaces are common here, '%' is a systemd specifier."""
    if "\n" in path or '"' in path:
        raise ValueError(f"Python path can't be used in a systemd unit: {path!r}")
    return '"' + path.replace("\\", "\\\\").replace("%", "%%") + '"'


def unit_text(python: str = sys.executable) -> str:
    python = quote_exec_path(python)
    return f"""[Unit]
Description=Percy home network monitor (security checks + per-device activity log)
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart={python} -m percy monitor
Restart=on-failure
RestartSec=30
Nice=10

[Install]
WantedBy=default.target
"""


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=30, check=False)


def is_active() -> bool:
    return _systemctl("is-active", UNIT_NAME).stdout.strip() == "active"


def install(python: str = sys.executable) -> None:
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    (UNIT_DIR / UNIT_NAME).write_text(unit_text(python))
    for args in (("daemon-reload",), ("enable", "--now", UNIT_NAME)):
        done = _systemctl(*args)
        if done.returncode != 0:
            raise RuntimeError(f"systemctl --user {' '.join(args)} failed: {done.stderr.strip()}")


def uninstall() -> None:
    _systemctl("disable", "--now", UNIT_NAME)
    (UNIT_DIR / UNIT_NAME).unlink(missing_ok=True)
    _systemctl("daemon-reload")
