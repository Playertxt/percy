"""Settings and file locations (XDG). Secrets never go here; see percy.secrets."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path


def _xdg(var: str, fallback: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / fallback)


CONFIG_DIR = _xdg("XDG_CONFIG_HOME", ".config") / "percy"
DATA_DIR = _xdg("XDG_DATA_HOME", ".local/share") / "percy"
CONFIG_FILE = CONFIG_DIR / "config.json"
DB_FILE = DATA_DIR / "percy.db"

# Pinned, at least two weeks old when chosen (2026-11-21). Bump deliberately.
ADGUARD_IMAGE = "adguard/adguardhome:v0.107.80"
NETALERTX_IMAGE = "jokobsk/netalertx:26.10.28"


@dataclass(frozen=True)
class Settings:
    router_host: str = "192.168.1.1"
    router_username: str = "user"  # XC220-G3v login page sends adminType="user", not "admin"
    # LAN address of this PC that other devices will use as DNS (AdGuard Home).
    dns_host_ip: str = ""
    adguard_web_port: int = 3000
    adguard_username: str = "percy"
    # Fallback DNS handed out next to AdGuard so the internet keeps working if this PC is off.
    fallback_dns: str = "1.1.1.1"
    check_interval_min: int = 30
    activity_poll_sec: int = 60
    activity_retention_days: int = 30
    notify: bool = True
    claude_summary: bool = True
    claude_model: str = "claude-opus-5-5"
    # Other routers in the home: dicts of host/username/label/family (see percy.router.fleet.SubRouter).
    sub_routers: tuple = ()

    def with_changes(self, **changes) -> "Settings":
        return replace(self, **changes)


def private_dir(path: Path) -> Path:
    """Create (or tighten) a directory only this user can read."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def load_settings(path: Path = CONFIG_FILE) -> Settings:
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError:
        return Settings()
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read settings file {path}: {exc}") from exc
    known = {f.name for f in fields(Settings)}
    values = {k: v for k, v in raw.items() if k in known}
    if "sub_routers" in values:
        values["sub_routers"] = tuple(dict(r) for r in values["sub_routers"] or () if isinstance(r, dict))
    return Settings(**values)


def save_settings(settings: Settings, path: Path = CONFIG_FILE) -> None:
    import tempfile

    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".config-", suffix=".tmp")  # 0600, unique
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(asdict(settings), indent=2))
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
