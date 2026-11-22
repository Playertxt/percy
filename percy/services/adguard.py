"""REST client for AdGuard Home (tested against the v0.107 API)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

REQUEST_TIMEOUT_SEC = 10
QUERYLOG_PAGE = 500

# Popular, well-maintained block lists people can add with one click.
RECOMMENDED_LISTS = (
    ("AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"),
    ("OISD big", "https://big.oisd.nl"),
    ("HaGeZi Multi PRO", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt"),
    ("HaGeZi Threat Intelligence (malware/phishing)",
     "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt"),
)

BLOCKED_REASONS = frozenset({
    "FilteredBlackList", "FilteredBlockedService", "FilteredParental",
    "FilteredSafeBrowsing", "FilteredSafeSearch", "FilteredInvalid",
})


class AdGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdGuardStatus:
    running: bool
    protection_enabled: bool
    version: str
    dns_addresses: tuple[str, ...]


@dataclass(frozen=True)
class QueryLogEntry:
    time: str          # RFC 3339, e.g. 2026-11-21T16:40:12.123+05:30
    client_ip: str
    client_name: str
    domain: str
    qtype: str
    blocked: bool
    reason: str


def parse_querylog_entry(raw: dict[str, Any]) -> QueryLogEntry | None:
    question = raw.get("question") or {}
    domain = str(question.get("name") or question.get("host") or "").rstrip(".").lower()
    if not domain or not raw.get("time"):
        return None
    reason = str(raw.get("reason", ""))
    info = raw.get("client_info") or {}
    return QueryLogEntry(
        time=str(raw["time"]),
        client_ip=str(raw.get("client", "")),
        client_name=str(info.get("name", "") or ""),
        domain=domain,
        qtype=str(question.get("type", "")),
        blocked=reason in BLOCKED_REASONS,
        reason=reason,
    )


class AdGuard:
    def __init__(self, base_url: str, username: str, password: str | None,
                 session: requests.Session | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._session = session or requests.Session()
        if password:
            self._session.auth = (username, password)

    def _call(self, method: str, path: str, **kwargs) -> Any:
        try:
            resp = self._session.request(method, self._base + path, timeout=REQUEST_TIMEOUT_SEC, **kwargs)
        except requests.RequestException as exc:
            raise AdGuardError(f"AdGuard Home is not reachable at {self._base}: {exc}") from exc
        if resp.status_code == 401 or resp.status_code == 403:
            raise AdGuardError("AdGuard Home rejected Percy's login. Re-run ad blocker setup.")
        if resp.status_code >= 400:
            raise AdGuardError(f"AdGuard Home error {resp.status_code} on {path}: {resp.text[:200]}")
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -- first run -------------------------------------------------------
    def needs_setup(self) -> bool:
        try:
            resp = self._session.get(self._base + "/control/install/get_addresses",
                                     timeout=REQUEST_TIMEOUT_SEC)
        except requests.RequestException as exc:
            raise AdGuardError(f"AdGuard Home is not reachable at {self._base}: {exc}") from exc
        return resp.status_code == 200

    def first_run_setup(self, username: str, password: str) -> None:
        body = {
            "web": {"ip": "0.0.0.0", "port": 3000},
            "dns": {"ip": "0.0.0.0", "port": 53},
            "username": username,
            "password": password,
        }
        self._call("POST", "/control/install/configure", json=body)
        self._session.auth = (username, password)

    # -- status & control -----------------------------------------------
    def status(self) -> AdGuardStatus:
        data = self._call("GET", "/control/status") or {}
        return AdGuardStatus(
            running=bool(data.get("running", False)),
            protection_enabled=bool(data.get("protection_enabled", False)),
            version=str(data.get("version", "")),
            dns_addresses=tuple(data.get("dns_addresses") or ()),
        )

    def set_protection(self, enabled: bool) -> None:
        self._call("POST", "/control/protection", json={"enabled": enabled})

    def stats(self) -> dict[str, Any]:
        return self._call("GET", "/control/stats") or {}

    # -- block lists -----------------------------------------------------
    def filters(self) -> list[dict[str, Any]]:
        data = self._call("GET", "/control/filtering/status") or {}
        return list(data.get("filters") or [])

    def add_filter(self, name: str, url: str) -> None:
        if any(f.get("url") == url for f in self.filters()):
            return
        self._call("POST", "/control/filtering/add_url", json={"name": name, "url": url, "whitelist": False})

    def remove_filter(self, url: str) -> None:
        self._call("POST", "/control/filtering/remove_url", json={"url": url, "whitelist": False})

    # -- blocked apps (TikTok, games, ...) -------------------------------
    def available_services(self) -> list[dict[str, Any]]:
        data = self._call("GET", "/control/blocked_services/all") or {}
        return list(data.get("blocked_services") or [])

    def blocked_services(self) -> list[str]:
        data = self._call("GET", "/control/blocked_services/get") or {}
        return list(data.get("ids") or [])

    def set_blocked_services(self, ids: list[str]) -> None:
        self._call("PUT", "/control/blocked_services/update", json={"ids": sorted(set(ids))})

    # -- per-device query log -------------------------------------------
    def querylog_page(self, older_than: str | None = None,
                      limit: int = QUERYLOG_PAGE) -> tuple[list[QueryLogEntry], str | None]:
        params: dict[str, Any] = {"limit": limit}
        if older_than:
            params["older_than"] = older_than
        data = self._call("GET", "/control/querylog", params=params) or {}
        if not isinstance(data, dict):
            raise AdGuardError("AdGuard Home returned an unexpected query-log page (is setup finished?)")
        entries = [e for raw in data.get("data") or [] if (e := parse_querylog_entry(raw))]
        return entries, (data.get("oldest") or None)

    def blocks(self, domain: str) -> bool:
        """True if AdGuard would block this domain right now."""
        data = self._call("GET", "/control/filtering/check_host", params={"name": domain}) or {}
        return str(data.get("reason", "")) in BLOCKED_REASONS
