"""Sub-routers: other TP-Link routers in the home besides the main (internet) one.

Detection never logs in. ``fingerprint`` reads public login-page endpoints to pick
the one library client that fits, so adding a router costs a single login attempt.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Callable, Iterable, Mapping

import requests

from percy.router.client import Router, _default_factories

FINGERPRINT_TIMEOUT_SEC = 4
FINGERPRINT_MAX_BYTES = 64 * 1024  # a login-parameter page is ~1 KB; never buffer more than this
ADMIN_PORT = 80
ROUTER_NAME_HINT = re.compile(r"archer|deco|mercusys|tp-?link|router|^tl-|^ex\d|^c\d{2}\b", re.IGNORECASE)
# shortcut: a few common TP-Link OUIs; hostnames catch the rest. Extend as needed.
TP_LINK_OUIS = frozenset({"14:EB:B6", "1C:61:B4", "50:C7:BF", "98:DA:C4", "C0:06:C3", "60:32:B1", "B0:BE:76",
                          "E8:48:B8", "3C:52:A1", "54:AF:97", "A8:42:A1", "AC:15:A2"})


@dataclass(frozen=True)
class SubRouter:
    host: str
    username: str = "admin"
    label: str = ""
    family: str = ""  # "ex", "c50" or a tplinkrouterc6u LuCI client name

    @property
    def name(self) -> str:
        return self.label or self.host

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "SubRouter":
        return cls(**{k: str(raw[k]) for k in ("host", "username", "label", "family") if k in raw})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Candidate:
    host: str
    name: str
    mac: str
    where: str          # how Percy found it
    reachable: bool     # admin page answers from this PC


def password_key(host: str) -> str:
    return f"router-password:{host}"


def auth_failed_key(host: str) -> str:
    return f"router_auth_failed:{host}"


def _post(url: str, referer: str) -> str:
    """Read a public page without following redirects (they could point off the LAN) and bounded in size."""
    try:
        with requests.post(url, headers={"Referer": referer}, timeout=FINGERPRINT_TIMEOUT_SEC,
                           allow_redirects=False, stream=True) as response:
            if response.is_redirect:
                return ""
            body = response.raw.read(FINGERPRINT_MAX_BYTES + 1, decode_content=True)
    except requests.RequestException:
        return ""
    return "" if len(body) > FINGERPRINT_MAX_BYTES else body.decode("utf-8", "replace")


def fingerprint(host: str) -> str | None:
    """Which login protocol the router's public pages advertise, or None if not a known TP-Link."""
    base = f"http://{host}"
    gdpr = _post(f"{base}/cgi/getGDPRParm", base + "/")
    if 'var nn="' in gdpr and 'var seq="' in gdpr:
        return "ex"
    # shortcut: getParm is shared by C50 and older MR models; C50 is the common one. Add MR if one appears.
    if 'var nn="' in _post(f"{base}/cgi/getParm", base + "/"):
        return "c50"
    from tplinkrouterc6u.discovery import discover_router

    try:
        return discover_router(host, timeout=FINGERPRINT_TIMEOUT_SEC).client_name
    except Exception:
        return None


def factories_for(family: str) -> tuple:
    if family == "ex":
        return _default_factories()
    if family == "c50":
        from tplinkrouterc6u.client.c50 import TPLinkC50Client
        classes: tuple = (TPLinkC50Client,)
    else:
        import tplinkrouterc6u
        cls = getattr(tplinkrouterc6u, family, None) if family.startswith("TplinkRouter") else None
        if cls is None:
            raise ValueError(f"Percy doesn't know how to log in to a '{family or 'unknown'}' router")
        classes = (cls,)
    return tuple(lambda host, user, pwd, timeout, c=c: c(host, pwd, username=user, timeout=timeout)
                 for c in classes)


def open_router(sub: SubRouter, password: str | None) -> Router:
    return Router(sub.host, sub.username, password or "", factories=factories_for(sub.family))


def looks_like_router(hostname: str, mac: str) -> bool:
    return bool(ROUTER_NAME_HINT.search(hostname or "")) or mac.upper()[:8] in TP_LINK_OUIS


def detect(devices: Iterable[tuple[str, str, str]], gateways: Iterable[tuple[str, str]],
           known_hosts: Iterable[str], main_host: str, reachable: Callable[[str], bool],
           identify: Callable[[str], str | None] = fingerprint) -> list[Candidate]:
    """Routers Percy hasn't been given yet.

    ``devices`` are (mac, ip, hostname) seen on the main network; ``gateways`` are
    (interface, gateway) of this PC, which reveal a sub-router's own LAN side when
    this PC is plugged into, or on the Wi-Fi of, one.
    """
    skip = set(known_hosts) | {main_host}
    found: dict[str, Candidate] = {}
    for mac, ip, hostname in devices:
        if ip and ip not in skip and looks_like_router(hostname, mac):
            found[ip] = Candidate(ip, hostname or "TP-Link device", mac.upper(), "on the main network",
                                  reachable(ip))
    for iface, gateway in gateways:
        if gateway in skip or gateway in found or not _private(gateway):
            continue
        if identify(gateway):  # only list gateways that really are TP-Link routers
            found[gateway] = Candidate(gateway, f"router on {iface}", "", f"this PC's gateway on {iface}", True)
    return sorted(found.values(), key=lambda c: c.host)


def _private(ip: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip).is_private
    except ValueError:
        return False
