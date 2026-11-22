"""Router settings that Percy can show and change, discovered by probing field names.

Every change is a two-step affair: ``plan_*`` builds an immutable ChangePlan
(showing before/after) without touching the router, and ``apply`` performs it
and reads the value back to confirm. The UI always shows the plan first.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from percy.router.client import Router, RouterError

DHCP_POOL = "DEV2_DHCPV4_SERVER_POOL"
WIFI_SSID = "DEV2_WIFI_SSID"
WIFI_AP = "DEV2_WIFI_AP"
WIFI_ADT = "DEV2_ADT_WIFI"
TELNET = "DEV2_TELNET_CFG"
SSH = "DEV2_SSH_CFG"
UPNP = "DEV2_UPNP_CFG"
UPNP_MAPS = "DEV2_UPNP_PORTMAPPING"
WPS = "DEV2_WIFI_WPS"
REMOTE_UI = "DEV2_UI_REMOTE_ACCESS"
DMZ = "DEV2_DMZ_HOST_CFG"
CWMP = "DEV2_CWMP_CFG"
WIFI_COMMON = "DEV2_ADT_WIFI_COMMON"
DHCP_RESERVATION = "DEV2_DHCPV4_POOL_STATICADDR"  # fields from main/dhcpStaticEdit.htm

# Objects shown by `percy router-probe` and read by the security checks.
PROBE_OBJECTS = (DHCP_POOL, WIFI_SSID, WIFI_AP, WIFI_ADT, TELNET, SSH, UPNP, UPNP_MAPS,
                 WPS, REMOTE_UI, DMZ, CWMP, "DEV2_DEV_INFO", WIFI_COMMON)

ENABLE_FIELDS = ("enable", "Enable", "X_TP_Enable", "enabled", "telnetLocalEnabled")
DNS_FIELDS = ("DNSServers", "dnsServers", "DNSServer", "X_TP_DNSServers")
SSID_FIELDS = ("SSID", "ssid", "X_TP_SSID")
PASSWORD_FIELDS = ("KeyPassphrase", "X_TP_PreSharedKey", "PreSharedKey", "pskKey", "psk_key",
                   "wpaKey", "X_TP_KeyPassphrase", "password")
SECURITY_FIELDS = ("ModeEnabled", "securityMode", "X_TP_SecurityMode", "encryption", "beaconType")
SECRET_HINT = re.compile(r"pass|psk|key|secret|pwd|token|pin|community|auth|wps|cred", re.IGNORECASE)

# XC220 keeps every network of a band in one DEV2_ADT_WIFI_COMMON row, as <prefix>SSID/PSK/...
# backhaul* are the mesh links the router manages itself, so Percy leaves them alone.
WIFI_COMMON_PREFIXES = {"primary": "", "guest": " guest", "mssid1": " extra 1", "mssid2": " extra 2",
                        "mssid3": " extra 3"}

MIN_WIFI_PASSWORD = 12
MAX_WIFI_PASSWORD = 63


@dataclass(frozen=True)
class ChangePlan:
    title: str
    oid: str
    stack: str
    changes: Mapping[str, str]
    before: Mapping[str, str]
    secret_fields: frozenset[str] = field(default_factory=frozenset)
    adds: bool = False  # create a new instance under ``stack`` instead of changing ``stack``

    def describe(self) -> list[str]:
        lines = []
        for key, new in self.changes.items():
            old = self.before.get(key, "(unset)")
            if key in self.secret_fields:
                old, new = "••••••", "•••••• (new)"
            lines.append(f"{key}: {old} → {new}")
        return lines


@dataclass(frozen=True)
class WifiNetwork:
    oid: str
    stack: str
    ssid: str
    enabled: bool | None
    security: str | None
    band: str
    ssid_field: str
    password_field: str | None
    password_oid: str | None
    password_stack: str | None


def first_field(row: Mapping[str, object], candidates: Iterable[str]) -> str | None:
    for name in candidates:
        if name in row:
            return name
    return None


def as_bool(value: object) -> bool | None:
    text = str(value).strip().lower()
    if text in ("1", "true", "on", "yes", "enabled"):
        return True
    if text in ("0", "false", "off", "no", "disabled", ""):
        return False
    return None


def mask_row(row: Mapping[str, object]) -> dict[str, object]:
    return {k: ("••••••" if SECRET_HINT.search(k) and v not in ("", None) else v) for k, v in row.items()}


def parse_dns_list(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[,\s]+", value or "") if part.strip()]


def validate_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid IPv4 address") from exc


def validate_wifi_password(password: str) -> str:
    if not MIN_WIFI_PASSWORD <= len(password) <= MAX_WIFI_PASSWORD:
        raise ValueError(f"Wi-Fi password must be {MIN_WIFI_PASSWORD}-{MAX_WIFI_PASSWORD} characters")
    if not password.isprintable() or not password.isascii():
        raise ValueError("Wi-Fi password must use plain printable ASCII characters")
    return password


def validate_ssid(ssid: str) -> str:
    if not 1 <= len(ssid.encode()) <= 32:
        raise ValueError("Wi-Fi name must be 1-32 bytes")
    return ssid


class RouterSettings:
    """Reads and plans changes for one connected Router."""

    def __init__(self, router: Router) -> None:
        self._router = router

    # -- reading ---------------------------------------------------------
    def probe(self) -> dict[str, list[dict[str, object]]]:
        result: dict[str, list[dict[str, object]]] = {}
        for oid in PROBE_OBJECTS:
            try:
                result[oid] = [mask_row(r) for r in self._router.read(oid)]
            except RouterError as exc:
                result[oid] = [{"error": str(exc)}]
        return result

    def service_enabled(self, oid: str) -> bool | None:
        """True/False for Telnet, SSH, UPnP, WPS, remote admin... None if unknown."""
        try:
            rows = self._router.read(oid)
        except RouterError:
            return None
        states = [as_bool(row[f]) for row in rows if (f := first_field(row, ENABLE_FIELDS))]
        known = [s for s in states if s is not None]
        return any(known) if known else None

    def upnp_mappings(self) -> list[dict[str, object]]:
        try:
            return self._router.read(UPNP_MAPS)
        except RouterError:
            return []

    def dhcp_dns(self) -> list[str]:
        """DNS servers the router hands out to devices; empty if unknown."""
        try:
            pool = self._dhcp_pool()
        except RouterError:
            return []
        if pool is None:
            return []
        name = first_field(pool, DNS_FIELDS)
        return parse_dns_list(str(pool.get(name, ""))) if name else []

    def wifi_networks(self) -> list[WifiNetwork]:
        networks = self._wifi_common_networks()
        if networks:
            return networks
        for oid in (WIFI_SSID, WIFI_ADT):
            try:
                rows = self._router.read(oid)
            except RouterError:
                continue
            for i, row in enumerate(rows):
                ssid_field = first_field(row, SSID_FIELDS)
                if not ssid_field:
                    continue
                pw_oid, pw_stack, pw_field = self._password_location(oid, row, i)
                sec_field = first_field(row, SECURITY_FIELDS)
                enable_field = first_field(row, ENABLE_FIELDS)
                networks.append(WifiNetwork(
                    oid=oid,
                    stack=str(row.get("stack", f"{i + 1},0,0,0,0,0")),
                    ssid=str(row[ssid_field]),
                    enabled=as_bool(row[enable_field]) if enable_field else None,
                    security=str(row[sec_field]) if sec_field else None,
                    band=_band_label(row, i),
                    ssid_field=ssid_field,
                    password_field=pw_field,
                    password_oid=pw_oid,
                    password_stack=pw_stack,
                ))
            if networks:
                break
        return networks

    # -- planning --------------------------------------------------------
    def plan_dhcp_dns(self, servers: list[str]) -> ChangePlan:
        servers = [validate_ipv4(s) for s in servers if s.strip()]
        if not servers:
            raise ValueError("Give at least one DNS server")
        pool = self._dhcp_pool()
        if pool is None:
            raise RouterError("This router did not expose its DHCP server settings")
        name = first_field(pool, DNS_FIELDS)
        if name is None:
            raise RouterError("Could not find the DHCP DNS field on this firmware. "
                              "Run `percy router-probe` and share the DEV2_DHCPV4_SERVER_POOL fields.")
        return ChangePlan(
            title="DNS server handed out to your devices",
            oid=DHCP_POOL, stack=str(pool.get("stack", "1,0,0,0,0,0")),
            changes={name: ",".join(servers)}, before={name: str(pool.get(name, ""))},
        )

    def plan_reservation(self, mac: str, ip: str) -> ChangePlan | None:
        """Always give ``mac`` the address ``ip`` (DHCP reservation). None if that is already so."""
        mac, ip = mac.strip().upper(), validate_ipv4(ip)
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
            raise ValueError(f"'{mac}' is not a MAC address")
        rows = self._router.read(DHCP_RESERVATION)
        for row in rows:
            if str(row.get("yiaddr")) == ip and str(row.get("chaddr", "")).upper() != mac:
                raise RouterError(f"{ip} is already reserved for {row.get('chaddr')}; free it first")
        mine = next((r for r in rows if str(r.get("chaddr", "")).upper() == mac), None)
        title = f"Always give this PC ({mac}) the address {ip}"
        if mine is None:
            pool = self._dhcp_pool()
            if pool is None:
                raise RouterError("This router did not expose its DHCP server settings")
            return ChangePlan(title=title, oid=DHCP_RESERVATION, stack=str(pool.get("stack", "1,0,0,0,0,0")),
                              changes={"chaddr": mac, "yiaddr": ip, "enable": "1"}, before={}, adds=True)
        if str(mine.get("yiaddr")) == ip and as_bool(mine.get("enable", "1")):
            return None
        return ChangePlan(title=title, oid=DHCP_RESERVATION, stack=str(mine.get("stack")),
                          changes={"yiaddr": ip, "enable": "1"},
                          before={"yiaddr": str(mine.get("yiaddr", "")), "enable": str(mine.get("enable", ""))})

    def plan_service(self, oid: str, enabled: bool, title: str) -> list[ChangePlan]:
        """One plan per instance that needs changing (WPS has one per Wi-Fi network); [] if already done."""
        rows = [(row, name) for row in self._router.read(oid) if (name := first_field(row, ENABLE_FIELDS))]
        if not rows:
            raise RouterError(f"This firmware does not expose an on/off switch for {oid}")
        return [ChangePlan(
                    title=title if len(rows) == 1 else f"{title} (#{_instance(str(row.get('stack', '')))})",
                    oid=oid, stack=str(row.get("stack", "0,0,0,0,0,0")),
                    changes={name: "1" if enabled else "0"}, before={name: str(row[name])})
                for row, name in rows if as_bool(row[name]) is not enabled]

    def plan_wifi(self, net: WifiNetwork, ssid: str | None = None,
                  password: str | None = None) -> list[ChangePlan]:
        plans = []
        if ssid is not None and ssid != net.ssid:
            plans.append(ChangePlan(
                title=f"Wi-Fi name ({net.band})", oid=net.oid, stack=net.stack,
                changes={net.ssid_field: validate_ssid(ssid)}, before={net.ssid_field: net.ssid},
            ))
        if password:
            if not (net.password_field and net.password_oid and net.password_stack):
                raise RouterError("Could not find the Wi-Fi password field on this firmware. "
                                  "Run `percy router-probe` to see what it exposes.")
            plans.append(ChangePlan(
                title=f"Wi-Fi password ({net.band})", oid=net.password_oid, stack=net.password_stack,
                changes={net.password_field: validate_wifi_password(password)},
                before={net.password_field: ""}, secret_fields=frozenset({net.password_field}),
            ))
        return plans

    # -- applying --------------------------------------------------------
    def apply(self, plan: ChangePlan) -> bool:
        """Write the plan, then read it back. Returns False if it couldn't be verified."""
        if plan.adds:
            self._router.add(plan.oid, plan.stack, plan.changes)
            return any(all(_normalise(k, row.get(k, "")) == _normalise(k, v) for k, v in plan.changes.items())
                       for row in self._router.read(plan.oid))
        self._router.write(plan.oid, plan.stack, plan.changes)
        if plan.secret_fields:
            return False  # passwords can't be read back; the write itself raised on failure
        rows = self._router.read(plan.oid)
        matching = [r for r in rows if str(r.get("stack", "")) == plan.stack]
        if not matching and len(rows) == 1 and "stack" not in rows[0]:
            matching = rows  # single-instance object that doesn't report its stack
        if not matching:
            return False
        row = matching[0]
        verified = True
        for key, value in plan.changes.items():
            if key not in row:
                verified = False
                continue
            if _normalise(key, row[key]) != _normalise(key, value):
                raise RouterError(f"The router did not keep the change to {key} "
                                  f"(it reports '{row.get(key)}').")
        return verified

    # -- helpers ---------------------------------------------------------
    def _wifi_common_networks(self) -> list[WifiNetwork]:
        try:
            rows = self._router.read(WIFI_COMMON)
        except RouterError:
            return []
        networks = []
        for i, row in enumerate(rows):
            for prefix, label in WIFI_COMMON_PREFIXES.items():
                ssid_field = f"{prefix}SSID"
                if ssid_field not in row:
                    continue
                pw_field = f"{prefix}PSK" if f"{prefix}PSK" in row else None
                stack = str(row.get("stack", f"{i + 1},0,0,0,0,0"))
                security = row.get(f"{prefix}ModeEnabled")
                networks.append(WifiNetwork(
                    oid=WIFI_COMMON, stack=stack, ssid=str(row[ssid_field]),
                    enabled=as_bool(row.get(f"{prefix}Enable", "")),
                    security=str(security) if security is not None else None,
                    band=_band_label(row, i) + label, ssid_field=ssid_field,
                    password_field=pw_field, password_oid=WIFI_COMMON if pw_field else None,
                    password_stack=stack if pw_field else None,
                ))
        return networks

    def _dhcp_pool(self) -> dict | None:
        rows = self._router.read(DHCP_POOL)
        return rows[0] if rows else None

    def _password_location(self, oid: str, row: Mapping[str, object],
                           index: int) -> tuple[str | None, str | None, str | None]:
        own = first_field(row, PASSWORD_FIELDS)
        stack = str(row.get("stack", f"{index + 1},0,0,0,0,0"))
        if own:
            return oid, stack, own
        if oid != WIFI_SSID:
            return None, None, None
        try:  # TR-181 keeps the passphrase on the AccessPoint that references this SSID
            aps = self._router.read(WIFI_AP)
        except RouterError:
            return None, None, None
        ap = _matching_access_point(aps, stack)
        name = first_field(ap, PASSWORD_FIELDS) if ap else None
        if ap is None or name is None:
            return None, None, None  # ambiguous or missing: refuse rather than change the wrong network
        return WIFI_AP, str(ap.get("stack")), name


def _normalise(key: str, value: object) -> object:
    if key in ENABLE_FIELDS:
        return as_bool(value)
    if key in DNS_FIELDS:
        return parse_dns_list(str(value))
    return str(value).strip()


def _instance(stack: str) -> str:
    return stack.split(",")[0] if stack else ""


def _matching_access_point(aps: list[dict], ssid_stack: str) -> dict | None:
    """The AccessPoint whose SSIDReference points at this SSID instance, else an unambiguous stack match."""
    instance = _instance(ssid_stack)
    by_ref = []
    for ap in aps:
        ref_field = next((k for k in ap if "ssidref" in k.lower()), None)
        if ref_field:
            match = re.search(r"SSID\.(\d+)", str(ap[ref_field]), re.IGNORECASE)
            if match and match.group(1) == instance:
                by_ref.append(ap)
    if by_ref:
        return by_ref[0] if len(by_ref) == 1 else None
    if any(any("ssidref" in k.lower() for k in ap) for ap in aps):
        return None  # references exist but none point here
    same_stack = [ap for ap in aps if str(ap.get("stack", "")) == ssid_stack]
    return same_stack[0] if len(same_stack) == 1 else None


def _band_label(row: Mapping[str, object], index: int) -> str:
    for key in ("X_TP_Band", "band", "OperatingFrequencyBand", "frequency"):
        if key in row and str(row[key]).strip():
            return str(row[key])
    return ("2.4 GHz", "5 GHz")[index] if index < 2 else f"network {index + 1}"
