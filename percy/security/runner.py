"""Gather NetworkFacts from the router, the LAN and AdGuard, then run the checks."""
from __future__ import annotations

import logging
import secrets as pysecrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from percy import secrets
from percy.activity.store import FindingRecord, Store, utcnow
from percy.config import Settings
from percy.net import dns, scan
from percy.router import Router, RouterAuthError, RouterError, RouterSettings
from percy.router import fleet
from percy.router import settings as rs
from percy.security.checks import (DEVICE_RISKY_PORTS, ROUTER_PORTS, Finding, NetworkFacts, SeenDevice,
                                   run_checks)

log = logging.getLogger(__name__)
SERVICE_OIDS = {"telnet": rs.TELNET, "ssh": rs.SSH, "upnp": rs.UPNP, "wps": rs.WPS,
                "remote_ui": rs.REMOTE_UI, "dmz": rs.DMZ}
DEVICE_PORT_TIMEOUT_SEC = 0.8
# Set when the router rejects the saved password; cleared by a successful manual login.
AUTH_FAILED_KEY = "router_auth_failed"


def clear_auth_failure(store: Store) -> None:
    store.set_meta(AUTH_FAILED_KEY, "")


@dataclass(frozen=True)
class Report:
    run_ts: str
    findings: tuple[Finding, ...]
    facts: NetworkFacts


@dataclass(frozen=True)
class RouterFacts:
    model: str = ""
    firmware: str = ""
    logged_in: bool = False
    services: dict | None = None
    upnp_mappings: tuple = ()
    wifi_security: tuple = ()
    dhcp_dns: tuple = ()
    new_macs: frozenset[str] = frozenset()
    live_macs: frozenset[str] = frozenset()
    error: str | None = None


def read_router(settings: Settings, password: str | None, store: Store) -> RouterFacts:
    if not password:
        return RouterFacts(error="Router password not set, so router settings (UPnP, WPS, remote admin, "
                                 "connected devices) were not checked. Add it in Settings.")
    if store.get_meta(AUTH_FAILED_KEY):
        return RouterFacts(error="The router rejected the saved password, so Percy stopped logging in "
                                 "to avoid locking its admin page. Save the password again in Settings.")
    try:
        with Router(settings.router_host, settings.router_username, password) as router:
            info = router.info()
            rset = RouterSettings(router)
            services = {k: rset.service_enabled(oid) for k, oid in SERVICE_OIDS.items()}
            mappings = tuple(rset.upnp_mappings())
            # A switched-off network can't be joined, so its security mode doesn't matter.
            wifi = tuple((n.ssid or n.band, n.security) for n in rset.wifi_networks()
                         if n.security and n.enabled is not False)
            dhcp_dns = tuple(rset.dhcp_dns())
            devices = router.devices()
    except RouterAuthError as exc:
        store.set_meta(AUTH_FAILED_KEY, utcnow())
        store.add_event("error", "Router login rejected; background logins paused until the password is re-saved")
        return RouterFacts(error=f"Router: {exc}")
    except RouterError as exc:
        return RouterFacts(error=f"Router: {exc}")
    active = [d for d in devices if d.active and d.mac]
    new = store.upsert_devices((d.mac, d.ip, d.hostname, d.connection) for d in active)
    return RouterFacts(model=info.model, firmware=info.firmware, logged_in=True, services=services,
                       upnp_mappings=mappings, wifi_security=wifi, dhcp_dns=dhcp_dns, new_macs=frozenset(new),
                       live_macs=frozenset(d.mac.upper() for d in active))


@dataclass(frozen=True)
class SubRouterFacts:
    name: str
    host: str
    open_ports: tuple[int, ...] = ()
    logged_in: bool = False
    new_macs: frozenset[str] = frozenset()
    live_macs: frozenset[str] = frozenset()
    error: str | None = None


def read_sub_router(sub: fleet.SubRouter, store: Store) -> SubRouterFacts:
    """Port-scan a sub-router and, when its admin page answers, log in once for its devices."""
    ports = tuple(scan.scan_ports(sub.host, list(ROUTER_PORTS)))
    base = SubRouterFacts(sub.name, sub.host, ports)
    if fleet.ADMIN_PORT not in ports:
        return base  # unreachable: reported by check_sub_routers, not an error
    try:
        password = secrets.get_secret(fleet.password_key(sub.host))
    except secrets.SecretStoreError as exc:
        return SubRouterFacts(sub.name, sub.host, ports, error=f"{sub.name}: {exc}")
    if not password:
        return SubRouterFacts(sub.name, sub.host, ports, error=f"{sub.name}: no password saved "
                              f"(run `percy routers add {sub.host}`).")
    if store.get_meta(fleet.auth_failed_key(sub.host)):
        return SubRouterFacts(sub.name, sub.host, ports, error=f"{sub.name} rejected the saved password, so "
                              f"Percy stopped logging in. Run `percy routers add {sub.host}` again.")
    try:
        with fleet.open_router(sub, password) as router:
            devices = router.devices()
    except RouterAuthError as exc:
        store.set_meta(fleet.auth_failed_key(sub.host), utcnow())
        return SubRouterFacts(sub.name, sub.host, ports, error=f"{sub.name}: {exc}")
    except (RouterError, ValueError) as exc:
        return SubRouterFacts(sub.name, sub.host, ports, error=f"{sub.name}: {exc}")
    active = [d for d in devices if d.active and d.mac]
    new = store.upsert_devices((d.mac, d.ip, d.hostname, f"{sub.name} · {d.connection}") for d in active)
    return SubRouterFacts(sub.name, sub.host, ports, True, frozenset(new),
                          frozenset(d.mac.upper() for d in active))


def find_candidates(settings: Settings, devices, gateway: str) -> tuple[fleet.Candidate, ...]:
    """``devices`` are (mac, ip, hostname) online now, so a router removed long ago isn't reported."""
    known = [fleet.SubRouter.from_dict(r).host for r in settings.sub_routers]
    return tuple(fleet.detect(devices, scan.default_gateways(), known, gateway,
                              lambda ip: scan.tcp_open(ip, fleet.ADMIN_PORT, 1.0)))


def lan_devices(store: Store, router: RouterFacts, baseline: bool,
                extra: tuple[SubRouterFacts, ...] = ()) -> tuple[SeenDevice, ...]:
    """Devices online right now (router list + this PC's neighbour table), matched by MAC.

    On the very first run everything is "new", which says nothing; that run only
    records a baseline.
    """
    neigh = [n for n in scan.neighbors() if "FAILED" not in n.state and "INCOMPLETE" not in n.state]
    new = set(router.new_macs).union(*(s.new_macs for s in extra)) | set(
        store.upsert_devices((n.mac, n.ip, "", "") for n in neigh))
    if baseline:
        store.add_event("baseline", f"First check: recorded {len(new)} devices as the starting point")
        new = set()
    live = set(router.live_macs).union(*(s.live_macs for s in extra)) | {n.mac for n in neigh}
    return tuple(SeenDevice(mac=d.mac, ip=d.ip, name=d.display_name, trusted=d.trusted,
                            first_seen_now=d.mac in new)
                 for d in store.devices() if d.mac in live)


def nx_hijack(server: str) -> str | None:
    """Ask the router to resolve a name that cannot exist; an IP back means DNS rewriting."""
    name = f"percy-{pysecrets.token_hex(6)}.invalid-domain-test.com"
    try:
        answer = dns.resolve_a(name, server)
    except dns.DnsError:
        return None
    return answer.addresses[0] if answer.addresses else None


def gather_facts(settings: Settings, router_password: str | None, store: Store,
                 adblock_running: bool | None = None) -> NetworkFacts:
    gateway = settings.router_host or scan.default_gateway() or "192.168.1.1"
    baseline = not store.devices()
    router = read_router(settings, router_password, store)
    subs = tuple(read_sub_router(fleet.SubRouter.from_dict(r), store) for r in settings.sub_routers)
    devices = lan_devices(store, router, baseline, subs)
    hostnames = {d.mac: d.hostname for d in store.devices()}
    candidates = find_candidates(settings, [(d.mac, d.ip, hostnames.get(d.mac, "")) for d in devices], gateway)
    targets = sorted({d.ip for d in devices if d.ip and d.ip != gateway})
    risky = list(DEVICE_RISKY_PORTS)

    with ThreadPoolExecutor(max_workers=8) as pool:
        router_ports = pool.submit(scan.scan_ports, gateway, list(ROUTER_PORTS))
        nx = pool.submit(nx_hijack, gateway)
        upnp = pool.submit(scan.ssdp_gateways)
        per_device = {ip: pool.submit(scan.scan_ports, ip, risky, DEVICE_PORT_TIMEOUT_SEC) for ip in targets}
        device_ports = {ip: tuple(open_ports) for ip, fut in per_device.items() if (open_ports := fut.result())}
        router_open = tuple(router_ports.result())
        nx_ip = nx.result()
        responders = tuple(upnp.result())

    wifi = list(router.wifi_security)
    link = scan.wifi_link()
    if link and not wifi:
        wifi.append((link.ssid, link.security))

    return NetworkFacts(
        gateway=gateway,
        router_model=router.model,
        router_firmware=router.firmware,
        router_logged_in=router.logged_in,
        router_open_ports=router_open,
        router_services=router.services or {},
        upnp_mappings=router.upnp_mappings,
        upnp_responders=responders,
        wifi_security=tuple(wifi),
        nx_hijack_ip=nx_ip,
        dhcp_dns=router.dhcp_dns,
        adblock_ip=settings.dns_host_ip or None,
        adblock_running=adblock_running,
        devices=devices,
        device_ports=device_ports,
        errors=tuple(e for e in (router.error, *(s.error for s in subs)) if e),
        sub_routers=tuple((s.name, s.host, s.open_ports, s.logged_in) for s in subs),
        sub_router_candidates=tuple((c.name, c.host, c.where, c.reachable) for c in candidates),
    )


def run_full_check(settings: Settings, router_password: str | None, store: Store,
                   adblock_running: bool | None = None) -> Report:
    facts = gather_facts(settings, router_password, store, adblock_running)
    findings = run_checks(facts)
    run_ts = utcnow()
    store.save_findings(run_ts, (FindingRecord(run_ts, f.check_id, f.severity, f.title, f.detail, f.fix)
                                 for f in findings))
    return Report(run_ts=run_ts, findings=tuple(findings), facts=facts)
