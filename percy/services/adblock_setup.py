"""One-click ad blocker: run AdGuard Home on this PC, then (after confirmation) point the router's DHCP at it."""
from __future__ import annotations

import secrets as pysecrets
import time
from typing import Callable

from percy import secrets
from percy.config import Settings, save_settings
from percy.net import dns, scan
from percy.router import ChangePlan, Router, RouterSettings
from percy.services import catalog
from percy.services.adguard import RECOMMENDED_LISTS, AdGuard, AdGuardError
from percy.services.docker import Docker, DockerError

READY_TIMEOUT_SEC = 60
TEST_AD_DOMAIN = "doubleclick.net"

Progress = Callable[[str], None]


class SetupError(RuntimeError):
    pass


def detect_lan_ip(settings: Settings) -> str:
    gateway = settings.router_host or scan.default_gateway()
    ip = scan.lan_ip_for(gateway) if gateway else None
    if not ip:
        raise SetupError("Could not work out this PC's address on your home network.")
    return ip


def _wait_ready(client: AdGuard) -> bool:
    deadline = time.monotonic() + READY_TIMEOUT_SEC
    while time.monotonic() < deadline:
        try:
            return client.needs_setup()
        except AdGuardError:
            time.sleep(2)
    raise SetupError("AdGuard Home did not start within a minute. Check `docker logs percy-adguard`.")


def install_adblock(settings: Settings, progress: Progress = lambda _m: None,
                    docker: Docker | None = None) -> Settings:
    """Install/start AdGuard Home, create its admin login (kept in the keyring), add block lists."""
    docker = docker or Docker()
    if not docker.available():
        raise SetupError("Docker is not running or you are not in the 'docker' group.")
    if not settings.dns_host_ip:
        settings = settings.with_changes(dns_host_ip=detect_lan_ip(settings))
        save_settings(settings)
    progress(f"Using this PC's address {settings.dns_host_ip} as the network's DNS")

    spec = catalog.adguard_spec(settings)
    progress(f"Downloading and starting {spec.title} ({spec.image})…")
    try:
        docker.install(spec)
    except DockerError as exc:
        raise SetupError(f"Could not start AdGuard Home: {exc}") from exc

    base = spec.web_url or f"http://127.0.0.1:{settings.adguard_web_port}"
    password = secrets.get_secret(secrets.ADGUARD_PASSWORD)
    client = AdGuard(base, settings.adguard_username, password)
    if _wait_ready(client):
        password = pysecrets.token_urlsafe(18)
        progress("Creating AdGuard Home's admin login (saved in your keyring)…")
        client.first_run_setup(settings.adguard_username, password)
        secrets.set_secret(secrets.ADGUARD_PASSWORD, password)
    elif not password:
        raise SetupError("AdGuard Home is already set up but Percy doesn't know its password. "
                         "Remove ~/.local/share/percy/adguard and run setup again.")

    for name, url in RECOMMENDED_LISTS[:2]:
        progress(f"Adding block list: {name}")
        try:
            client.add_filter(name, url)
        except AdGuardError as exc:
            progress(f"  (skipped: {exc})")

    progress(verify_blocking(settings.dns_host_ip))
    return settings


def verify_blocking(dns_ip: str) -> str:
    try:
        answer = dns.resolve_a(TEST_AD_DOMAIN, dns_ip)
    except dns.DnsError as exc:
        return (f"⚠ AdGuard is not answering DNS on {dns_ip} ({exc}). A firewall on this PC may be "
                "blocking port 53 from the LAN.")
    if answer.blocked:
        return f"✓ Ad blocking works: {TEST_AD_DOMAIN} is blocked when asked through {dns_ip}"
    return f"⚠ {TEST_AD_DOMAIN} was not blocked yet; block lists may still be downloading."


def plan_network_dns(settings: Settings, router: Router, use_adblock: bool,
                     keep_fallback: bool = True) -> list[ChangePlan]:
    """Plan the DHCP DNS change. Nothing is written until RouterSettings.apply(plan).

    Turning the ad blocker on also reserves this PC's address: if DHCP moved the PC,
    every device would be sent to a DNS server that is no longer there.
    """
    rset = RouterSettings(router)
    if not use_adblock:
        return [rset.plan_dhcp_dns([settings.router_host])]  # back to the router's own DNS relay
    if not settings.dns_host_ip:
        raise SetupError("Install the ad blocker first.")
    servers = [settings.dns_host_ip] + ([settings.fallback_dns] if keep_fallback else [])
    reservation = rset.plan_reservation(mac_for_ip(settings.dns_host_ip), settings.dns_host_ip)
    return [p for p in (reservation, rset.plan_dhcp_dns(servers)) if p is not None]


def mac_for_ip(ip: str) -> str:
    """MAC of this PC's network card that holds ``ip``."""
    from pathlib import Path

    for iface in scan.interfaces():
        if iface.ip == ip:
            return Path(f"/sys/class/net/{iface.name}/address").read_text().strip().upper()
    raise SetupError(f"This PC no longer has the address {ip}. Run `percy adblock setup` again.")
