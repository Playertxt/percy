"""The open-source tools Percy installs and runs for you, with pinned versions."""
from __future__ import annotations

import ipaddress

from percy.config import ADGUARD_IMAGE, DATA_DIR, NETALERTX_IMAGE, Settings
from percy.services.docker import ContainerSpec

ADGUARD = "adguard"
NETALERTX = "netalertx"
NETALERTX_PORT = 20211


def validate_lan_ip(value: str) -> str:
    """DNS must only be published on a private LAN address, never 0.0.0.0 or a public IP."""
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid IPv4 address") from exc
    if not ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
        raise ValueError(f"{ip} is not a private LAN address; refusing to publish DNS on it")
    return str(ip)


def adguard_spec(settings: Settings) -> ContainerSpec:
    if not settings.dns_host_ip:
        raise ValueError("Set this PC's LAN address (Settings → DNS address) before installing AdGuard Home")
    base = DATA_DIR / "adguard"
    lan = validate_lan_ip(settings.dns_host_ip)
    return ContainerSpec(
        key=ADGUARD,
        name="percy-adguard",
        image=ADGUARD_IMAGE,
        title="AdGuard Home",
        description=("Network-wide ad and tracker blocker. Every device that uses it as DNS gets "
                     "ads blocked, and its query log is what fills Percy's per-device activity log."),
        # DNS only on the LAN address (systemd-resolved keeps 127.0.0.53);
        # the admin UI only on localhost, so other devices can't reach it.
        run_args=(
            "-v", f"{base / 'work'}:/opt/adguardhome/work",
            "-v", f"{base / 'conf'}:/opt/adguardhome/conf",
            "-p", f"{lan}:53:53/tcp",
            "-p", f"{lan}:53:53/udp",
            "-p", f"127.0.0.1:{settings.adguard_web_port}:3000/tcp",
        ),
        web_url=f"http://127.0.0.1:{settings.adguard_web_port}",
        data_dirs=(str(base / "work"), str(base / "conf")),
    )


def netalertx_spec() -> ContainerSpec:
    base = DATA_DIR / "netalertx"
    return ContainerSpec(
        key=NETALERTX,
        name="percy-netalertx",
        image=NETALERTX_IMAGE,
        title="NetAlertX",
        description=("Always-on network scanner (open source). Alerts when a new or unknown device "
                     "joins, when a device drops off, or when an IP changes. Its dashboard (port 20211) "
                     "is reachable from your whole LAN because it needs host networking to scan: set a "
                     "password in its Settings after installing."),
        run_args=(
            "--network=host",
            "--cap-add=NET_RAW", "--cap-add=NET_ADMIN", "--cap-add=NET_BIND_SERVICE",
            "-v", f"{base}:/data",
            "-v", "/etc/localtime:/etc/localtime:ro",
            "--tmpfs", "/tmp:uid=20211,gid=20211,mode=1700",
            "-e", f"PORT={NETALERTX_PORT}",
            "-e", 'APP_CONF_OVERRIDE={"GRAPHQL_PORT":"20214"}',
        ),
        web_url=f"http://127.0.0.1:{NETALERTX_PORT}",
        data_dirs=(str(base),),
    )


def all_specs(settings: Settings) -> list[ContainerSpec]:
    specs = [netalertx_spec()]
    try:
        specs.insert(0, adguard_spec(settings))
    except ValueError:
        pass
    return specs
