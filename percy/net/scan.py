"""Local network facts: open TCP ports, neighbours, interfaces, Wi-Fi link, UPnP."""
from __future__ import annotations

import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

CMD_TIMEOUT_SEC = 10
# Container/VM bridges: their "neighbours" are Percy's own containers, not home devices.
VIRTUAL_IFACES = ("docker", "br-", "veth", "virbr", "vnet", "tun", "tap", "wg")
SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
).encode()


@dataclass(frozen=True)
class Neighbor:
    ip: str
    mac: str
    interface: str
    state: str


@dataclass(frozen=True)
class Interface:
    name: str
    ip: str
    prefix: int


@dataclass(frozen=True)
class WifiLink:
    ssid: str
    security: str
    channel: str
    signal: int | None


def _run(args: list[str]) -> str:
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=CMD_TIMEOUT_SEC, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout if done.returncode == 0 else ""


def tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host: str, ports: list[int], timeout: float = 1.0, workers: int = 32) -> list[int]:
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as pool:
        results = pool.map(lambda p: (p, tcp_open(host, p, timeout)), ports)
        return sorted(p for p, is_open in results if is_open)


def neighbors() -> list[Neighbor]:
    try:
        rows = json.loads(_run(["ip", "-j", "-4", "neigh", "show"]) or "[]")
    except ValueError:
        return []
    return [
        Neighbor(ip=r["dst"], mac=r["lladdr"].upper(), interface=r.get("dev", ""),
                 state=",".join(r.get("state", [])))
        for r in rows
        if r.get("lladdr") and r.get("dst") and not r.get("dev", "").startswith(VIRTUAL_IFACES)
    ]


def interfaces() -> list[Interface]:
    try:
        rows = json.loads(_run(["ip", "-j", "-4", "addr", "show", "scope", "global"]) or "[]")
    except ValueError:
        return []
    result = []
    for row in rows:
        if row.get("ifname", "").startswith(VIRTUAL_IFACES):
            continue
        for addr in row.get("addr_info", []):
            result.append(Interface(row["ifname"], addr["local"], int(addr["prefixlen"])))
    return result


def default_gateways() -> list[tuple[str, str]]:
    """(interface, gateway) for every default route, lowest metric first."""
    try:
        rows = json.loads(_run(["ip", "-j", "-4", "route", "show", "default"]) or "[]")
    except ValueError:
        return []
    rows.sort(key=lambda r: r.get("metric", 0))
    return [(r.get("dev", ""), r["gateway"]) for r in rows if r.get("gateway")]


def default_gateway() -> str | None:
    gateways = default_gateways()
    return gateways[0][1] if gateways else None


def lan_ip_for(gateway: str) -> str | None:
    """This PC's address on the gateway's subnet, preferring wired over Wi-Fi."""
    import ipaddress

    gw = ipaddress.IPv4Address(gateway)
    matches = [i for i in interfaces()
               if gw in ipaddress.IPv4Network(f"{i.ip}/{i.prefix}", strict=False)]
    matches.sort(key=lambda i: i.name.startswith(("wl", "wlan")))
    return matches[0].ip if matches else None


def parse_nmcli_wifi(output: str) -> WifiLink | None:
    for line in output.splitlines():
        parts = line.replace("\\:", "\x00").split(":")
        if len(parts) >= 5 and parts[0] == "yes":
            ssid, security, chan, signal = (p.replace("\x00", ":") for p in parts[1:5])
            return WifiLink(ssid=ssid, security=security or "open", channel=chan,
                            signal=int(signal) if signal.isdigit() else None)
    return None


def wifi_link() -> WifiLink | None:
    return parse_nmcli_wifi(_run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY,CHAN,SIGNAL", "dev", "wifi"]))


def ssdp_gateways(timeout: float = 3.0) -> list[str]:
    """Devices answering a UPnP Internet-Gateway search (i.e. UPnP port-forwarding is on)."""
    found: set[str] = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        try:
            sock.sendto(SSDP_SEARCH, SSDP_ADDR)
            while True:
                _, (addr, _) = sock.recvfrom(2048)
                found.add(addr)
        except OSError:
            pass
    return sorted(found)
