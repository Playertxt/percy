"""Security checks. Each check is a pure function of NetworkFacts -> list[Finding]."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping

HIGH, MEDIUM, LOW, INFO, OK = "high", "medium", "low", "info", "ok"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3, OK: 4}

# Ports checked on the router itself.
ROUTER_PORTS = (21, 22, 23, 80, 443, 445, 1900, 5000, 7547, 8080, 8443, 49152)
# Ports on other LAN devices that usually mean something is exposed that shouldn't be.
DEVICE_RISKY_PORTS: Mapping[int, tuple[str, str]] = {
    23: (HIGH, "Telnet (unencrypted remote shell, a favourite of IoT malware)"),
    2323: (HIGH, "Telnet on an alternate port"),
    5555: (HIGH, "Android Debug Bridge over the network (full control of the device)"),
    3389: (MEDIUM, "Windows Remote Desktop"),
    5900: (MEDIUM, "VNC remote desktop"),
    445: (LOW, "Windows file sharing (SMB)"),
    21: (LOW, "FTP file transfer (unencrypted)"),
    554: (LOW, "RTSP video stream (common on IP cameras)"),
}


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: str
    title: str
    detail: str
    fix: str = ""


@dataclass(frozen=True)
class SeenDevice:
    mac: str
    ip: str
    name: str
    trusted: bool
    first_seen_now: bool


@dataclass(frozen=True)
class NetworkFacts:
    gateway: str | None = None
    router_model: str = ""
    router_firmware: str = ""
    router_logged_in: bool = False
    router_open_ports: tuple[int, ...] = ()
    # telnet/ssh/upnp/wps/remote_ui/dmz -> True/False/None (unknown)
    router_services: Mapping[str, bool | None] = field(default_factory=dict)
    upnp_mappings: tuple[Mapping[str, object], ...] = ()
    upnp_responders: tuple[str, ...] = ()
    wifi_security: tuple[tuple[str, str], ...] = ()  # (ssid or band, security mode)
    nx_hijack_ip: str | None = None                  # what the router's DNS answered for a made-up name
    dhcp_dns: tuple[str, ...] = ()
    adblock_ip: str | None = None
    adblock_running: bool | None = None
    devices: tuple[SeenDevice, ...] = ()
    device_ports: Mapping[str, tuple[int, ...]] = field(default_factory=dict)  # ip -> open risky ports
    errors: tuple[str, ...] = ()
    # (name, host, open ports, logged in) for each saved sub-router
    sub_routers: tuple[tuple[str, str, tuple[int, ...], bool], ...] = ()
    # (name, host, how it was found, admin page reachable) for routers not added yet
    sub_router_candidates: tuple[tuple[str, str, str, bool], ...] = ()


def check_router_telnet(f: NetworkFacts) -> list[Finding]:
    if 23 not in f.router_open_ports and f.router_services.get("telnet") is not True:
        return []
    return [Finding(
        "router-telnet", HIGH, "Telnet is open on your router",
        "Port 23 answers on the router. Telnet sends logins in plain text and is the most common way "
        "malware takes over home routers.",
        "Turn Telnet off (Security page → Fix, or the router's Administration page).",
    )]


def check_router_ssh(f: NetworkFacts) -> list[Finding]:
    if 22 not in f.router_open_ports:
        return []
    return [Finding(
        "router-ssh", LOW, "SSH is open on your router",
        "Port 22 answers on the router's LAN side and only offers old key exchange. Fine if you use it; "
        "otherwise it is one more door for anything on your Wi-Fi.",
        "Turn SSH off if you don't use it.",
    )]


def check_router_extra_ports(f: NetworkFacts) -> list[Finding]:
    labels = {21: "FTP", 445: "file sharing (SMB)", 7547: "ISP remote management (TR-069)",
              8080: "alternate web admin", 8443: "alternate web admin (HTTPS)"}
    found = [f"{p} ({labels[p]})" for p in f.router_open_ports if p in labels]
    if not found:
        return []
    return [Finding(
        "router-extra-ports", INFO, "Extra services on your router",
        "Also open on the router: " + ", ".join(found) + ".",
        "Disable any you don't use (USB sharing, FTP). TR-069 belongs to your ISP and usually can't be turned off.",
    )]


def check_admin_https(f: NetworkFacts) -> list[Finding]:
    if 80 in f.router_open_ports and 443 not in f.router_open_ports:
        return [Finding(
            "router-admin-http", INFO, "Router admin page has no HTTPS",
            "The admin page is plain HTTP. The login itself is encrypted by the page's own script, "
            "but settings pages travel unencrypted on your LAN.",
            "Nothing to do on stock firmware; keep the admin password strong and unique.",
        )]
    return []


def check_services(f: NetworkFacts) -> list[Finding]:
    s = f.router_services
    out = []
    if s.get("remote_ui"):
        out.append(Finding("router-remote-admin", HIGH, "Router admin page is reachable from the internet",
                           "Remote management is on, so anyone online can try to log in to your router.",
                           "Turn remote management off unless you really need it."))
    if s.get("dmz"):
        out.append(Finding("router-dmz", HIGH, "A device is in the DMZ",
                           "DMZ forwards every incoming internet connection to one device, bypassing the firewall.",
                           "Turn DMZ off and forward only the specific ports you need."))
    if s.get("wps"):
        out.append(Finding("wifi-wps", MEDIUM, "WPS is on",
                           "WPS PIN mode can be brute-forced to recover your Wi-Fi password.",
                           "Turn WPS off; join new devices by typing the password or using a QR code."))
    return out


def check_upnp(f: NetworkFacts) -> list[Finding]:
    if not (f.router_services.get("upnp") or f.upnp_responders or f.upnp_mappings):
        return []
    detail = "UPnP lets any program on any device open ports on your router without asking."
    if f.upnp_mappings:
        rows = []
        for m in f.upnp_mappings[:10]:
            rows.append(f"{m.get('externalPort', m.get('ExternalPort', '?'))} → "
                        f"{m.get('internalClient', m.get('InternalClient', '?'))} "
                        f"({m.get('description', m.get('PortMappingDescription', '')) or 'no description'})")
        detail += " Open right now: " + "; ".join(rows) + "."
    return [Finding("router-upnp", MEDIUM if f.upnp_mappings else LOW, "UPnP port-forwarding is on", detail,
                    "Turn UPnP off unless a game console or app needs it; set manual port forwards instead.")]


def classify_wifi_security(security: str) -> str:
    """'weak-open', 'weak-tkip', 'wpa3', 'wpa2' or 'unknown'."""
    sec = security.upper()
    if not sec or sec in ("NONE", "OPEN", "--") or "WEP" in sec:
        return "weak-open"
    if "WPA3" in sec or "SAE" in sec:
        return "wpa3"
    if "TKIP" in sec and "AES" not in sec and "CCMP" not in sec:
        return "weak-tkip"
    if "WPA2" in sec or "11I" in sec or "RSN" in sec:
        return "wpa2"
    if "WPA" in sec:
        return "weak-tkip"
    return "unknown"


def check_wifi_security(f: NetworkFacts) -> list[Finding]:
    out = []
    for name, security in f.wifi_security:
        kind = classify_wifi_security(security)
        if kind == "weak-open":
            out.append(Finding("wifi-weak", HIGH, f"'{name}' is open or uses WEP",
                               "Anyone nearby can join or read the traffic.", "Switch to WPA2-PSK (AES) or WPA3."))
        elif kind == "weak-tkip":
            out.append(Finding("wifi-weak", HIGH, f"'{name}' uses old WPA/TKIP",
                               "WPA/TKIP is broken and also slows Wi-Fi down.", "Switch to WPA2-PSK with AES, or WPA3."))
        elif kind == "wpa3":
            out.append(Finding("wifi-ok", OK, f"'{name}' uses WPA3", "Current, strong Wi-Fi encryption."))
        elif kind == "wpa2":
            out.append(Finding("wifi-wpa2", INFO, f"'{name}' uses WPA2",
                               "WPA2 with a long password is fine.",
                               "If the router offers WPA2/WPA3 mixed mode and your devices cope, use it."))
    return out


def check_dns_hijack(f: NetworkFacts) -> list[Finding]:
    if not f.nx_hijack_ip:
        return []
    return [Finding("dns-hijack", MEDIUM, "Your router's DNS rewrites missing websites",
                    f"A made-up name resolved to {f.nx_hijack_ip} instead of 'not found'. Your ISP's DNS "
                    "redirects typos to its own pages, which also means it sees every lookup.",
                    "Point your devices at AdGuard Home on this PC (Ad blocker page).")]


def check_adblock_coverage(f: NetworkFacts) -> list[Finding]:
    if not f.adblock_ip:
        return []
    if f.adblock_running is False:
        return [Finding("adblock-down", HIGH if f.adblock_ip in f.dhcp_dns else LOW,
                        "AdGuard Home is not running",
                        "Devices that use it for DNS fall back to the second DNS server (no ad blocking) "
                        "or lose internet if there is no fallback.",
                        "Start it on the Agents page or run `docker start percy-adguard`.")]
    if f.dhcp_dns and f.adblock_ip not in f.dhcp_dns:
        return [Finding("adblock-not-used", INFO, "Your devices don't use the ad blocker yet",
                        f"The router hands out DNS {', '.join(f.dhcp_dns)}, not {f.adblock_ip}.",
                        "Ad blocker page → 'Use for whole network'.")]
    return []


def check_new_devices(f: NetworkFacts) -> list[Finding]:
    new = [d for d in f.devices if d.first_seen_now and not d.trusted]
    unknown = [d for d in f.devices if not d.trusted and not d.first_seen_now]
    out = []
    if new:
        names = ", ".join(f"{d.name} ({d.ip}, {d.mac})" for d in new[:8])
        out.append(Finding("device-new", MEDIUM, f"{len(new)} new device(s) joined your network",
                           f"First seen just now: {names}.",
                           "If you don't recognise one, change the Wi-Fi password and block its MAC on the router."))
    if unknown:
        out.append(Finding("device-unreviewed", INFO, f"{len(unknown)} device(s) not marked as known",
                           "Mark devices you recognise as trusted on the Devices page so new ones stand out.", ""))
    return out


def check_device_ports(f: NetworkFacts) -> list[Finding]:
    names = {d.ip: d.name for d in f.devices}
    out = []
    for ip, ports in sorted(f.device_ports.items()):
        for port in ports:
            severity, label = DEVICE_RISKY_PORTS.get(port, (LOW, f"port {port}"))
            out.append(Finding(f"device-port-{port}", severity,
                               f"{names.get(ip, ip)} has {label.split(' (')[0]} open",
                               f"{ip} answers on port {port}: {label}.",
                               "Turn the feature off in that device's settings, or update its firmware."))
    return out


def check_errors(f: NetworkFacts) -> list[Finding]:
    return [Finding("check-error", INFO, "A check could not run", e, "") for e in f.errors]


def check_sub_routers(f: NetworkFacts) -> list[Finding]:
    findings = []
    for name, host, ports, _logged_in in f.sub_routers:
        if 23 in ports:
            findings.append(Finding(
                f"subrouter-telnet-{host}", HIGH, f"Telnet is open on {name}",
                f"Port 23 answers on {name} ({host}). Telnet sends logins in plain text.",
                f"Turn Telnet off in {name}'s admin page."))
        if 80 not in ports:  # Percy's router sessions use plain HTTP
            findings.append(Finding(
                f"subrouter-unreachable-{host}", INFO, f"Can't reach {name}'s admin page",
                f"{name} ({host}) blocks its admin page from this PC, so its devices and settings weren't "
                "checked. Routers in router mode only open it on their own Wi-Fi or LAN ports.",
                f"Join {name}'s Wi-Fi (or plug into it) and run `percy routers`, or switch it to access point mode."))
    for name, host, where, reachable in f.sub_router_candidates:
        how = (f"run `percy routers add {host}`" if reachable else
               "join its Wi-Fi or plug into it, then run `percy routers` to find its own address")
        findings.append(Finding(
            f"subrouter-found-{host}", INFO, f"Found another router: {name}",
            f"{name} at {host} ({where}) isn't managed by Percy yet.", f"To manage it, {how}."))
    return findings


ALL_CHECKS: tuple[Callable[[NetworkFacts], list[Finding]], ...] = (
    check_router_telnet, check_router_ssh, check_router_extra_ports, check_admin_https, check_services,
    check_upnp, check_wifi_security, check_dns_hijack, check_adblock_coverage, check_new_devices,
    check_device_ports, check_sub_routers, check_errors,
)


def run_checks(facts: NetworkFacts) -> list[Finding]:
    findings = [finding for check in ALL_CHECKS for finding in check(facts)]
    return sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.check_id))


def score(findings: list[Finding]) -> int:
    """0-100 health score for the overview page."""
    penalty = {HIGH: 25, MEDIUM: 10, LOW: 3}
    return max(0, 100 - sum(penalty.get(x.severity, 0) for x in findings))
