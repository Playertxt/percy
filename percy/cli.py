"""`percy` command line. With no arguments it opens the desktop app."""
from __future__ import annotations

import argparse
import getpass
import json
import logging
import signal
import sys
import threading
from datetime import datetime, timedelta, timezone

from percy import __version__, secrets
from percy.config import DB_FILE, Settings, load_settings, save_settings

log = logging.getLogger("percy")
SEVERITY_MARK = {"high": "‼", "medium": "!", "low": "·", "info": "i", "ok": "✓"}


def _store():
    from percy.activity.store import Store

    return Store(DB_FILE)


def _router(settings: Settings):
    from percy.router import Router

    return Router(settings.router_host, settings.router_username, secrets.get_secret(secrets.ROUTER_PASSWORD))


def _confirm(question: str) -> bool:
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def _apply_plans(rset, plans) -> int:
    for plan in plans:
        print(f"\n{plan.title}:")
        for line in plan.describe():
            print(f"  {line}")
    if not plans or not _confirm("\nApply these changes to the router?"):
        print("Nothing changed.")
        return 1
    for plan in plans:
        if not rset.apply(plan):
            print(f"  {plan.title}: written, but the router doesn't report it back, so it couldn't be verified.")
    print("Done.")
    return 0


# -- commands ---------------------------------------------------------------
def cmd_gui(_args, _settings) -> int:
    from percy.ui.app import run

    return run()


def cmd_login(args, settings: Settings) -> int:
    from percy.router import Router

    host = _check_router_host(args.host or settings.router_host)
    user = args.username or settings.router_username
    password = getpass.getpass(f"Router admin password for {user}@{host}: ")
    with Router(host, user, password) as router:
        info = router.info()
    from percy.security.runner import clear_auth_failure

    secrets.set_secret(secrets.ROUTER_PASSWORD, password)
    save_settings(settings.with_changes(router_host=host, router_username=user))
    clear_auth_failure(_store())
    print(f"Logged in to {info.model} (firmware {info.firmware}). Password saved in your keyring.")
    return 0


def cmd_set_key(args, _settings) -> int:
    value = getpass.getpass("Anthropic API key: ")
    secrets.set_secret(secrets.ANTHROPIC_KEY, value.strip())
    print("Saved in your keyring.")
    return 0


def _sub_router(settings: Settings, host: str):
    from percy.router import fleet

    for raw in settings.sub_routers:
        sub = fleet.SubRouter.from_dict(raw)
        if host in (sub.host, sub.label):
            return fleet.open_router(sub, secrets.get_secret(fleet.password_key(sub.host)))
    raise ValueError(f"No saved router '{host}'. See `percy routers`.")


def cmd_router_info(args, settings: Settings) -> int:
    with (_sub_router(settings, args.router) if args.router else _router(settings)) as router:
        info = router.info()
        devices = router.devices()
    print(json.dumps(info.__dict__, indent=2))
    print(f"\n{len(devices)} devices:")
    for d in devices:
        print(f"  {'●' if d.active else '○'} {d.ip:15} {d.mac:17} {d.connection:14} {d.hostname}")
    return 0


def cmd_routers(args, settings: Settings) -> int:
    from percy.router import fleet
    from percy.security.runner import find_candidates

    subs = [fleet.SubRouter.from_dict(r) for r in settings.sub_routers]
    if args.action == "remove":
        keep = tuple(s.to_dict() for s in subs if args.host not in (s.host, s.label))
        if len(keep) == len(subs):
            print(f"No saved router '{args.host}'.")
            return 1
        removed = next(s for s in subs if args.host in (s.host, s.label))
        save_settings(settings.with_changes(sub_routers=keep))
        secrets.delete_secret(fleet.password_key(removed.host))
        print(f"Removed {removed.name}.")
        return 0
    if args.action == "add":
        return _add_sub_router(args, settings, subs)
    from percy.net import scan

    print(f"Main router: {settings.router_host}")
    for s in subs:
        state = "admin page reachable" if scan.tcp_open(s.host, fleet.ADMIN_PORT) else "admin page NOT reachable from here"
        print(f"  saved: {s.name:20} {s.host:15} {s.family:8} {state}")
    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    recent = [(d.mac, d.ip, d.hostname) for d in _store().devices() if d.last_seen >= day_ago]
    found = find_candidates(settings, recent, settings.router_host)
    if not found:
        print("No other routers found. Run `percy check` first so Percy knows the devices on your network.")
    for c in found:
        hint = f"add with: percy routers add {c.host}" if c.reachable else "admin page closed from here (router mode)"
        print(f"  found: {c.name:20} {c.host:15} {c.where}; {hint}")
    return 0


def _add_sub_router(args, settings: Settings, subs) -> int:
    from percy.router import fleet

    if not args.host:
        print("Give the router's address: percy routers add <address>")
        return 1
    args.host = _check_router_host(args.host)
    family = fleet.fingerprint(args.host)
    if family is None:
        print(f"{args.host} didn't answer like a TP-Link router Percy knows. If it's in router mode, join its "
              "Wi-Fi (or plug into it) and use the address `percy routers` shows.")
        return 1
    sub = fleet.SubRouter(args.host, args.username or "admin", args.label or "", family)
    password = getpass.getpass(f"Admin password for {sub.username}@{sub.host}: ")
    with fleet.open_router(sub, password) as router:
        info = router.info()
        count = len(router.devices())
    name = sub.label or info.model or sub.host
    saved = fleet.SubRouter(sub.host, sub.username, name, family)
    others = tuple(s.to_dict() for s in subs if s.host != sub.host)
    secrets.set_secret(fleet.password_key(sub.host), password)
    save_settings(settings.with_changes(sub_routers=others + (saved.to_dict(),)))
    _store().set_meta(fleet.auth_failed_key(sub.host), "")
    print(f"Added {name} ({info.model}, firmware {info.firmware}) with {count} devices. Password saved in your keyring.")
    return 0


def cmd_router_probe(_args, settings: Settings) -> int:
    from percy.router import RouterSettings

    with _router(settings) as router:
        print(json.dumps(RouterSettings(router).probe(), indent=2, ensure_ascii=False))
    return 0


def cmd_wifi(args, settings: Settings) -> int:
    from percy.router import RouterSettings

    with _router(settings) as router:
        rset = RouterSettings(router)
        nets = rset.wifi_networks()
        if not args.set_ssid and not args.set_password:
            for i, n in enumerate(nets):
                print(f"[{i}] {n.band:10} {n.ssid!r:28} security={n.security} enabled={n.enabled}")
            return 0
        if not 0 <= args.index < len(nets):
            print(f"No Wi-Fi network number {args.index}; run `percy wifi` to list them.")
            return 1
        net = nets[args.index]
        password = getpass.getpass("New Wi-Fi password: ") if args.set_password else None
        return _apply_plans(rset, rset.plan_wifi(net, ssid=args.set_ssid, password=password))


def cmd_service(args, settings: Settings) -> int:
    from percy.router import RouterSettings
    from percy.router import settings as rs

    oids = {"telnet": rs.TELNET, "ssh": rs.SSH, "upnp": rs.UPNP, "wps": rs.WPS, "remote-admin": rs.REMOTE_UI}
    with _router(settings) as router:
        rset = RouterSettings(router)
        plans = rset.plan_service(oids[args.name], args.state == "on", f"{args.name} on the router")
        if not plans:
            print(f"{args.name} is already {args.state}.")
            return 0
        return _apply_plans(rset, plans)


def cmd_check(args, settings: Settings) -> int:
    from percy.monitor.daemon import Monitor

    store = _store()
    findings = Monitor(settings, store, alerts=False).tick_check()
    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
        return 0
    for f in findings:
        print(f"{SEVERITY_MARK.get(f.severity, '?')} [{f.severity:6}] {f.title}\n           {f.detail}")
        if f.fix:
            print(f"           Fix: {f.fix}")
    return 0


def cmd_summary(args, settings: Settings) -> int:
    from percy.agents.summary import summarize
    from percy.security.checks import Finding

    store = _store()
    findings = [Finding(r.check_id, r.severity, r.title, r.detail, r.fix) for r in store.latest_findings()]
    if not findings:
        print("No check results yet. Run `percy check` first.")
        return 1
    usage = None
    if args.with_activity:
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        usage = store.usage_for(since=since, limit=40)
    context = {"router": "TP-Link XC220-G3v", "devices_known": len(store.devices())}
    print(summarize(findings, context, secrets.get_secret(secrets.ANTHROPIC_KEY), settings.claude_model, usage))
    return 0


def cmd_adblock(args, settings: Settings) -> int:
    from percy.router import RouterSettings
    from percy.services import adblock_setup

    if args.action == "setup":
        adblock_setup.install_adblock(settings, progress=print)
        print("\nNext: `percy adblock use-for-network` to protect every device.")
        return 0
    if args.action == "status":
        from percy.monitor.daemon import adguard_client

        client = adguard_client(settings)
        if client is None:
            print("Ad blocker not set up. Run `percy adblock setup`.")
            return 1
        st, stats = client.status(), client.stats()
        print(f"AdGuard Home {st.version}: {'protecting' if st.protection_enabled else 'PAUSED'}")
        print(f"Queries: {stats.get('num_dns_queries', 0)}  blocked: {stats.get('num_blocked_filtering', 0)}")
        print(adblock_setup.verify_blocking(settings.dns_host_ip))
        return 0
    with _router(settings) as router:
        plans = adblock_setup.plan_network_dns(settings, router, use_adblock=args.action == "use-for-network",
                                               keep_fallback=not args.no_fallback)
        return _apply_plans(RouterSettings(router), plans)


class DeviceLookupError(ValueError):
    pass


def _resolve_device(store, query: str):
    """Exact MAC/IP/name match first, then a name substring that matches exactly one device."""
    q = query.strip().lower()
    if not q:
        raise DeviceLookupError("Say which device (name, IP or MAC).")
    devices = store.devices()
    exact = [d for d in devices if q in (d.mac.lower(), d.ip, d.display_name.lower())]
    if len(exact) == 1:
        return exact[0]
    partial = exact or [d for d in devices if q in d.display_name.lower()]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        known = ", ".join(d.display_name for d in devices) or "none yet"
        raise DeviceLookupError(f"No device matches '{query}'. Known: {known}")
    raise DeviceLookupError(f"'{query}' matches several devices: " + ", ".join(
        f"{d.display_name} ({d.ip})" for d in partial) + ". Use the IP or MAC.")


def cmd_activity(args, _settings) -> int:
    store = _store()
    since = (datetime.now(timezone.utc) - timedelta(hours=args.hours)).replace(microsecond=0).isoformat()
    try:
        device = _resolve_device(store, args.device) if args.device else None
    except DeviceLookupError as exc:
        print(exc)
        return 1
    mac = device.mac if device else None
    who = device.display_name if device else "whole network"
    if args.apps:
        print(f"Apps and sites, {who}, last {args.hours} h:")
        for u in store.usage_for(mac=mac, since=since):
            print(f"  {u.name:28} {u.category:14} {u.queries:6} lookups  {u.blocked:5} blocked  last {u.last_ts}")
        return 0
    names = {d.mac: d.display_name for d in store.devices()}
    for r in store.dns_for(mac=mac, since=since, search=args.search, limit=args.limit):
        local = datetime.fromisoformat(r.ts).astimezone().strftime("%d %b %H:%M:%S")
        print(f"{local}  {names.get(r.device_mac or '', r.client_ip):22.22} {'BLOCKED ' if r.blocked else ''}"
              f"{r.domain}  {('[' + r.app + ']') if r.app else ''}")
    return 0


def cmd_devices(args, _settings) -> int:
    store = _store()
    if args.trust or args.label:
        try:
            device = _resolve_device(store, args.target or "")
        except DeviceLookupError as exc:
            print(exc)
            return 1
        if args.trust:
            store.set_device_trusted(device.mac, True)
        if args.label:
            store.set_device_label(device.mac, args.label)
        print("Saved.")
        return 0
    for d in store.devices():
        print(f"{'✓' if d.trusted else '?'} {d.display_name:24.24} {d.ip:15} {d.mac}  {d.connection:12} last {d.last_seen}")
    return 0


def cmd_monitor(args, settings: Settings) -> int:
    from percy.monitor.daemon import Monitor

    monitor = Monitor(settings, _store())
    if args.once:
        monitor.step()
        return 0
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("Percy monitor running (checks every %d min)", settings.check_interval_min)
    monitor.run_forever(stop)
    return 0


def cmd_service_install(args, _settings) -> int:
    from percy.monitor import systemd

    if args.remove:
        systemd.uninstall()
        print("Background monitor removed.")
    else:
        systemd.install()
        print("Background monitor installed and started (systemctl --user status percy-monitor).")
    return 0


def cmd_agents(args, settings: Settings) -> int:
    from percy.services import catalog
    from percy.services.docker import Docker

    docker = Docker()
    specs = {s.key: s for s in catalog.all_specs(settings)}
    if args.install:
        spec = specs[args.install]
        print(f"Installing {spec.title} ({spec.image})…")
        docker.install(spec)
        print(f"Running. Dashboard: {spec.web_url}")
        return 0
    for spec in specs.values():
        print(f"{spec.title:14} {docker.state(spec.name):10} {spec.image}\n    {spec.description}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="percy", description="Router, Wi-Fi, ad blocking and network security.")
    p.add_argument("--version", action="version", version=f"percy {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("gui", help="open the desktop app (default)").set_defaults(func=cmd_gui)
    s = sub.add_parser("login", help="save and test the router admin password")
    s.add_argument("--host")
    s.add_argument("--username")
    s.set_defaults(func=cmd_login)
    sub.add_parser("set-key", help="save an Anthropic API key for Claude summaries").set_defaults(func=cmd_set_key)
    s = sub.add_parser("router-info", help="router status and connected devices")
    s.add_argument("--router", help="a saved sub-router (address or name) instead of the main router")
    s.set_defaults(func=cmd_router_info)
    s = sub.add_parser("routers", help="list, find, add or remove the other routers in your home")
    s.add_argument("action", nargs="?", choices=["list", "add", "remove"], default="list")
    s.add_argument("host", nargs="?")
    s.add_argument("--username", help="admin username (default admin)")
    s.add_argument("--label", help="a name for it, e.g. 'Upstairs'")
    s.set_defaults(func=cmd_routers)
    sub.add_parser("router-probe", help="dump what the router exposes (passwords masked)").set_defaults(
        func=cmd_router_probe)
    s = sub.add_parser("wifi", help="show or change Wi-Fi name/password")
    s.add_argument("--index", type=int, default=0)
    s.add_argument("--set-ssid")
    s.add_argument("--set-password", action="store_true")
    s.set_defaults(func=cmd_wifi)
    s = sub.add_parser("service", help="turn a router service on/off")
    s.add_argument("name", choices=["telnet", "ssh", "upnp", "wps", "remote-admin"])
    s.add_argument("state", choices=["on", "off"])
    s.set_defaults(func=cmd_service)
    s = sub.add_parser("check", help="run all security checks now")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_check)
    s = sub.add_parser("summary", help="Claude explains the latest check results")
    s.add_argument("--with-activity", action="store_true", help="also send 24 h app totals (no device names)")
    s.set_defaults(func=cmd_summary)
    s = sub.add_parser("adblock", help="network-wide ad blocker (AdGuard Home)")
    s.add_argument("action", choices=["setup", "status", "use-for-network", "off-for-network"])
    s.add_argument("--no-fallback", action="store_true", help="don't hand out a backup DNS server")
    s.set_defaults(func=cmd_adblock)
    s = sub.add_parser("activity", help="what each device looked up")
    s.add_argument("--device", help="name, IP or MAC")
    s.add_argument("--hours", type=int, default=24)
    s.add_argument("--search")
    s.add_argument("--apps", action="store_true", help="totals per app/site instead of every lookup")
    s.add_argument("--limit", type=int, default=200)
    s.set_defaults(func=cmd_activity)
    s = sub.add_parser("devices", help="list devices, or mark one as trusted / give it a name")
    s.add_argument("target", nargs="?")
    s.add_argument("--trust", action="store_true")
    s.add_argument("--label")
    s.set_defaults(func=cmd_devices)
    s = sub.add_parser("monitor", help="run the always-on monitor in the foreground")
    s.add_argument("--once", action="store_true")
    s.set_defaults(func=cmd_monitor)
    s = sub.add_parser("install-service", help="run the monitor in the background at login (systemd --user)")
    s.add_argument("--remove", action="store_true")
    s.set_defaults(func=cmd_service_install)
    s = sub.add_parser("agents", help="list or install the open-source monitors (NetAlertX, AdGuard Home)")
    s.add_argument("--install", choices=["adguard", "netalertx"])
    s.set_defaults(func=cmd_agents)
    return p


def main(argv: list[str] | None = None) -> int:
    from percy.safe_text import SafeStream

    # Device names, SSIDs and domains come from the LAN; strip terminal escape codes from everything printed.
    real_out, real_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = SafeStream(real_out), SafeStream(real_err)
    try:
        return _main(argv)
    finally:
        sys.stdout, sys.stderr = real_out, real_err


def _check_router_host(host: str) -> str:
    """The router password is sent to this address, so only accept a private LAN IPv4."""
    from percy.services.catalog import validate_lan_ip

    try:
        return validate_lan_ip(host)
    except ValueError as exc:
        raise ValueError(f"Router address must be a private LAN IPv4 like 192.168.1.1 ({exc})") from exc


def _main(argv: list[str] | None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        settings = load_settings()
        return (args.func if args.cmd else cmd_gui)(args, settings)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # show a clean message instead of a traceback
        if args.verbose:
            raise
        print(f"percy: {exc}", file=sys.stderr)
        return 1
