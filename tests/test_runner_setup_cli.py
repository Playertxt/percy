"""Security runner, ad-blocker setup and CLI, with network/docker/router faked."""
from types import SimpleNamespace

import pytest

from percy import cli, secrets
from percy.config import Settings
from percy.monitor import systemd
from percy.net.dns import DnsAnswer, DnsError
from percy.net.scan import Neighbor, WifiLink
from percy.router import RouterDevice, RouterInfo
from percy.router import settings as rs
from percy.security import runner
from percy.services import adblock_setup


class FakeRouter:
    objects = {rs.TELNET: [{"stack": "0,0,0,0,0,0", "enable": "1"}],
               rs.UPNP: [{"stack": "0,0,0,0,0,0", "enable": "0"}],
               rs.DHCP_POOL: [{"stack": "1,0,0,0,0,0", "DNSServers": "192.168.1.1"}],
               rs.WIFI_SSID: [{"stack": "1,0,0,0,0,0", "SSID": "Home", "ModeEnabled": "WPA2-Personal"}]}

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def info(self):
        return RouterInfo("XC220-G3v", "1.0", "v1", "192.168.1.1", "100.64.0.2", 5.0, 40.0, True, True, False, False)

    def devices(self):
        return [RouterDevice("AA:00:00:00:00:01", "192.168.1.50", "phone", "5 GHz", True),
                RouterDevice("AA:00:00:00:00:02", "192.168.1.51", "old-tv", "wired", False)]

    def read(self, oid, **_k):
        return [dict(r) for r in self.objects.get(oid, [])]

    def write(self, oid, stack, changes):
        self.objects[oid][0].update(changes)


@pytest.fixture
def fake_network(monkeypatch):
    monkeypatch.setattr(runner, "Router", FakeRouter)
    monkeypatch.setattr(runner.scan, "neighbors", lambda: [Neighbor("192.168.1.60", "AA:00:00:00:00:03", "enp3s0", "REACHABLE")])
    monkeypatch.setattr(runner.scan, "ssdp_gateways", lambda timeout=3.0: [])
    monkeypatch.setattr(runner.scan, "wifi_link", lambda: WifiLink("Home", "WPA2", "157", 80))
    ports = {"192.168.1.1": [22, 23, 53, 80], "192.168.1.60": [5555]}
    monkeypatch.setattr(runner.scan, "scan_ports", lambda host, p, timeout=1.0, workers=32: ports.get(host, []))
    monkeypatch.setattr(runner.dns, "resolve_a", lambda name, server, timeout=3.0: DnsAnswer(3, ()))
    monkeypatch.setattr(runner.scan, "default_gateways", lambda: [])
    monkeypatch.setattr(runner.scan, "tcp_open", lambda host, port, timeout=1.0: False)


def test_first_check_is_a_baseline(store, fake_network):
    report = runner.run_full_check(Settings(), "pw", store)
    assert "device-new" not in {f.check_id for f in report.findings}
    assert any(kind == "baseline" for _t, kind, _m in store.events())


def test_full_check_combines_router_lan_and_scan(store, fake_network):
    store.upsert_devices([("AA:00:00:00:00:09", "192.168.1.50", "stale-old-owner-of-.50", "")])
    report = runner.run_full_check(Settings(), "pw", store, adblock_running=None)
    ids = {f.check_id for f in report.findings}
    assert {"router-telnet", "router-ssh", "device-port-5555", "device-new", "wifi-wpa2"} <= ids
    assert "dns-hijack" not in ids  # NXDOMAIN came back correctly
    assert report.facts.router_services["telnet"] is True and report.facts.router_services["upnp"] is False
    assert {d.mac for d in store.devices()} >= {"AA:00:00:00:00:01", "AA:00:00:00:00:03"}
    assert "AA:00:00:00:00:02" not in {d.mac for d in store.devices()}  # inactive router entry skipped
    live = {d.mac for d in report.facts.devices}
    assert live == {"AA:00:00:00:00:01", "AA:00:00:00:00:03"}  # stale row with a reused IP is not "live"
    assert store.latest_findings()


def test_disabled_wifi_network_is_not_flagged(store, fake_network, monkeypatch):
    objects = dict(FakeRouter.objects)
    objects[rs.WIFI_SSID] = [{"stack": "1,0,0,0,0,0", "SSID": "Guest", "enable": "0", "ModeEnabled": "None"}]
    monkeypatch.setattr(FakeRouter, "objects", objects)
    report = runner.run_full_check(Settings(), "pw", store)
    assert "wifi-weak" not in {f.check_id for f in report.findings}


def test_check_without_password_still_scans(store, fake_network):
    report = runner.run_full_check(Settings(), None, store)
    ids = {f.check_id for f in report.findings}
    assert "check-error" in ids and "router-telnet" in ids


def test_nx_hijack_reports_rewritten_answer(monkeypatch):
    monkeypatch.setattr(runner.dns, "resolve_a", lambda *a, **k: DnsAnswer(0, ("49.44.1.1",)))
    assert runner.nx_hijack("192.168.1.1") == "49.44.1.1"
    def broken(*a, **k):
        raise DnsError("timeout")
    monkeypatch.setattr(runner.dns, "resolve_a", broken)
    assert runner.nx_hijack("192.168.1.1") is None


class FakeDocker:
    def __init__(self, available=True):
        self.installed = []
        self._available = available

    def available(self):
        return self._available

    def install(self, spec):
        self.installed.append(spec)


class FakeAdGuardForSetup:
    instances = []

    def __init__(self, base, user, password):
        self.password = password
        self.filters = []
        self.configured = None
        FakeAdGuardForSetup.instances.append(self)

    def needs_setup(self):
        return True

    def first_run_setup(self, user, password):
        self.configured = (user, password)

    def add_filter(self, name, url):
        self.filters.append(url)


def test_install_adblock_creates_login_and_lists(monkeypatch):
    saved = {}
    monkeypatch.setattr(adblock_setup, "AdGuard", FakeAdGuardForSetup)
    monkeypatch.setattr(adblock_setup.secrets, "get_secret", lambda name: None)
    monkeypatch.setattr(adblock_setup.secrets, "set_secret", lambda name, value: saved.__setitem__(name, value))
    monkeypatch.setattr(adblock_setup, "save_settings", lambda s: saved.__setitem__("settings", s))
    monkeypatch.setattr(adblock_setup, "detect_lan_ip", lambda s: "192.168.1.104")
    monkeypatch.setattr(adblock_setup.dns, "resolve_a", lambda *a, **k: DnsAnswer(0, ("0.0.0.0",)))
    docker, messages = FakeDocker(), []
    result = adblock_setup.install_adblock(Settings(), messages.append, docker)
    assert result.dns_host_ip == "192.168.1.104" and saved["settings"].dns_host_ip == "192.168.1.104"
    client = FakeAdGuardForSetup.instances[-1]
    assert client.configured[1] == saved[secrets.ADGUARD_PASSWORD] and len(client.configured[1]) >= 20
    assert len(client.filters) == 2 and docker.installed[0].name == "percy-adguard"
    assert messages[-1].startswith("✓")


def test_install_adblock_needs_docker():
    with pytest.raises(adblock_setup.SetupError, match="Docker"):
        adblock_setup.install_adblock(Settings(dns_host_ip="192.168.1.104"), docker=FakeDocker(available=False))


def test_verify_blocking_messages(monkeypatch):
    monkeypatch.setattr(adblock_setup.dns, "resolve_a", lambda *a, **k: DnsAnswer(0, ("142.250.1.1",)))
    assert adblock_setup.verify_blocking("192.168.1.104").startswith("⚠")


def test_plan_network_dns_reserves_this_pc_then_sets_dns(monkeypatch):
    monkeypatch.setattr(adblock_setup, "mac_for_ip", lambda ip: "02:00:00:00:00:AA")
    router = FakeRouter()
    s = Settings(dns_host_ip="192.168.1.104")
    reserve, dns_plan = adblock_setup.plan_network_dns(s, router, True)
    assert reserve.adds and reserve.oid == rs.DHCP_RESERVATION and reserve.stack == "1,0,0,0,0,0"
    assert reserve.changes == {"chaddr": "02:00:00:00:00:AA", "yiaddr": "192.168.1.104", "enable": "1"}
    assert dns_plan.changes == {"DNSServers": "192.168.1.104,1.1.1.1"}
    assert adblock_setup.plan_network_dns(s, router, True, keep_fallback=False)[-1].changes == {
        "DNSServers": "192.168.1.104"}
    (off,) = adblock_setup.plan_network_dns(s, router, False)
    assert off.changes == {"DNSServers": "192.168.1.1"}
    with pytest.raises(adblock_setup.SetupError):
        adblock_setup.plan_network_dns(Settings(), router, True)


def test_systemd_unit_quotes_paths_with_spaces_and_percent():
    text = systemd.unit_text("/home/me/my projects/percy/.venv/bin/python")
    assert 'ExecStart="/home/me/my projects/percy/.venv/bin/python" -m percy monitor' in text
    assert 'ExecStart="/opt/100%/python"' in systemd.unit_text("/opt/100%/python").replace("%%", "%")
    assert "%%" in systemd.unit_text("/opt/100%/python")
    with pytest.raises(ValueError):
        systemd.unit_text("/bad\npath")


def test_router_lockout_guard(store, fake_network, monkeypatch):
    from percy.router import RouterAuthError

    attempts = []

    class Rejecting(FakeRouter):
        def __enter__(self):
            attempts.append(1)
            raise RouterAuthError("wrong user or password")

    monkeypatch.setattr(runner, "Router", Rejecting)
    runner.run_full_check(Settings(), "old-pw", store)
    second = runner.run_full_check(Settings(), "old-pw", store)
    assert len(attempts) == 1  # the second check did not try to log in again
    assert any("stopped logging in" in f.detail for f in second.findings)
    runner.clear_auth_failure(store)
    runner.run_full_check(Settings(), "new-pw", store)
    assert len(attempts) == 2


def test_lan_ip_validation():
    from percy.services.catalog import validate_lan_ip

    assert validate_lan_ip(" 192.168.1.104 ") == "192.168.1.104"
    for bad in ("0.0.0.0", "8.8.8.8", "127.0.0.1", "169.254.1.1", "nope"):
        with pytest.raises(ValueError):
            validate_lan_ip(bad)


def test_private_files(tmp_path):
    import stat

    from percy.activity.store import Store
    from percy.config import save_settings

    db = tmp_path / "data" / "percy.db"
    Store(db).close()
    save_settings(Settings(), tmp_path / "cfg" / "config.json")
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "cfg" / "config.json").stat().st_mode) == 0o600
    assert not list((tmp_path / "cfg").glob("*.tmp"))


def test_cli_parser_knows_every_command():
    parser = cli.build_parser()
    for argv in (["check"], ["activity", "--apps"], ["adblock", "use-for-network", "--no-fallback"],
                 ["service", "telnet", "off"], ["wifi", "--set-ssid", "x"], ["agents", "--install", "netalertx"]):
        assert parser.parse_args(argv).func


def test_cli_devices_and_activity(store, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_store", lambda: store)
    store.upsert_devices([("AA:00:00:00:00:01", "192.168.1.50", "phone", "5 GHz")])
    from percy.activity.store import DnsRecord, utcnow
    store.add_dns([DnsRecord(utcnow(), "192.168.1.50", "AA:00:00:00:00:01", "youtube.com", "YouTube", "Video",
                             False, "A")])
    assert cli.main(["devices", "--trust"]) == 1  # no target: must not pick a device at random
    assert not store.devices()[0].trusted
    assert cli.main(["devices", "phone", "--trust", "--label", "Mum's phone"]) == 0
    assert cli.main(["activity", "--device", "Mum", "--apps"]) == 0
    assert cli.main(["activity", "--device", "nobody"]) == 1
    store.upsert_devices([("AA:00:00:00:00:02", "192.168.1.51", "Mum's laptop", "")])
    assert cli.main(["activity", "--device", "Mum"]) == 1  # ambiguous
    assert cli.main(["activity", "--device", "192.168.1.51"]) == 0  # exact IP is fine
    out = capsys.readouterr().out
    assert "YouTube" in out and "No device matches" in out and "matches several" in out
    assert next(d for d in store.devices() if d.mac == "AA:00:00:00:00:01").trusted


def test_cli_reports_errors_cleanly(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_settings", lambda: (_ for _ in ()).throw(ValueError("bad config")))
    assert cli.main(["check"]) == 1
    assert "bad config" in capsys.readouterr().err
