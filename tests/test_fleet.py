"""Sub-routers: detection, fingerprinting, saving, checks and the `percy routers` command."""
import pytest

from percy import cli, secrets
from percy.config import Settings, load_settings, save_settings
from percy.router import RouterDevice, RouterInfo, fleet
from percy.security import runner
from tests.test_runner_setup_cli import FakeRouter, fake_network  # noqa: F401  (fixture)


def test_detect_finds_routers_by_name_mac_and_gateway():
    devices = [("14:EB:B6:00:00:0A", "192.168.1.102", "Archer_C50"),
               ("14:eb:b6:00:00:0b", "192.168.1.100", ""),        # TP-Link OUI, no name
               ("AA:00:00:00:00:01", "192.168.1.50", "phone"),
               ("14:EB:B6:00:00:09", "192.168.1.103", "Upstairs")]  # already saved
    gateways = [("enp3s0", "192.168.1.1"), ("wlan0", "192.168.0.1"), ("wlan1", "10.10.10.1")]
    found = fleet.detect(devices, gateways, ["192.168.1.103"], "192.168.1.1",
                         reachable=lambda ip: ip == "192.168.1.100",
                         identify=lambda ip: "c50" if ip == "192.168.0.1" else None)
    assert [(c.host, c.name, c.reachable) for c in found] == [
        ("192.168.0.1", "router on wlan0", True),
        ("192.168.1.100", "TP-Link device", True),
        ("192.168.1.102", "Archer_C50", False)]  # phone, saved router, main router, hotspot skipped


def test_fingerprint_reads_public_pages_only(monkeypatch):
    pages = {}
    monkeypatch.setattr(fleet, "_post", lambda url, referer: pages.get(url.split("/", 3)[3], ""))
    monkeypatch.setattr("tplinkrouterc6u.discovery.discover_router",
                        lambda host, timeout=5: type("R", (), {"client_name": None})())
    assert fleet.fingerprint("10.0.0.1") is None
    pages["cgi/getParm"] = 'var ee="010001";\nvar nn="ab";\n$.ret=0;'
    assert fleet.fingerprint("10.0.0.1") == "c50"
    pages["cgi/getGDPRParm"] = 'var nn="ab";\nvar seq="1";'
    assert fleet.fingerprint("10.0.0.1") == "ex"


def test_unknown_family_is_refused():
    with pytest.raises(ValueError):
        fleet.factories_for("")
    assert len(fleet.factories_for("c50")) == 1 and len(fleet.factories_for("TplinkRouter")) == 1


def test_sub_routers_survive_save_and_load(tmp_path):
    path = tmp_path / "config.json"
    sub = fleet.SubRouter("192.168.0.1", "admin", "Upstairs", "c50")
    save_settings(Settings(sub_routers=(sub.to_dict(),)), path)
    loaded = load_settings(path)
    assert [fleet.SubRouter.from_dict(r) for r in loaded.sub_routers] == [sub]


class FakeSubRouter(FakeRouter):
    def devices(self):
        return [RouterDevice("BB:00:00:00:00:07", "192.168.0.100", "tablet", "2.4 GHz", True)]


def test_check_covers_reachable_and_unreachable_sub_routers(store, fake_network, monkeypatch):
    up = fleet.SubRouter("192.168.0.1", "admin", "Upstairs", "c50")
    down = fleet.SubRouter("192.168.1.102", "admin", "Archer_C50", "c50")
    ports = {"192.168.1.1": [80], "192.168.0.1": [23, 80]}
    monkeypatch.setattr(runner.scan, "scan_ports", lambda host, p, timeout=1.0, workers=32: ports.get(host, []))
    monkeypatch.setattr(runner.secrets, "get_secret", lambda name: "pw")
    monkeypatch.setattr(runner.fleet, "open_router", lambda sub, pw: FakeSubRouter())
    from percy.net.scan import Neighbor

    monkeypatch.setattr(runner.scan, "neighbors", lambda: [  # an undeclared TP-Link box, online now
        Neighbor("192.168.1.100", "14:EB:B6:00:00:0B", "enp3s0", "REACHABLE")])
    store.upsert_devices([("14:EB:B6:00:00:01", "192.168.1.99", "Archer_old", "")])  # offline: not reported
    report = runner.run_full_check(Settings(sub_routers=(up.to_dict(), down.to_dict())), "pw", store)
    ids = {f.check_id for f in report.findings}
    assert {"subrouter-telnet-192.168.0.1", "subrouter-unreachable-192.168.1.102",
            "subrouter-found-192.168.1.100"} <= ids
    assert "subrouter-unreachable-192.168.0.1" not in ids
    assert "subrouter-found-192.168.1.99" not in ids
    tablet = next(d for d in store.devices() if d.mac == "BB:00:00:00:00:07")
    assert tablet.connection.startswith("Upstairs") and "BB:00:00:00:00:07" in {d.mac for d in report.facts.devices}


def test_sub_router_wrong_password_stops_further_logins(store, fake_network, monkeypatch):
    from percy.router import RouterAuthError

    tries = []

    class Rejecting(FakeRouter):
        def __enter__(self):
            tries.append(1)
            raise RouterAuthError("wrong user or password")

    sub = fleet.SubRouter("192.168.0.1", "admin", "Upstairs", "c50")
    monkeypatch.setattr(runner.scan, "scan_ports", lambda host, p, timeout=1.0, workers=32: [80])
    monkeypatch.setattr(runner.secrets, "get_secret", lambda name: "pw")
    monkeypatch.setattr(runner.fleet, "open_router", lambda s, pw: Rejecting())
    settings = Settings(sub_routers=(sub.to_dict(),))
    runner.run_full_check(settings, "pw", store)
    second = runner.run_full_check(settings, "pw", store)
    assert len(tries) == 1 and any("stopped logging in" in f.detail for f in second.findings)


def test_cli_add_and_remove_sub_router(store, monkeypatch, capsys):
    saved, keyring = {}, {}
    monkeypatch.setattr(cli, "_store", lambda: store)
    monkeypatch.setattr(cli, "load_settings", lambda: saved.get("s", Settings()))
    monkeypatch.setattr(cli, "save_settings", lambda s: saved.__setitem__("s", s))
    monkeypatch.setattr(cli.secrets, "set_secret", keyring.__setitem__)
    monkeypatch.setattr(cli.secrets, "delete_secret", lambda k: keyring.pop(k, None))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "pw")
    monkeypatch.setattr(fleet, "fingerprint", lambda host: "c50" if host == "192.168.0.1" else None)
    monkeypatch.setattr(fleet, "open_router", lambda sub, pw: FakeSubRouter())

    assert cli.main(["routers", "add", "10.9.9.9"]) == 1  # not a known router: no password asked
    assert cli.main(["routers", "add", "192.168.0.1", "--label", "Upstairs"]) == 0
    (sub,) = [fleet.SubRouter.from_dict(r) for r in saved["s"].sub_routers]
    assert (sub.label, sub.family) == ("Upstairs", "c50") and keyring[fleet.password_key("192.168.0.1")] == "pw"
    assert cli.main(["routers", "remove", "Upstairs"]) == 0
    assert saved["s"].sub_routers == () and not keyring
    assert "Added Upstairs" in capsys.readouterr().out
