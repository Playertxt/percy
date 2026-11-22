import pytest

from percy.router import Router, RouterAuthError, RouterError, RouterSettings
from percy.router.client import format_field
from percy.router import settings as rs
from tests.conftest import FakeLibClient


def make_router(objects=None, fail_first=None, clients=None):
    made = clients if clients is not None else []

    def factory_ok(host, user, pwd, timeout):
        c = FakeLibClient(objects)
        made.append(c)
        return c

    factories = [factory_ok]
    if fail_first:
        factories.insert(0, lambda *a: made.append(FakeLibClient(fail_login=fail_first)) or made[-1])
    return Router("192.168.1.1", "admin", "pw", factories=factories), made


def test_wrong_password_stops_without_trying_other_variants():
    made = []
    router, _ = make_router(fail_first="TplinkRouter - EX - Login failed, wrong user or password.", clients=made)
    with pytest.raises(RouterAuthError):
        router.connect()
    assert len(made) == 1  # the second login variant was never tried


def test_falls_back_to_next_cipher_variant_on_other_errors():
    router, made = make_router({"X": [{"a": "1"}]}, fail_first="Unknown error rsa_key")
    with router:
        assert router.read("X") == [{"a": "1"}]
    assert len(made) == 2 and made[1].logged_out


def test_empty_password_is_rejected_before_any_request():
    with pytest.raises(RouterAuthError):
        Router("192.168.1.1", "admin", "")


def test_format_field_escapes_quotes_and_backslashes():
    assert format_field("SSID", 'my "net"\\') == '"SSID":"my \\"net\\"\\\\"'


def test_read_before_connect_raises():
    router, _ = make_router()
    with pytest.raises(RouterError):
        router.read("X")


def objects():
    return {
        rs.DHCP_POOL: [{"stack": "1,0,0,0,0,0", "DNSServers": "192.168.1.1"}],
        rs.TELNET: [{"stack": "0,0,0,0,0,0", "enable": "1", "password": "secret"}],
        rs.WIFI_SSID: [{"stack": "1,0,0,0,0,0", "SSID": "Home", "enable": "1"},
                       {"stack": "2,0,0,0,0,0", "SSID": "Home_5G", "enable": "1"}],
        rs.WIFI_AP: [{"stack": "1,0,0,0,0,0", "KeyPassphrase": "old-pass-123", "ModeEnabled": "WPA2-Personal"},
                     {"stack": "2,0,0,0,0,0", "KeyPassphrase": "old-pass-123", "ModeEnabled": "WPA2-Personal"}],
    }


def test_plan_and_apply_dhcp_dns_round_trip():
    router, made = make_router(objects())
    with router:
        rset = RouterSettings(router)
        plan = rset.plan_dhcp_dns(["192.168.1.104", "1.1.1.1"])
        assert plan.changes == {"DNSServers": "192.168.1.104,1.1.1.1"}
        assert plan.before == {"DNSServers": "192.168.1.1"}
        rset.apply(plan)
        assert rset.dhcp_dns() == ["192.168.1.104", "1.1.1.1"]


def test_plan_dhcp_dns_rejects_bad_ip():
    router, _ = make_router(objects())
    with router, pytest.raises(ValueError):
        RouterSettings(router).plan_dhcp_dns(["192.168.1.999"])


def test_apply_detects_router_ignoring_change():
    class Stubborn(FakeLibClient):
        def req_act(self, acts):
            if acts[0].type == "so":
                return "", [None]
            return super().req_act(acts)

    router = Router("h", "admin", "pw", factories=[lambda *a: Stubborn(objects())])
    with router:
        rset = RouterSettings(router)
        with pytest.raises(RouterError):
            rset.apply(rset.plan_service(rs.TELNET, False, "Telnet")[0])


def test_service_enabled_and_plan_off():
    router, _ = make_router(objects())
    with router:
        rset = RouterSettings(router)
        assert rset.service_enabled(rs.TELNET) is True
        plan, = rset.plan_service(rs.TELNET, False, "Telnet")
        assert plan.changes == {"enable": "0"}
        rset.apply(plan)
        assert rset.service_enabled(rs.TELNET) is False
        assert rset.service_enabled(rs.UPNP) is None  # object missing -> unknown


def test_wifi_networks_find_password_on_access_point():
    router, _ = make_router(objects())
    with router:
        nets = RouterSettings(router).wifi_networks()
    assert [n.ssid for n in nets] == ["Home", "Home_5G"]
    assert nets[1].password_oid == rs.WIFI_AP and nets[1].password_stack == "2,0,0,0,0,0"
    assert nets[0].security == "WPA2-Personal" or nets[0].security is None


def test_wifi_password_follows_ssid_reference_not_position():
    objs = objects()
    # APs listed in a different order than SSIDs, linked by reference (TR-181 style)
    objs[rs.WIFI_AP] = [{"stack": "1,0,0,0,0,0", "SSIDReference": "Device.WiFi.SSID.2.", "KeyPassphrase": "x"},
                        {"stack": "2,0,0,0,0,0", "SSIDReference": "Device.WiFi.SSID.1.", "KeyPassphrase": "y"}]
    router, _ = make_router(objs)
    with router:
        nets = RouterSettings(router).wifi_networks()
    assert nets[0].password_stack == "2,0,0,0,0,0" and nets[1].password_stack == "1,0,0,0,0,0"


def test_wifi_password_refused_when_ambiguous():
    objs = objects()
    objs[rs.WIFI_AP] = [{"stack": "7,0,0,0,0,0", "KeyPassphrase": "x"}]  # no reference, no matching stack
    router, _ = make_router(objs)
    with router:
        rset = RouterSettings(router)
        net = rset.wifi_networks()[0]
        assert net.password_field is None
        with pytest.raises(RouterError):
            rset.plan_wifi(net, password="a-long-enough-pass")


def test_apply_accepts_equivalent_values_and_reports_unverified():
    class Normalising(FakeLibClient):
        def req_act(self, acts):
            out = super().req_act(acts)
            for row in self.objects.get(rs.TELNET, []):
                row["enable"] = {"0": "false", "1": "true"}.get(row["enable"], row["enable"])
            for row in self.objects.get(rs.DHCP_POOL, []):
                row["DNSServers"] = row["DNSServers"].replace(",", ", ")
            return out

    router = Router("h", "admin", "pw", factories=[lambda *a: Normalising(objects())])
    with router:
        rset = RouterSettings(router)
        assert rset.apply(rset.plan_service(rs.TELNET, False, "Telnet")[0]) is True
        assert rset.apply(rset.plan_dhcp_dns(["192.168.1.104", "1.1.1.1"])) is True
        net = rset.wifi_networks()[0]
        assert rset.apply(rset.plan_wifi(net, password="a-long-enough-pass")[0]) is False  # secret: unverifiable


def test_plan_wifi_validates_and_masks_password():
    router, _ = make_router(objects())
    with router:
        rset = RouterSettings(router)
        net = rset.wifi_networks()[0]
        with pytest.raises(ValueError):
            rset.plan_wifi(net, password="short")
        plans = rset.plan_wifi(net, ssid="NewName", password="a-long-enough-pass")
    assert [p.oid for p in plans] == [rs.WIFI_SSID, rs.WIFI_AP]
    assert "a-long-enough-pass" not in " ".join(plans[1].describe())


def test_probe_masks_secret_fields():
    router, _ = make_router(objects())
    with router:
        probe = RouterSettings(router).probe()
    assert probe[rs.TELNET][0]["password"] == "••••••"
    assert probe[rs.WIFI_AP][0]["KeyPassphrase"] == "••••••"
    assert probe[rs.WIFI_SSID][0]["SSID"] == "Home"


def test_xc220_wifi_common_rows_become_networks():
    objs = objects()
    objs[rs.WIFI_COMMON] = [{"stack": "1,0,0,0,0,0", "band": "2.4GHz",
                             "primaryEnable": "1", "primarySSID": "Home", "primaryModeEnabled": "WPA2-Personal",
                             "primaryPSK": "x", "guestEnable": "0", "guestSSID": "Guest", "guestModeEnabled": "None",
                             "guestPSK": "", "backhaulEnable": "1", "backhaulSSID": "mesh", "backhaulPSK": "y"}]
    router, _ = make_router(objs)
    with router:
        rset = RouterSettings(router)
        nets = rset.wifi_networks()
        assert [(n.ssid, n.band, n.enabled) for n in nets] == [("Home", "2.4GHz", True),
                                                               ("Guest", "2.4GHz guest", False)]  # no mesh link
        plans = rset.plan_wifi(nets[0], ssid="New", password="a-long-enough-pass")
        assert [(p.oid, p.stack, list(p.changes)) for p in plans] == [
            (rs.WIFI_COMMON, "1,0,0,0,0,0", ["primarySSID"]), (rs.WIFI_COMMON, "1,0,0,0,0,0", ["primaryPSK"])]
        assert rset.apply(plans[0]) is True and rset.wifi_networks()[0].ssid == "New"


def test_telnet_local_enabled_field():
    router, _ = make_router({rs.TELNET: [{"stack": "0,0,0,0,0,0", "telnetLocalEnabled": "1"}]})
    with router:
        rset = RouterSettings(router)
        assert rset.service_enabled(rs.TELNET) is True
        assert rset.plan_service(rs.TELNET, False, "Telnet")[0].changes == {"telnetLocalEnabled": "0"}


def test_service_off_covers_every_instance_and_skips_done_ones():
    wps = [{"stack": "1,0,0,0,0,0", "enable": "1"}, {"stack": "2,0,0,0,0,0", "enable": "0"},
           {"stack": "3,0,0,0,0,0", "enable": "1"}]
    router, _ = make_router({rs.WPS: wps})
    with router:
        rset = RouterSettings(router)
        plans = rset.plan_service(rs.WPS, False, "WPS")
        assert [p.stack for p in plans] == ["1,0,0,0,0,0", "3,0,0,0,0,0"]
        for p in plans:
            rset.apply(p)
        assert rset.plan_service(rs.WPS, False, "WPS") == [] and rset.service_enabled(rs.WPS) is False


def test_reservation_add_then_noop_and_conflict():
    objs = objects()
    router, made = make_router(objs)
    with router:
        rset = RouterSettings(router)
        plan = rset.plan_reservation("02:00:00:00:00:aa", "192.168.1.118")
        assert plan.adds and plan.stack == "1,0,0,0,0,0"
        assert rset.apply(plan) is True
        assert ("ao", rs.DHCP_RESERVATION) in {(c[0], c[1]) for c in made[0].calls}
        assert rset.plan_reservation("02:00:00:00:00:AA", "192.168.1.118") is None  # already done
        with pytest.raises(RouterError):
            rset.plan_reservation("AA:BB:CC:DD:EE:FF", "192.168.1.118")  # IP belongs to another device
        with pytest.raises(ValueError):
            rset.plan_reservation("not-a-mac", "192.168.1.118")
