from percy.security.checks import (HIGH, INFO, MEDIUM, NetworkFacts, SeenDevice, classify_wifi_security,
                                   run_checks, score)


def ids(findings):
    return {f.check_id for f in findings}


def test_telnet_open_on_router_is_high():
    findings = run_checks(NetworkFacts(router_open_ports=(22, 23, 53, 80)))
    telnet = next(f for f in findings if f.check_id == "router-telnet")
    assert telnet.severity == HIGH
    assert findings[0].check_id == "router-telnet"  # sorted most severe first
    assert {"router-ssh", "router-admin-http"} <= ids(findings)


def test_clean_network_has_no_problems():
    facts = NetworkFacts(router_open_ports=(53, 80, 443), wifi_security=(("Home", "WPA3-SAE"),),
                         router_services={"upnp": False, "wps": False, "remote_ui": False, "dmz": False})
    findings = run_checks(facts)
    assert score(findings) == 100
    assert ids(findings) == {"wifi-ok"}


def test_wifi_security_classification():
    assert classify_wifi_security("WPA2") == "wpa2"
    assert classify_wifi_security("WPA2-PSK (AES)") == "wpa2"
    assert classify_wifi_security("WPA/WPA2 TKIP") == "weak-tkip"
    assert classify_wifi_security("WEP") == "weak-open"
    assert classify_wifi_security("") == "weak-open"
    assert classify_wifi_security("WPA2/WPA3") == "wpa3"
    assert classify_wifi_security("WPA") == "weak-tkip"


def test_dns_hijack_and_upnp_mappings():
    facts = NetworkFacts(nx_hijack_ip="49.44.1.1", router_services={"upnp": True},
                         upnp_mappings=({"externalPort": "3074", "internalClient": "192.168.1.20",
                                         "description": "Xbox"},))
    by_id = {f.check_id: f for f in run_checks(facts)}
    assert by_id["dns-hijack"].severity == MEDIUM and "49.44.1.1" in by_id["dns-hijack"].detail
    assert by_id["router-upnp"].severity == MEDIUM and "Xbox" in by_id["router-upnp"].detail


def test_new_and_unreviewed_devices():
    devices = (SeenDevice("AA:00:00:00:00:01", "192.168.1.50", "phone", False, True),
               SeenDevice("AA:00:00:00:00:02", "192.168.1.51", "tv", False, False),
               SeenDevice("AA:00:00:00:00:03", "192.168.1.52", "laptop", True, True))
    by_id = {f.check_id: f for f in run_checks(NetworkFacts(devices=devices))}
    assert "phone" in by_id["device-new"].detail and "laptop" not in by_id["device-new"].detail
    assert by_id["device-unreviewed"].severity == INFO


def test_risky_device_ports_use_device_name():
    facts = NetworkFacts(devices=(SeenDevice("AA:00:00:00:00:09", "192.168.1.70", "Living-room TV", True, False),),
                         device_ports={"192.168.1.70": (5555,)})
    finding = next(f for f in run_checks(facts) if f.check_id == "device-port-5555")
    assert finding.severity == HIGH and finding.title.startswith("Living-room TV")


def test_adblock_coverage():
    not_used = run_checks(NetworkFacts(adblock_ip="192.168.1.104", adblock_running=True, dhcp_dns=("192.168.1.1",)))
    assert "adblock-not-used" in ids(not_used)
    down = run_checks(NetworkFacts(adblock_ip="192.168.1.104", adblock_running=False,
                                   dhcp_dns=("192.168.1.104", "1.1.1.1")))
    assert next(f for f in down if f.check_id == "adblock-down").severity == HIGH
    in_use = run_checks(NetworkFacts(adblock_ip="192.168.1.104", adblock_running=True,
                                     dhcp_dns=("192.168.1.104",)))
    assert not ({"adblock-not-used", "adblock-down"} & ids(in_use))


def test_score_floor_is_zero():
    facts = NetworkFacts(router_open_ports=(23,), router_services={"remote_ui": True, "dmz": True, "wps": True},
                         wifi_security=(("x", "WEP"),))
    assert score(run_checks(facts)) == 0
