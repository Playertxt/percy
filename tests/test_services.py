import subprocess
from types import SimpleNamespace

import pytest

from percy.config import Settings
from percy.net.dns import RCODE_NXDOMAIN, build_query, parse_response
from percy.net.scan import parse_nmcli_wifi
from percy.services import catalog
from percy.services.adguard import AdGuard, AdGuardError
from percy.services.docker import Docker, DockerError


def dns_reply(query: bytes, rcode=0, ips=()):
    header = query[:2] + bytes([0x81, 0x80 | rcode]) + b"\x00\x01" + len(ips).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    body = query[12:]
    for ip in ips:
        body += b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x04" + bytes(map(int, ip.split(".")))
    return header + body


def test_dns_round_trip():
    q = build_query("doubleclick.net", 0x1234)
    assert parse_response(dns_reply(q, ips=["0.0.0.0"]), 0x1234).blocked
    nx = parse_response(dns_reply(q, rcode=RCODE_NXDOMAIN), 0x1234)
    assert nx.nxdomain and nx.blocked
    ok = parse_response(dns_reply(q, ips=["142.250.1.1", "142.250.1.2"]), 0x1234)
    assert ok.addresses == ("142.250.1.1", "142.250.1.2") and not ok.blocked


def test_parse_nmcli_wifi_handles_escaped_colons():
    out = "no:Other:WPA2:6:40\nyes:Home\\:Net_5G:WPA2:36:82\n"
    link = parse_nmcli_wifi(out)
    assert (link.ssid, link.security, link.channel, link.signal) == ("Home:Net_5G", "WPA2", "36", 82)


class FakeRunner:
    def __init__(self, fail_on=()):
        self.commands = []
        self.fail_on = fail_on

    def __call__(self, args, **_kw):
        self.commands.append(args)
        failing = any(token in args for token in self.fail_on)
        return subprocess.CompletedProcess(args, 1 if failing else 0, stdout="running", stderr="boom")


def test_docker_install_pulls_then_runs(tmp_path):
    runner = FakeRunner(fail_on=("inspect",))
    spec = catalog.netalertx_spec()
    spec = spec.__class__(**{**spec.__dict__, "data_dirs": (str(tmp_path / "d"),)})
    Docker(runner).install(spec)
    verbs = [c[1] for c in runner.commands]
    assert verbs == ["pull", "inspect", "run"]
    assert runner.commands[-1][-1] == spec.image and (tmp_path / "d").is_dir()


def test_docker_state_missing_and_errors():
    assert Docker(FakeRunner(fail_on=("inspect",))).state("x") == "missing"
    with pytest.raises(DockerError):
        Docker(FakeRunner(fail_on=("stop",))).stop("x")


def test_adguard_spec_binds_dns_to_lan_and_ui_to_localhost():
    with pytest.raises(ValueError):
        catalog.adguard_spec(Settings())
    args = catalog.adguard_spec(Settings(dns_host_ip="192.168.1.104")).run_args
    assert "192.168.1.104:53:53/udp" in args and "127.0.0.1:3000:3000/tcp" in args
    assert not any(a.startswith("0.0.0.0") or a == "53:53/udp" for a in args)


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []
        self.auth = None

    def request(self, method, url, timeout, **kw):
        self.requests.append((method, url, kw))
        status, body = self.responses.get((method, url.split("3000")[1]), (200, {}))
        import json
        return SimpleNamespace(status_code=status, content=json.dumps(body).encode(), text=json.dumps(body),
                               json=lambda: body)

    def get(self, url, timeout):
        return self.request("GET", url, timeout)


def test_adguard_client_status_and_auth_error():
    session = FakeSession({("GET", "/control/status"): (200, {"running": True, "protection_enabled": True,
                                                              "version": "v0.107.80", "dns_addresses": ["x"]}),
                           ("GET", "/control/stats"): (401, {})})
    client = AdGuard("http://127.0.0.1:3000", "percy", "pw", session=session)
    assert client.status().version == "v0.107.80"
    assert session.auth == ("percy", "pw")
    with pytest.raises(AdGuardError, match="rejected"):
        client.stats()


def test_adguard_add_filter_skips_existing():
    session = FakeSession({("GET", "/control/filtering/status"): (200, {"filters": [{"url": "https://a"}]})})
    client = AdGuard("http://127.0.0.1:3000", "percy", "pw", session=session)
    client.add_filter("A", "https://a")
    client.add_filter("B", "https://b")
    posts = [r for r in session.requests if r[0] == "POST"]
    assert len(posts) == 1 and posts[0][2]["json"]["url"] == "https://b"
