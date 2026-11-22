from percy.activity.apps import classify, site_of
from percy.activity.collector import CURSOR_KEY, collect
from percy.activity.store import DnsRecord, to_utc
from percy.services.adguard import QueryLogEntry, parse_querylog_entry


def test_classify_longest_suffix_wins():
    assert classify("mail.google.com").app == "Gmail"
    assert classify("www.google.com").app == "Google Search"
    assert classify("r3---sn-abc.googlevideo.com").app == "YouTube"
    assert classify("WWW.INSTAGRAM.COM.").app == "Instagram"
    assert classify("example.org") is None


def test_site_of():
    assert site_of("cdn.news.example.co.in") == "example.co.in"
    assert site_of("a.b.example.com") == "example.com"


def test_to_utc_normalises_offsets():
    assert to_utc("2026-11-21T16:40:12.123456+05:30") == "2026-11-21T11:10:12.123+00:00"
    assert to_utc("2026-11-21T11:10:12Z") == "2026-11-21T11:10:12.000+00:00"
    # still sorts correctly against second-precision 'since' values
    assert to_utc("2026-11-21T11:10:12.5Z") >= "2026-11-21T11:10:12+00:00"
    assert to_utc("2026-11-21T11:10:11.999Z") < "2026-11-21T11:10:12+00:00"


def test_parse_querylog_entry():
    raw = {"time": "2026-11-21T16:40:12+05:30", "client": "192.168.1.50",
           "question": {"name": "ads.doubleclick.net.", "type": "A"}, "reason": "FilteredBlackList",
           "client_info": {"name": "phone"}}
    entry = parse_querylog_entry(raw)
    assert entry.domain == "ads.doubleclick.net" and entry.blocked and entry.client_name == "phone"
    assert parse_querylog_entry({"time": "x"}) is None


def test_store_devices_new_detection_and_labels(store):
    assert store.upsert_devices([("aa:bb:cc:00:00:01", "192.168.1.50", "phone", "5 GHz")]) == ["AA:BB:CC:00:00:01"]
    assert store.upsert_devices([("AA:BB:CC:00:00:01", "192.168.1.51", "", "")]) == []
    store.set_device_label("AA:BB:CC:00:00:01", "Mum's phone")
    store.set_device_trusted("AA:BB:CC:00:00:01", True)
    (d,) = store.devices()
    assert (d.ip, d.hostname, d.display_name, d.trusted) == ("192.168.1.51", "phone", "Mum's phone", True)
    assert store.mac_by_ip() == {"192.168.1.51": "AA:BB:CC:00:00:01"}


def record(ts, domain, ip="192.168.1.50", mac="AA:BB:CC:00:00:01", blocked=False):
    m = classify(domain)
    return DnsRecord(ts, ip, mac, domain, m.app if m else None, m.category if m else None, blocked, "A")


def test_store_dns_dedupe_usage_and_search(store):
    rows = [record("2026-11-21T10:00:00+00:00", "i.ytimg.com"),
            record("2026-11-21T10:00:01+00:00", "youtube.com"),
            record("2026-11-21T10:00:01+00:00", "youtube.com"),  # duplicate
            record("2026-11-21T10:05:00+00:00", "ads.doubleclick.net", blocked=True),
            record("2026-11-21T10:06:00+00:00", "news.example.com", ip="192.168.1.60", mac="AA:BB:CC:00:00:02")]
    assert store.add_dns(rows) == 4
    usage = {u.name: u for u in store.usage_for(mac="AA:BB:CC:00:00:01")}
    assert usage["YouTube"].queries == 2 and usage["Ads & tracking"].blocked == 1
    assert {u.name for u in store.usage_for()} == {"YouTube", "Ads & tracking", "example.com"}
    # search matches the domain or the app name, so YouTube's image CDN is included
    assert [r.domain for r in store.dns_for(search="tube")] == ["youtube.com", "i.ytimg.com"]
    assert [r.domain for r in store.dns_for(search="example")] == ["news.example.com"]
    assert [r.domain for r in store.dns_for(since="2026-11-21T10:05:00+00:00", mac="AA:BB:CC:00:00:01")] == [
        "ads.doubleclick.net"]


def test_prune_removes_old_rows(store):
    store.add_dns([record("2020-01-01T00:00:00+00:00", "old.example.com")])
    assert store.prune(keep_days=30) == 1


class FakeAdGuard:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def querylog_page(self, older_than=None, limit=500):
        self.calls.append(older_than)
        return self.pages.get(older_than, ([], None))


def entry(ts, domain, ip="192.168.1.50"):
    return QueryLogEntry(ts, ip, "", domain, "A", False, "NotFilteredNotFound")


def test_collect_pages_until_cursor_and_maps_devices(store):
    store.upsert_devices([("AA:BB:CC:00:00:01", "192.168.1.50", "phone", "")])
    first = FakeAdGuard({
        None: ([entry("2026-11-21T10:02:00+00:00", "youtube.com"),
                entry("2026-11-21T10:01:00+00:00", "netflix.com")], "2026-11-21T10:01:00+00:00"),
        "2026-11-21T10:01:00+00:00": ([entry("2026-11-21T10:00:00+00:00", "spotify.com")], None),
    })
    assert collect(first, store) == 3
    assert store.get_meta(CURSOR_KEY) == "2026-11-21T10:02:00.000+00:00"
    assert {r.device_mac for r in store.dns_for()} == {"AA:BB:CC:00:00:01"}

    second = FakeAdGuard({
        None: ([entry("2026-11-21T10:03:00+00:00", "whatsapp.net"),
                entry("2026-11-21T10:02:00+00:00", "youtube.com"),
                entry("2026-11-21T10:01:00+00:00", "netflix.com")], "2026-11-21T10:01:00+00:00"),
    })
    assert collect(second, store) == 1  # only the new lookup
    assert second.calls == [None]       # stopped at the cursor, no extra pages


def test_collect_remembers_and_drains_backlog(store, monkeypatch):
    from percy.activity import collector

    monkeypatch.setattr(collector, "MAX_PAGES_PER_RUN", 1)
    store.set_meta(CURSOR_KEY, "2026-11-21T10:00:00.000+00:00")
    log = FakeAdGuard({
        None: ([entry("2026-11-21T10:05:00+00:00", "a.example.com")], "p1"),
        "p1": ([entry("2026-11-21T10:04:00+00:00", "b.example.com")], "p2"),
        "p2": ([entry("2026-11-21T10:03:00+00:00", "c.example.com"),
                entry("2026-11-21T09:59:00+00:00", "old.example.com")], "p3"),
    })
    collect(log, store)  # one page of new data + one backlog page
    assert {r.domain for r in store.dns_for()} == {"a.example.com", "b.example.com"}
    assert store.get_meta(collector.BACKLOG_FROM_KEY) == "p2"
    collect(FakeAdGuard({None: ([], None), **{k: v for k, v in log.pages.items() if k}}), store)
    assert {r.domain for r in store.dns_for()} == {"a.example.com", "b.example.com", "c.example.com"}
    assert store.get_meta(collector.BACKLOG_FROM_KEY) == ""  # drained, older-than-cursor row skipped


def test_latest_findings_clears_after_clean_run(store):
    from percy.activity.store import FindingRecord

    store.save_findings("2026-11-21T10:00:00+00:00", [FindingRecord("2026-11-21T10:00:00+00:00", "x", "high",
                                                                    "t", "d", "f")])
    assert len(store.latest_findings()) == 1
    store.save_findings("2026-11-21T11:00:00+00:00", [])
    assert store.latest_findings() == [] and store.last_check_run() == "2026-11-21T11:00:00+00:00"
