"""Copy new AdGuard Home query-log entries into Percy's per-device activity log.

AdGuard pages its log newest-first. Each run reads from the top down to the
saved cursor. If the page budget runs out first (big backlog, monitor was off),
the unread gap is remembered and drained on later runs, so nothing is skipped.
"""
from __future__ import annotations

from percy.activity.apps import classify
from percy.activity.store import DnsRecord, Store, to_utc
from percy.services.adguard import AdGuard, QueryLogEntry

CURSOR_KEY = "querylog_cursor"            # newest entry already stored (UTC)
BACKLOG_FROM_KEY = "querylog_backlog_from"  # resume paging older than this (AdGuard's own value)
BACKLOG_UNTIL_KEY = "querylog_backlog_until"  # ...down to this time (UTC)
MAX_PAGES_PER_RUN = 40  # 40 x 500 = 20k lookups per poll


def to_record(entry: QueryLogEntry, mac_by_ip: dict[str, str]) -> DnsRecord:
    match = classify(entry.domain)
    return DnsRecord(
        ts=to_utc(entry.time),
        client_ip=entry.client_ip,
        device_mac=mac_by_ip.get(entry.client_ip),
        domain=entry.domain,
        app=match.app if match else None,
        category=match.category if match else None,
        blocked=entry.blocked,
        qtype=entry.qtype,
    )


def _read_down_to(adguard: AdGuard, floor_utc: str | None, older_than: str | None, pages: int,
                  mac_by_ip: dict[str, str]) -> tuple[list[DnsRecord], str | None, bool, str | None]:
    """Page newest-first until floor_utc. Returns (records, newest_time, done, resume_point)."""
    records: list[DnsRecord] = []
    newest: str | None = None
    for _ in range(pages):
        entries, oldest = adguard.querylog_page(older_than=older_than)
        if not entries:
            return records, newest, True, None
        newest = newest or entries[0].time
        for entry in entries:
            if floor_utc and to_utc(entry.time) < floor_utc:
                return records, newest, True, None
            records.append(to_record(entry, mac_by_ip))
        if not oldest:
            return records, newest, True, None
        older_than = oldest
    return records, newest, False, older_than


def collect(adguard: AdGuard, store: Store) -> int:
    """Store lookups newer than the cursor, then drain any remembered backlog. Returns rows added."""
    mac_by_ip = store.mac_by_ip()
    cursor = store.get_meta(CURSOR_KEY) or None
    records, newest, done, resume = _read_down_to(adguard, cursor, None, MAX_PAGES_PER_RUN, mac_by_ip)
    added = store.add_dns(records)
    if newest:
        store.set_meta(CURSOR_KEY, to_utc(newest))
    if not done and cursor:  # gap between what we read and the old cursor: remember it
        store.set_meta(BACKLOG_FROM_KEY, resume or "")
        store.set_meta(BACKLOG_UNTIL_KEY, cursor)
    return added + _drain_backlog(adguard, store, mac_by_ip)


def _drain_backlog(adguard: AdGuard, store: Store, mac_by_ip: dict[str, str]) -> int:
    start = store.get_meta(BACKLOG_FROM_KEY)
    until = store.get_meta(BACKLOG_UNTIL_KEY)
    if not start or not until:
        return 0
    records, _newest, done, resume = _read_down_to(adguard, until, start, MAX_PAGES_PER_RUN, mac_by_ip)
    added = store.add_dns(records)  # UNIQUE ignores the overlap at either end
    store.set_meta(BACKLOG_FROM_KEY, "" if done else (resume or ""))
    if done:
        store.set_meta(BACKLOG_UNTIL_KEY, "")
    return added
