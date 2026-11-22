"""SQLite store for devices, per-device DNS activity, security findings and events."""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    connection TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dns_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    device_mac TEXT,
    domain TEXT NOT NULL,
    app TEXT,
    category TEXT,
    blocked INTEGER NOT NULL DEFAULT 0,
    qtype TEXT NOT NULL DEFAULT '',
    UNIQUE (ts, client_ip, domain, qtype)
);
CREATE INDEX IF NOT EXISTS dns_log_ts ON dns_log (ts);
CREATE INDEX IF NOT EXISTS dns_log_client ON dns_log (client_ip, ts);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    run_ts TEXT NOT NULL,
    check_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    fix TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_run ON findings (run_ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
BUSY_TIMEOUT_SEC = 10
LAST_RUN_KEY = "last_check_run"


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def to_utc(ts: str) -> str:
    """Normalise an RFC 3339 timestamp (any offset) to millisecond UTC ISO text.

    Milliseconds keep genuine repeat lookups in the same second distinct, and the
    text still sorts correctly against second-precision values from utcnow().
    """
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class DeviceRecord:
    mac: str
    ip: str
    hostname: str
    label: str
    connection: str
    first_seen: str
    last_seen: str
    trusted: bool

    @property
    def display_name(self) -> str:
        return self.label or self.hostname or self.ip or self.mac


@dataclass(frozen=True)
class DnsRecord:
    ts: str
    client_ip: str
    device_mac: str | None
    domain: str
    app: str | None
    category: str | None
    blocked: bool
    qtype: str


@dataclass(frozen=True)
class FindingRecord:
    run_ts: str
    check_id: str
    severity: str
    title: str
    detail: str
    fix: str


@dataclass(frozen=True)
class UsageRow:
    name: str          # app name, or site for unknown domains
    category: str
    queries: int
    blocked: int
    first_ts: str
    last_ts: str


class Store:
    def __init__(self, path: Path) -> None:
        from percy.config import private_dir

        private_dir(path.parent)
        path.touch(mode=0o600, exist_ok=True)
        os.chmod(path, 0o600)  # household browsing log: owner only (WAL/SHM inherit this mode)
        # The GUI, the background monitor and the CLI share this file: wait for locks instead of failing.
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None,
                                     timeout=BUSY_TIMEOUT_SEC)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        # WAL lets the GUI read while the background monitor writes. Must run outside a transaction.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            # IMMEDIATE takes the write lock up front, so read-then-write can't hit
            # "database is locked" when another process commits in between.
            cur.execute("BEGIN IMMEDIATE")
            try:
                yield cur
                cur.execute("COMMIT")
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.rollback()
                raise

    def _query(self, sql: str, params: Iterable = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    # -- meta ------------------------------------------------------------
    def get_meta(self, key: str) -> str | None:
        rows = self._query("SELECT value FROM meta WHERE key = ?", (key,))
        return rows[0]["value"] if rows else None

    def set_meta(self, key: str, value: str) -> None:
        with self._tx() as cur:
            cur.execute("INSERT INTO meta(key, value) VALUES(?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    # -- devices ---------------------------------------------------------
    def upsert_devices(self, seen: Iterable[tuple[str, str, str, str]], now: str | None = None) -> list[str]:
        """Record (mac, ip, hostname, connection) sightings. Returns MACs never seen before."""
        now = now or utcnow()
        new: list[str] = []
        with self._tx() as cur:
            for mac, ip, hostname, connection in seen:
                mac = mac.upper()
                if not mac:
                    continue
                row = cur.execute("SELECT mac FROM devices WHERE mac = ?", (mac,)).fetchone()
                if row is None:
                    new.append(mac)
                    cur.execute(
                        "INSERT INTO devices(mac, ip, hostname, connection, first_seen, last_seen) "
                        "VALUES(?, ?, ?, ?, ?, ?)", (mac, ip, hostname, connection, now, now))
                else:
                    cur.execute(
                        "UPDATE devices SET ip = COALESCE(NULLIF(?, ''), ip), "
                        "hostname = COALESCE(NULLIF(?, ''), hostname), "
                        "connection = COALESCE(NULLIF(?, ''), connection), last_seen = ? WHERE mac = ?",
                        (ip, hostname, connection, now, mac))
        return new

    def devices(self) -> list[DeviceRecord]:
        rows = self._query("SELECT * FROM devices ORDER BY last_seen DESC")
        return [DeviceRecord(r["mac"], r["ip"], r["hostname"], r["label"], r["connection"],
                             r["first_seen"], r["last_seen"], bool(r["trusted"])) for r in rows]

    def set_device_label(self, mac: str, label: str) -> None:
        with self._tx() as cur:
            cur.execute("UPDATE devices SET label = ? WHERE mac = ?", (label.strip(), mac.upper()))

    def set_device_trusted(self, mac: str, trusted: bool) -> None:
        with self._tx() as cur:
            cur.execute("UPDATE devices SET trusted = ? WHERE mac = ?", (int(trusted), mac.upper()))

    def mac_by_ip(self) -> dict[str, str]:
        rows = self._query("SELECT ip, mac FROM devices WHERE ip != '' ORDER BY last_seen")
        return {r["ip"]: r["mac"] for r in rows}  # latest sighting wins

    # -- dns activity ----------------------------------------------------
    def add_dns(self, records: Iterable[DnsRecord]) -> int:
        added = 0
        with self._tx() as cur:
            for r in records:
                cur.execute(
                    "INSERT OR IGNORE INTO dns_log(ts, client_ip, device_mac, domain, app, category, blocked, qtype) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (r.ts, r.client_ip, r.device_mac, r.domain, r.app, r.category, int(r.blocked), r.qtype))
                added += cur.rowcount
        return added

    def dns_for(self, *, mac: str | None = None, client_ip: str | None = None, since: str | None = None,
                search: str | None = None, limit: int = 500) -> list[DnsRecord]:
        sql, params = "SELECT * FROM dns_log WHERE 1=1", []
        if mac:
            sql += " AND device_mac = ?"
            params.append(mac.upper())
        if client_ip:
            sql += " AND client_ip = ?"
            params.append(client_ip)
        if since:
            sql += " AND ts >= ?"
            params.append(since)
        if search:
            sql += " AND (domain LIKE ? OR app LIKE ?)"
            params += [f"%{search}%", f"%{search}%"]
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        return [DnsRecord(r["ts"], r["client_ip"], r["device_mac"], r["domain"], r["app"], r["category"],
                          bool(r["blocked"]), r["qtype"]) for r in self._query(sql, params)]

    def usage_for(self, *, mac: str | None = None, since: str | None = None, limit: int = 50) -> list[UsageRow]:
        """Per-app (or per-site) totals for one device, or the whole network if mac is None."""
        from percy.activity.apps import site_of

        sql = "SELECT domain, app, category, blocked, ts FROM dns_log WHERE 1=1"
        params: list = []
        if mac:
            sql += " AND device_mac = ?"
            params.append(mac.upper())
        if since:
            sql += " AND ts >= ?"
            params.append(since)
        totals: dict[str, list] = {}
        for r in self._query(sql, params):
            name = r["app"] or site_of(r["domain"])
            row = totals.setdefault(name, [r["category"] or "Website", 0, 0, r["ts"], r["ts"]])
            row[1] += 1
            row[2] += int(r["blocked"])
            row[3] = min(row[3], r["ts"])
            row[4] = max(row[4], r["ts"])
        ranked = sorted(totals.items(), key=lambda kv: kv[1][1], reverse=True)[:limit]
        return [UsageRow(name, *vals) for name, vals in ranked]

    def prune(self, keep_days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).replace(microsecond=0).isoformat()
        with self._tx() as cur:
            cur.execute("DELETE FROM dns_log WHERE ts < ?", (cutoff,))
            removed = cur.rowcount
            cur.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            cur.execute("DELETE FROM findings WHERE run_ts < ?", (cutoff,))
        return removed

    # -- findings & events ----------------------------------------------
    def save_findings(self, run_ts: str, findings: Iterable[FindingRecord]) -> None:
        with self._tx() as cur:
            for f in findings:
                cur.execute("INSERT INTO findings(run_ts, check_id, severity, title, detail, fix) "
                            "VALUES(?, ?, ?, ?, ?, ?)", (run_ts, f.check_id, f.severity, f.title, f.detail, f.fix))
            # Recorded even for a clean run, so old (now fixed) findings stop showing.
            cur.execute("INSERT INTO meta(key, value) VALUES(?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (LAST_RUN_KEY, run_ts))

    def last_check_run(self) -> str | None:
        return self.get_meta(LAST_RUN_KEY)

    def latest_findings(self) -> list[FindingRecord]:
        run_ts = self.last_check_run()
        if not run_ts:
            return []
        rows = self._query("SELECT * FROM findings WHERE run_ts = ?", (run_ts,))
        return [FindingRecord(r["run_ts"], r["check_id"], r["severity"], r["title"], r["detail"], r["fix"])
                for r in rows]

    def add_event(self, kind: str, message: str, ts: str | None = None) -> None:
        with self._tx() as cur:
            cur.execute("INSERT INTO events(ts, kind, message) VALUES(?, ?, ?)", (ts or utcnow(), kind, message))

    def events(self, limit: int = 200) -> list[tuple[str, str, str]]:
        rows = self._query("SELECT ts, kind, message FROM events ORDER BY ts DESC, id DESC LIMIT ?", (limit,))
        return [(r["ts"], r["kind"], r["message"]) for r in rows]
