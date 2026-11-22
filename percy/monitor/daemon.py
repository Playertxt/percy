"""The always-on monitor: activity log every minute, full security check every N minutes."""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from percy import secrets
from percy.activity.collector import collect
from percy.activity.store import Store
from percy.config import Settings
from percy.monitor.notify import notify
from percy.security.checks import HIGH, MEDIUM, Finding
from percy.security.runner import run_full_check
from percy.services.adguard import AdGuard, AdGuardError

log = logging.getLogger(__name__)
ALERT_SEVERITIES = (HIGH, MEDIUM)
PRUNE_EVERY_SEC = 6 * 3600


def adguard_client(settings: Settings) -> AdGuard | None:
    password = secrets.get_secret(secrets.ADGUARD_PASSWORD)
    if not password:
        return None
    return AdGuard(f"http://127.0.0.1:{settings.adguard_web_port}", settings.adguard_username, password)


@dataclass
class Monitor:
    settings: Settings
    store: Store
    notifier: Callable[[str, str, bool], None] = notify
    clock: Callable[[], float] = time.monotonic
    # False for one-off checks from the GUI/CLI: the background monitor owns alerts.
    alerts: bool = True
    _alerted: set[str] = field(default_factory=set)
    _next_check: float = 0.0
    _next_prune: float = 0.0

    def tick_activity(self) -> int:
        client = adguard_client(self.settings)
        if client is None:
            return 0
        try:
            added = collect(client, self.store)
        except (AdGuardError, ValueError, KeyError, TypeError, AttributeError) as exc:
            log.warning("Activity log not updated: %s", exc)
            return 0
        if added:
            log.info("Activity log: %d new lookups", added)
        return added

    def adblock_running(self) -> bool | None:
        client = adguard_client(self.settings)
        if client is None:
            return None
        try:
            return client.status().running
        except AdGuardError:
            return False

    def tick_check(self) -> list[Finding]:
        report = run_full_check(self.settings, secrets.get_secret(secrets.ROUTER_PASSWORD), self.store,
                                self.adblock_running())
        if self.alerts:
            self._alert_new(report.findings, degraded=bool(report.facts.errors))
        return list(report.findings)

    def _alert_new(self, findings: tuple[Finding, ...], degraded: bool = False) -> None:
        current = {f"{f.check_id}|{f.title}": f for f in findings if f.severity in ALERT_SEVERITIES}
        for key, finding in current.items():
            if key in self._alerted:
                continue
            self.store.add_event("alert", f"[{finding.severity}] {finding.title}: {finding.detail}")
            if self.settings.notify:
                self.notifier(f"Percy: {finding.title}", finding.fix or finding.detail, finding.severity == HIGH)
        # A fixed issue that comes back alerts again. But a run where part of the check
        # failed (router unreachable) can't tell "fixed" from "not checked": keep the memory.
        self._alerted = (self._alerted | set(current)) if degraded else set(current)

    def step(self) -> None:
        now = self.clock()
        try:
            self.tick_activity()
        except Exception:  # never let the activity log stop the security checks
            log.exception("Activity log update failed")
        if now >= self._next_check:
            try:
                self.tick_check()
            except Exception as exc:  # keep the monitor alive whatever a check does
                log.exception("Security check failed")
                self.store.add_event("error", f"Security check failed: {exc}")
            self._next_check = now + self.settings.check_interval_min * 60
        if now >= self._next_prune:
            removed = self.store.prune(self.settings.activity_retention_days)
            if removed:
                log.info("Pruned %d old activity rows", removed)
            self._next_prune = now + PRUNE_EVERY_SEC

    def run_forever(self, stop: threading.Event) -> None:
        self.store.add_event("monitor", "Monitor started")
        while not stop.is_set():
            try:
                self.step()
            except Exception:
                log.exception("Monitor step failed")
            stop.wait(max(15, self.settings.activity_poll_sec))
        self.store.add_event("monitor", "Monitor stopped")
