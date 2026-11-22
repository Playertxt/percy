from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gi.repository import Adw, Gtk

from percy import secrets
from percy.agents.summary import summarize
from percy.monitor.daemon import Monitor
from percy.router import RouterSettings
from percy.router import settings as rs
from percy.security.checks import Finding
from percy.ui.widgets import SEVERITY_CSS, SEVERITY_ICON, Page, action_row, apply_plans, button, local_time

# Findings Percy can fix directly on the router: check_id -> (object, label)
ROUTER_FIXES = {
    "router-telnet": (rs.TELNET, "Turn Telnet off"),
    "router-ssh": (rs.SSH, "Turn SSH off"),
    "router-upnp": (rs.UPNP, "Turn UPnP off"),
    "wifi-wps": (rs.WPS, "Turn WPS off"),
    "router-remote-admin": (rs.REMOTE_UI, "Turn remote management off"),
}
PAGE_FIXES = {"adblock-not-used": "adblock", "adblock-down": "agents", "device-new": "devices",
              "device-unreviewed": "devices"}


class SecurityPage(Page):
    title = "Security"
    icon = "security-high-symbolic"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._summary_text: str | None = None

    def refresh(self) -> None:
        self.clear()
        records = self.ctx.store.latest_findings()
        head = self.group("Security check",
                          f"Last run {local_time(records[0].run_ts)}" if records else "Not run yet")
        head.set_header_suffix(button("Run check now", self._run, "suggested-action"))
        findings = [Finding(r.check_id, r.severity, r.title, r.detail, r.fix) for r in records]
        if not findings:
            head.add(action_row("Press 'Run check now'",
                                "Scans the router's open ports and settings, Wi-Fi encryption, DNS, UPnP and every "
                                "device on the LAN for risky open ports. Takes about 30 seconds."))
        for f in findings:
            head.add(self._row(f))
        self._summary_group(bool(findings))

    def _row(self, f: Finding) -> Adw.ActionRow:
        row = action_row(f.title, f.detail + (f"\nFix: {f.fix}" if f.fix else ""),
                         SEVERITY_ICON.get(f.severity), SEVERITY_CSS.get(f.severity))
        if f.check_id in ROUTER_FIXES:
            oid, label = ROUTER_FIXES[f.check_id]
            row.add_suffix(button("Fix…", lambda o=oid, t=label: self._fix(o, t)))
        elif f.check_id in PAGE_FIXES:
            row.add_suffix(button("Open", lambda p=PAGE_FIXES[f.check_id]: self.ctx.window.show_page(p)))
        return row

    def _summary_group(self, have_findings: bool) -> None:
        grp = self.group("Explain with Claude",
                         "Sends the findings above (not your browsing) to Anthropic's API and shows a plain-words "
                         "plan. Needs an API key in Settings.")
        include = Adw.SwitchRow(title="Also send 24 h app totals", subtitle="App names and counts only, no device names")
        grp.add(include)
        ask = button("Explain", lambda: self._explain(include.get_active()), "suggested-action")
        ask.set_sensitive(have_findings and self.ctx.settings.claude_summary)
        grp.set_header_suffix(ask)
        if self._summary_text:
            label = Gtk.Label(label=self._summary_text, wrap=True, xalign=0, selectable=True,
                              margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
            grp.add(label)

    def _run(self) -> None:
        self.ctx.toast("Running security check…")
        monitor = Monitor(self.ctx.settings, self.ctx.store, alerts=False)
        self.ctx.run(monitor.tick_check, lambda _f: self.refresh(), "Security check")

    def _fix(self, oid: str, label: str) -> None:
        def work():
            with self.ctx.router() as router:
                return RouterSettings(router).plan_service(oid, False, label)

        self.ctx.run(work, lambda plans: apply_plans(self.ctx, plans, self._run), "Preparing the fix")

    def _explain(self, with_activity: bool) -> None:
        findings = [Finding(r.check_id, r.severity, r.title, r.detail, r.fix)
                    for r in self.ctx.store.latest_findings()]
        usage = None
        if with_activity:
            since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            usage = self.ctx.store.usage_for(since=since, limit=40)
        context = {"router": self.ctx.settings.router_host, "devices_known": len(self.ctx.store.devices())}
        key = secrets.get_secret(secrets.ANTHROPIC_KEY)
        self.ctx.toast("Asking Claude…")

        def done(text: str) -> None:
            self._summary_text = text
            self.refresh()

        self.ctx.run(lambda: summarize(findings, context, key, self.ctx.settings.claude_model, usage), done,
                     "Claude summary")
