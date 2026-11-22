from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gi.repository import Adw, Gtk

from percy.ui.widgets import Page, action_row, local_time

RANGES = (("Last hour", 1), ("Last 24 hours", 24), ("Last 7 days", 168), ("Last 30 days", 720))
MAX_ROWS = 300


class ActivityPage(Page):
    title = "Activity"
    icon = "document-open-recent-symbolic"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.device_mac: str | None = None
        self.hours = 24
        self.by_app = True
        self.search = ""

    def show_device(self, mac: str | None) -> None:
        self.device_mac = mac
        self.refresh()

    def refresh(self) -> None:
        self.clear()
        devices = self.ctx.store.devices()
        filters = self.group("What each device looked up",
                             "From AdGuard Home's DNS log: the site/app name, not the full link or page contents "
                             "(HTTPS hides those). Only devices using the ad blocker for DNS show up.")
        names = ["Whole network"] + [d.display_name for d in devices]
        device_row = Adw.ComboRow(title="Device", model=Gtk.StringList.new(names))
        macs = [None] + [d.mac for d in devices]
        device_row.set_selected(macs.index(self.device_mac) if self.device_mac in macs else 0)
        device_row.connect("notify::selected", lambda r, _p: self._set(device_mac=macs[r.get_selected()]))
        filters.add(device_row)

        range_row = Adw.ComboRow(title="Time", model=Gtk.StringList.new([r[0] for r in RANGES]))
        range_row.set_selected(next((i for i, r in enumerate(RANGES) if r[1] == self.hours), 1))
        range_row.connect("notify::selected", lambda r, _p: self._set(hours=RANGES[r.get_selected()][1]))
        filters.add(range_row)

        mode = Adw.SwitchRow(title="Group by app", subtitle="Off: every single lookup", active=self.by_app)
        mode.connect("notify::active", lambda r, _p: self._set(by_app=r.get_active()))
        filters.add(mode)

        search = Adw.EntryRow(title="Search domain or app", text=self.search, show_apply_button=True)
        search.connect("apply", lambda r: self._set(search=r.get_text().strip()))
        filters.add(search)

        since = (datetime.now(timezone.utc) - timedelta(hours=self.hours)).replace(microsecond=0).isoformat()
        results = self.group()
        if self.by_app:
            rows = self.ctx.store.usage_for(mac=self.device_mac, since=since, limit=MAX_ROWS)
            rows = [u for u in rows if not self.search or self.search.lower() in u.name.lower()]
            for u in rows:
                blocked = f" · {u.blocked} blocked" if u.blocked else ""
                results.add(action_row(u.name, f"{u.category} · {u.queries} lookups{blocked} · "
                                       f"{local_time(u.first_ts)} – {local_time(u.last_ts)}"))
        else:
            names_by_mac = {d.mac: d.display_name for d in devices}
            rows = self.ctx.store.dns_for(mac=self.device_mac, since=since, search=self.search or None,
                                          limit=MAX_ROWS)
            for r in rows:
                who = names_by_mac.get(r.device_mac or "", r.client_ip)
                tag = "BLOCKED · " if r.blocked else ""
                results.add(action_row(r.domain, f"{tag}{r.app or 'website'} · {who} · {local_time(r.ts)}",
                                       "action-unavailable-symbolic" if r.blocked else None, "error" if r.blocked else None))
        if not rows:
            results.add(action_row("Nothing logged yet",
                                   "Set up the ad blocker, point the network at it, and keep the monitor running."))

    def _set(self, **changes) -> None:
        for key, value in changes.items():
            setattr(self, key, value)
        self.refresh()
