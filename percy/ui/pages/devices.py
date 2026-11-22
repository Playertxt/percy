from __future__ import annotations

from gi.repository import Adw, Gtk

from percy.activity.store import DeviceRecord
from percy.ui.widgets import Page, action_row, button, local_time


class DevicesPage(Page):
    title = "Devices"
    icon = "network-workgroup-symbolic"

    def refresh(self) -> None:
        self.clear()
        top = self.group("Devices on your network",
                         "Mark the ones you recognise as known; anything new or unknown is flagged by the monitor.")
        top.set_header_suffix(button("Scan router", self._scan, "suggested-action"))
        devices = self.ctx.store.devices()
        if not devices:
            top.add(action_row("No devices yet", "Press 'Scan router' or run a security check."))
            return
        for device in devices:
            top.add(self._row(device))

    def _row(self, d: DeviceRecord) -> Adw.ActionRow:
        subtitle = f"{d.ip}  ·  {d.mac}  ·  {d.connection or 'unknown link'}  ·  last seen {local_time(d.last_seen)}"
        row = action_row(d.display_name, subtitle,
                         "emblem-ok-symbolic" if d.trusted else "dialog-question-symbolic",
                         "success" if d.trusted else "warning")
        trusted = Gtk.Switch(active=d.trusted, valign=Gtk.Align.CENTER, tooltip_text="Known device")
        trusted.connect("notify::active", lambda sw, _p: self._trust(d.mac, sw.get_active()))
        row.add_suffix(button("Rename", lambda: self._rename(d)))
        row.add_suffix(button("Activity", lambda: self.ctx.window.show_page("activity", device=d.mac)))
        row.add_suffix(trusted)
        return row

    def _trust(self, mac: str, value: bool) -> None:
        self.ctx.store.set_device_trusted(mac, value)

    def _rename(self, d: DeviceRecord) -> None:
        entry = Gtk.Entry(text=d.label or d.hostname, activates_default=True)
        dialog = Adw.AlertDialog(heading="Name this device", body=f"{d.ip} · {d.mac}")
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save")
        dialog.set_default_response("save")

        def on_response(_d, response: str) -> None:
            if response == "save":
                self.ctx.store.set_device_label(d.mac, entry.get_text())
                self.refresh()

        dialog.connect("response", on_response)
        dialog.present(self.ctx.window)

    def _scan(self) -> None:
        def work() -> int:
            with self.ctx.router() as router:
                devices = router.devices()
            new = self.ctx.store.upsert_devices((x.mac, x.ip, x.hostname, x.connection) for x in devices if x.active)
            return len(new)

        def done(new_count: int) -> None:
            self.ctx.toast(f"Router scanned: {new_count} new device(s)")
            self.refresh()

        self.ctx.run(work, done, "Scanning the router")
