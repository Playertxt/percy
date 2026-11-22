from __future__ import annotations

from gi.repository import Adw

from percy.router import RouterSettings, WifiNetwork
from percy.security.checks import classify_wifi_security
from percy.ui.widgets import Page, action_row, apply_plans, button, spinner_row

BAND_SWITCHES = (("host_2g", "2.4 GHz Wi-Fi"), ("host_5g", "5 GHz Wi-Fi"),
                 ("guest_2g", "Guest network 2.4 GHz"), ("guest_5g", "Guest network 5 GHz"))


class WifiPage(Page):
    title = "Wi-Fi"
    icon = "network-wireless-symbolic"

    def refresh(self) -> None:
        self.clear()
        loading_group = self.group("Wi-Fi networks")
        loading = spinner_row("Reading Wi-Fi settings from the router…")
        loading_group.add(loading)

        def work():
            with self.ctx.router() as router:
                return RouterSettings(router).wifi_networks(), router.info()

        def done(result) -> None:
            nets, info = result
            self.clear()
            self._build(nets, info)

        def failed(exc: Exception) -> None:
            loading_group.remove(loading)
            loading_group.add(action_row("Could not read Wi-Fi settings", str(exc), "network-error-symbolic", "error"))

        from percy.ui.worker import run_async

        run_async(work, done, failed)

    def _build(self, nets: list[WifiNetwork], info) -> None:
        switches = self.group("On / off")
        states = {"host_2g": info.wifi_2g, "host_5g": info.wifi_5g,
                  "guest_2g": info.guest_2g, "guest_5g": info.guest_5g}
        for key, label in BAND_SWITCHES:
            row = Adw.SwitchRow(title=label, active=bool(states.get(key)))
            row.connect("notify::active", lambda r, _p, k=key: self._toggle(k, r.get_active()))
            switches.add(row)

        if not nets:
            self.group("Names and passwords").add(action_row(
                "This firmware didn't expose Wi-Fi names", "Run `percy router-probe` and share the output."))
        for net in nets:
            grp = self.group(f"{net.band}: {net.ssid}",
                             f"Security: {net.security or 'unknown'}")
            if net.security and classify_wifi_security(net.security).startswith("weak"):
                grp.add(action_row("Weak encryption", "Switch this network to WPA2-PSK (AES) or WPA3 in the router.",
                                   "dialog-warning-symbolic", "warning"))
            name = Adw.EntryRow(title="Network name", text=net.ssid)
            password = Adw.PasswordEntryRow(title="New password (leave empty to keep)")
            grp.add(name)
            if net.password_field:
                grp.add(password)
            save = button("Save", lambda n=net, e=name, p=password: self._save(n, e.get_text(), p.get_text()),
                          "suggested-action")
            grp.set_header_suffix(save)

    def _toggle(self, key: str, enabled: bool) -> None:
        def work() -> None:
            with self.ctx.router() as router:
                router.set_wifi_enabled(key, enabled)

        self.ctx.run(work, lambda _r: self.ctx.toast("Wi-Fi updated"), "Switching Wi-Fi")

    def _save(self, net: WifiNetwork, ssid: str, password: str) -> None:
        def work():
            with self.ctx.router() as router:
                return RouterSettings(router).plan_wifi(net, ssid=ssid.strip(), password=password or None)

        def planned(plans) -> None:
            if plans:
                self.ctx.toast("Devices on this network will need the new name/password to reconnect")
            apply_plans(self.ctx, plans, self.refresh)

        self.ctx.run(work, planned, "Preparing the change")
