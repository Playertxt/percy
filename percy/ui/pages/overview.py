from __future__ import annotations

from percy import secrets
from percy.security.checks import Finding, score
from percy.ui.widgets import Page, action_row, button, spinner_row
from percy.ui.worker import run_async


class OverviewPage(Page):
    title = "Overview"
    icon = "go-home-symbolic"

    def refresh(self) -> None:
        self.clear()
        findings = [Finding(r.check_id, r.severity, r.title, r.detail, r.fix)
                    for r in self.ctx.store.latest_findings()]
        health = self.group("Network health")
        if findings:
            value = score(findings)
            worst = [f for f in findings if f.severity in ("high", "medium")]
            row = action_row(f"Security score: {value}/100",
                             f"{len(worst)} thing(s) to fix" if worst else "Nothing urgent",
                             "security-high-symbolic" if value >= 80 else "security-low-symbolic",
                             "success" if value >= 80 else "warning")
        else:
            row = action_row("No security check yet", "Run one on the Security page.", "security-medium-symbolic")
        row.add_suffix(button("Open", lambda: self.ctx.window.show_page("security")))
        health.add(row)
        devices = self.ctx.store.devices()
        health.add(action_row(f"{len(devices)} devices seen",
                              f"{sum(not d.trusted for d in devices)} not marked as known",
                              "network-workgroup-symbolic"))

        router = self.group("Router", self.ctx.settings.router_host)
        if not secrets.get_secret(secrets.ROUTER_PASSWORD):
            row = action_row("Router password not set", "Add it in Settings to manage the router.",
                             "dialog-password-symbolic", "warning")
            row.add_suffix(button("Settings", lambda: self.ctx.window.show_page("settings"), "suggested-action"))
            router.add(row)
            return
        loading = spinner_row("Talking to the router…")
        router.add(loading)

        def work():
            with self.ctx.router() as r:
                return r.info()

        def done(info) -> None:
            router.remove(loading)
            router.add(action_row(info.model, f"Firmware {info.firmware}  ·  hardware {info.hardware}",
                                  "network-wired-symbolic"))
            router.add(action_row("Internet address", info.wan_ip or "unknown"))
            load = []
            if info.cpu_percent is not None:
                load.append(f"CPU {info.cpu_percent:.0f}%")
            if info.mem_percent is not None:
                load.append(f"memory {info.mem_percent:.0f}%")
            if load:
                router.add(action_row("Load", ", ".join(load)))
            wifi = [name for name, on in (("2.4 GHz", info.wifi_2g), ("5 GHz", info.wifi_5g),
                                          ("guest 2.4", info.guest_2g), ("guest 5", info.guest_5g)) if on]
            router.add(action_row("Wi-Fi on", ", ".join(wifi) or "none reported"))

        def failed(exc: Exception) -> None:
            router.remove(loading)
            router.add(action_row("Could not reach the router", str(exc), "network-error-symbolic", "error"))

        run_async(work, done, failed)
