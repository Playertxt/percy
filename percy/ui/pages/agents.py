from __future__ import annotations

from gi.repository import Adw, Gtk

from percy.monitor import systemd
from percy.services import catalog
from percy.services.docker import ContainerSpec, Docker
from percy.ui.widgets import Page, action_row, button, local_time, spinner_row
from percy.ui.worker import run_async


class AgentsPage(Page):
    title = "Agents"
    icon = "system-run-symbolic"

    def refresh(self) -> None:
        self.clear()
        monitor = self.group("Percy monitor",
                             "Runs in the background: copies the ad blocker's log into the activity log every "
                             f"minute and re-runs the security check every {self.ctx.settings.check_interval_min} "
                             "minutes, with a desktop notification for anything new and serious.")
        switch = Adw.SwitchRow(title="Run in the background", subtitle="systemd user service, starts at login",
                               active=systemd.is_active())
        switch.connect("notify::active", lambda r, _p: self._service(r.get_active()))
        monitor.add(switch)

        tools = self.group("Open-source monitors",
                           "Proven tools Percy installs and runs in Docker on this PC (pinned versions).")
        loading = spinner_row("Checking containers…")
        tools.add(loading)
        specs = catalog.all_specs(self.ctx.settings)
        run_async(lambda: [(s, Docker().state(s.name)) for s in specs],
                  lambda states: self._tools(tools, loading, states),
                  lambda exc: self.ctx.toast(f"Docker: {exc}"))

        events = self.group("Recent alerts and events")
        recent = self.ctx.store.events(limit=30)
        if not recent:
            events.add(action_row("No events yet"))
        for ts, kind, message in recent:
            events.add(action_row(message, f"{kind} · {local_time(ts)}"))

    def _tools(self, group: Adw.PreferencesGroup, loading, states: list[tuple[ContainerSpec, str]]) -> None:
        group.remove(loading)
        for spec, state in states:
            row = action_row(f"{spec.title} — {state}", spec.description + f"\n{spec.image}",
                             "emblem-ok-symbolic" if state == "running" else "media-playback-stop-symbolic",
                             "success" if state == "running" else None)
            if state == "missing":
                row.add_suffix(button("Install", lambda s=spec: self._install(s), "suggested-action"))
            elif state == "running":
                row.add_suffix(button("Stop", lambda s=spec: self._docker(Docker().stop, s.name)))
                if spec.web_url:
                    row.add_suffix(button("Dashboard", lambda u=spec.web_url: Gtk.UriLauncher.new(u).launch(
                        self.ctx.window, None, None)))
            else:
                row.add_suffix(button("Start", lambda s=spec: self._docker(Docker().start, s.name)))
            group.add(row)

    def _install(self, spec: ContainerSpec) -> None:
        if spec.key == catalog.ADGUARD:
            self.ctx.window.show_page("adblock")
            return
        self.ctx.toast(f"Installing {spec.title}… (downloads a few hundred MB)")
        self._docker(Docker().install, spec)

    def _docker(self, action, arg) -> None:
        self.ctx.run(lambda: action(arg), lambda _r: self.refresh(), "Docker")

    def _service(self, enabled: bool) -> None:
        self.ctx.run(systemd.install if enabled else systemd.uninstall,
                     lambda _r: self.ctx.toast("Background monitor " + ("on" if enabled else "off")),
                     "Background monitor")
