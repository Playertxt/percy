from __future__ import annotations

from gi.repository import Adw, Gtk

from percy.config import ADGUARD_IMAGE
from percy.monitor.daemon import adguard_client
from percy.services import adblock_setup
from percy.services.adguard import RECOMMENDED_LISTS
from percy.services.docker import Docker
from percy.ui.widgets import Page, action_row, apply_plans, button, spinner_row
from percy.ui.worker import run_async

POPULAR_APPS = ("tiktok", "instagram", "facebook", "snapchat", "youtube", "netflix", "discord",
                "twitch", "roblox", "minecraft", "steam", "epic_games", "pubg", "fortnite")


class AdblockPage(Page):
    title = "Ad blocker"
    icon = "action-unavailable-symbolic"

    def refresh(self) -> None:
        self.clear()
        status = self.group("AdGuard Home", "Blocks ads, trackers and malware sites for every device on the network.")
        loading = spinner_row("Checking the ad blocker…")
        status.add(loading)

        def work():
            state = Docker().state("percy-adguard")
            client = adguard_client(self.ctx.settings)
            if state != "running" or client is None:
                return state, None, None, None, None
            return (state, client.status(), client.stats(), client.filters(),
                    (client.available_services(), client.blocked_services()))

        def done(result) -> None:
            status.remove(loading)
            self._build(status, *result)

        def failed(exc: Exception) -> None:
            status.remove(loading)
            status.add(action_row("Ad blocker status unavailable", str(exc), "dialog-warning-symbolic", "warning"))
            status.add(self._setup_row())

        run_async(work, done, failed)

    def _setup_row(self) -> Adw.ActionRow:
        row = action_row("Set up the ad blocker",
                         f"Runs AdGuard Home ({ADGUARD_IMAGE}) in Docker on this PC. Nothing is installed on "
                         "the router: its stock firmware can't run add-ons.",
                         "list-add-symbolic")
        row.add_suffix(button("Install", self._install, "suggested-action"))
        return row

    def _build(self, status, state, st, stats, filters, services) -> None:
        if state != "running" or st is None:
            status.add(action_row(f"Not running ({state})", "", "media-playback-stop-symbolic", "warning"))
            status.add(self._setup_row())
            return
        protect = Adw.SwitchRow(title="Blocking on", subtitle=f"AdGuard Home {st.version}",
                                active=st.protection_enabled)
        protect.connect("notify::active", lambda r, _p: self._protect(r.get_active()))
        status.add(protect)
        total = int(stats.get("num_dns_queries", 0))
        blocked = int(stats.get("num_blocked_filtering", 0))
        pct = f" ({blocked * 100 // total}%)" if total else ""
        status.add(action_row(f"{blocked:,} of {total:,} lookups blocked{pct}", "Last 24 hours"))

        net = self.group("Whole network",
                         "Make the router tell every device to use this PC for DNS. Devices pick it up when they "
                         "reconnect. A backup DNS keeps the internet working if this PC is off, but some devices "
                         "will use the backup some of the time and see ads.")
        net.add(action_row("This PC's DNS address", self.ctx.settings.dns_host_ip))
        on_row = action_row("Use for whole network", "Router hands out this PC + backup DNS")
        on_row.add_suffix(button("Apply…", lambda: self._network(True, True), "suggested-action"))
        strict_row = action_row("Use for whole network, no backup", "Best blocking; internet stops if this PC is off")
        strict_row.add_suffix(button("Apply…", lambda: self._network(True, False)))
        off_row = action_row("Stop using for network", "Router goes back to its own DNS")
        off_row.add_suffix(button("Apply…", lambda: self._network(False, False)))
        for r in (on_row, strict_row, off_row):
            net.add(r)

        lists = self.group("Block lists")
        known = {f.get("url") for f in filters or []}
        for f in filters or []:
            lists.add(action_row(f.get("name", "list"), f"{f.get('rules_count', 0):,} rules · {f.get('url')}"))
        for name, url in RECOMMENDED_LISTS:
            if url not in known:
                row = action_row(f"Add: {name}", url, "list-add-symbolic")
                row.add_suffix(button("Add", lambda n=name, u=url: self._add_list(n, u)))
                lists.add(row)

        available, blocked_ids = services or ([], [])
        apps = self.group("Block apps on the whole network", "Blocks every domain the app uses.")
        by_id = {s.get("id"): s for s in available}
        for app_id in POPULAR_APPS:
            if app_id not in by_id:
                continue
            row = Adw.SwitchRow(title=by_id[app_id].get("name", app_id), active=app_id in blocked_ids)
            row.connect("notify::active", lambda r, _p, a=app_id: self._block_app(a, r.get_active(), blocked_ids))
            apps.add(row)

    # -- actions ---------------------------------------------------------
    def _install(self) -> None:
        log = Gtk.Label(xalign=0, wrap=True, selectable=True)
        lines: list[str] = []
        dialog = Adw.AlertDialog(heading="Setting up the ad blocker", body="This takes a minute or two.")
        dialog.set_extra_child(log)
        dialog.add_response("close", "Close")
        dialog.present(self.ctx.window)

        def progress(message: str) -> None:
            from gi.repository import GLib

            lines.append(message)
            GLib.idle_add(lambda: log.set_text("\n".join(lines)) or False)

        def work():
            return adblock_setup.install_adblock(self.ctx.settings, progress)

        def done(settings) -> None:
            self.ctx.update_settings(dns_host_ip=settings.dns_host_ip)
            progress("Done. Now use 'Use for whole network' to protect every device.")
            self.refresh()

        def failed(exc: Exception) -> None:
            progress(f"Failed: {exc}")

        run_async(work, done, failed)

    def _protect(self, enabled: bool) -> None:
        client = adguard_client(self.ctx.settings)
        if client:
            self.ctx.run(lambda: client.set_protection(enabled),
                         lambda _r: self.ctx.toast("Blocking on" if enabled else "Blocking paused"), "Ad blocker")

    def _network(self, use: bool, fallback: bool) -> None:
        def work():
            with self.ctx.router() as router:
                return adblock_setup.plan_network_dns(self.ctx.settings, router, use, fallback)

        self.ctx.run(work, lambda plans: apply_plans(self.ctx, plans, self.refresh), "Preparing the change")

    def _add_list(self, name: str, url: str) -> None:
        client = adguard_client(self.ctx.settings)
        if client:
            self.ctx.run(lambda: client.add_filter(name, url), lambda _r: self.refresh(), "Adding the list")

    def _block_app(self, app_id: str, blocked: bool, current: list[str]) -> None:
        client = adguard_client(self.ctx.settings)
        if not client:
            return
        ids = set(current) | {app_id} if blocked else set(current) - {app_id}
        current[:] = sorted(ids)
        self.ctx.run(lambda: client.set_blocked_services(sorted(ids)),
                     lambda _r: self.ctx.toast(f"{app_id} {'blocked' if blocked else 'allowed'}"), "Blocking the app")
