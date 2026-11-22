from __future__ import annotations

from gi.repository import Adw

from percy import secrets
from percy.router import Router
from percy.services.adblock_setup import SetupError, detect_lan_ip
from percy.ui.widgets import Page, button


class SettingsPage(Page):
    title = "Settings"
    icon = "emblem-system-symbolic"

    def refresh(self) -> None:
        self.clear()
        s = self.ctx.settings
        router = self.group("Router login", "The password is kept in your desktop keyring, never in a file.")
        host = Adw.EntryRow(title="Router address", text=s.router_host)
        user = Adw.EntryRow(title="Admin username", text=s.router_username)
        password = Adw.PasswordEntryRow(title="Admin password" + (" (saved)" if self._has(secrets.ROUTER_PASSWORD) else ""))
        for row in (host, user, password):
            router.add(row)
        router.set_header_suffix(button("Save and test", lambda: self._login(
            host.get_text().strip(), user.get_text().strip(), password.get_text()), "suggested-action"))

        dns = self.group("Ad blocker")
        dns_ip = Adw.EntryRow(title="This PC's LAN address (DNS for the network)", text=s.dns_host_ip,
                              show_apply_button=True)
        dns_ip.connect("apply", lambda r: self.ctx.update_settings(dns_host_ip=r.get_text().strip()))
        dns_ip.add_suffix(button("Detect", lambda: self._detect(dns_ip)))
        fallback = Adw.EntryRow(title="Backup DNS", text=s.fallback_dns, show_apply_button=True)
        fallback.connect("apply", lambda r: self.ctx.update_settings(fallback_dns=r.get_text().strip()))
        dns.add(dns_ip)
        dns.add(fallback)

        mon = self.group("Monitoring")
        interval = Adw.SpinRow.new_with_range(5, 720, 5)
        interval.set_title("Security check every (minutes)")
        interval.set_value(s.check_interval_min)
        interval.connect("notify::value", lambda r, _p: self.ctx.update_settings(check_interval_min=int(r.get_value())))
        keep = Adw.SpinRow.new_with_range(1, 365, 1)
        keep.set_title("Keep activity log (days)")
        keep.set_value(s.activity_retention_days)
        keep.connect("notify::value", lambda r, _p: self.ctx.update_settings(activity_retention_days=int(r.get_value())))
        notify = Adw.SwitchRow(title="Desktop notifications", active=s.notify)
        notify.connect("notify::active", lambda r, _p: self.ctx.update_settings(notify=r.get_active()))
        for row in (interval, keep, notify):
            mon.add(row)

        ai = self.group("Claude", "Optional. Used only when you press 'Explain' on the Security page.")
        enable = Adw.SwitchRow(title="Enable Claude explanations", active=s.claude_summary)
        enable.connect("notify::active", lambda r, _p: self.ctx.update_settings(claude_summary=r.get_active()))
        key = Adw.PasswordEntryRow(title="Anthropic API key" + (" (saved)" if self._has(secrets.ANTHROPIC_KEY) else ""),
                                   show_apply_button=True)
        key.connect("apply", lambda r: self._save_secret(secrets.ANTHROPIC_KEY, r.get_text().strip(), "API key"))
        model = Adw.EntryRow(title="Model", text=s.claude_model, show_apply_button=True)
        model.connect("apply", lambda r: self.ctx.update_settings(claude_model=r.get_text().strip()))
        for row in (enable, key, model):
            ai.add(row)

    @staticmethod
    def _has(name: str) -> bool:
        try:
            return bool(secrets.get_secret(name))
        except secrets.SecretStoreError:
            return False

    def _save_secret(self, name: str, value: str, label: str) -> None:
        try:
            secrets.set_secret(name, value)
        except (ValueError, secrets.SecretStoreError) as exc:
            self.ctx.toast(str(exc))
            return
        self.ctx.toast(f"{label} saved")
        self.refresh()

    def _login(self, host: str, user: str, password: str) -> None:
        from percy.services.catalog import validate_lan_ip

        try:  # the password is sent to this address, so only a private LAN IPv4 is accepted
            host = validate_lan_ip(host)
        except ValueError as exc:
            self.ctx.toast(str(exc))
            return
        password = password or secrets.get_secret(secrets.ROUTER_PASSWORD) or ""

        def work():
            with Router(host, user, password) as router:
                return router.info()

        def done(info) -> None:
            from percy.security.runner import clear_auth_failure

            secrets.set_secret(secrets.ROUTER_PASSWORD, password)
            clear_auth_failure(self.ctx.store)
            self.ctx.update_settings(router_host=host, router_username=user)
            self.ctx.toast(f"Logged in to {info.model}")
            self.refresh()

        self.ctx.run(work, done, "Router login")

    def _detect(self, row: Adw.EntryRow) -> None:
        try:
            ip = detect_lan_ip(self.ctx.settings)
        except SetupError as exc:
            self.ctx.toast(str(exc))
            return
        row.set_text(ip)
        self.ctx.update_settings(dns_host_ip=ip)
