"""Shared UI pieces: app context, page base class, confirm dialog, rows."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from percy import secrets  # noqa: E402
from percy.activity.store import Store  # noqa: E402
from percy.config import Settings, save_settings  # noqa: E402
from percy.router import ChangePlan, Router  # noqa: E402
from percy.ui.worker import run_async  # noqa: E402

SEVERITY_ICON = {
    "high": "dialog-error-symbolic",
    "medium": "dialog-warning-symbolic",
    "low": "dialog-information-symbolic",
    "info": "dialog-information-symbolic",
    "ok": "emblem-ok-symbolic",
}
SEVERITY_CSS = {"high": "error", "medium": "warning", "ok": "success"}


@dataclass
class AppContext:
    settings: Settings
    store: Store
    window: Any = None
    listeners: list[Callable[[], None]] = field(default_factory=list)

    def router(self) -> Router:
        return Router(self.settings.router_host, self.settings.router_username,
                      secrets.get_secret(secrets.ROUTER_PASSWORD))

    def update_settings(self, **changes) -> None:
        self.settings = self.settings.with_changes(**changes)
        save_settings(self.settings)
        for listener in self.listeners:
            listener()

    def toast(self, message: str) -> None:
        if self.window is not None:
            self.window.toast(message)

    def run(self, work: Callable[[], Any], on_done: Callable[[Any], None],
            what: str = "That") -> None:
        run_async(work, on_done, lambda exc: self.toast(f"{what} failed: {exc}"))


class Page(Gtk.Box):
    """A scrollable preferences-style page with a title and refresh hook."""

    title = "Page"
    icon = "applications-system-symbolic"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.ctx = ctx
        self.prefs = Adw.PreferencesPage()
        self.append(self.prefs)
        self.groups: list[Adw.PreferencesGroup] = []

    def group(self, title: str = "", description: str = "") -> Adw.PreferencesGroup:
        grp = Adw.PreferencesGroup(title=title, description=description)
        self.prefs.add(grp)
        self.groups.append(grp)
        return grp

    def clear(self) -> None:
        for grp in self.groups:
            self.prefs.remove(grp)
        self.groups = []

    def refresh(self) -> None:
        """Reload data. Pages override."""


def action_row(title: str, subtitle: str = "", icon: str | None = None, css: str | None = None) -> Adw.ActionRow:
    row = Adw.ActionRow(title=_escape(title), subtitle=_escape(subtitle))
    row.set_subtitle_lines(4)
    if icon:
        image = Gtk.Image.new_from_icon_name(icon)
        if css:
            image.add_css_class(css)
        row.add_prefix(image)
    return row


def button(label: str, on_click: Callable[[], None], css: str | None = None) -> Gtk.Button:
    btn = Gtk.Button(label=label, valign=Gtk.Align.CENTER)
    if css:
        btn.add_css_class(css)
    btn.connect("clicked", lambda _b: on_click())
    return btn


def spinner_row(text: str) -> Adw.ActionRow:
    row = Adw.ActionRow(title=text)
    row.add_prefix(Adw.Spinner())
    return row


def local_time(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d %b %H:%M")
    except ValueError:
        return iso


def _escape(text: str) -> str:
    from gi.repository import GLib

    return GLib.markup_escape_text(text or "")


def confirm_plans(ctx: AppContext, plans: Iterable[ChangePlan], on_yes: Callable[[], None]) -> None:
    plans = list(plans)
    if not plans:
        ctx.toast("Nothing to change")
        return
    body = "\n\n".join(p.title + "\n" + "\n".join("  " + line for line in p.describe()) for p in plans)
    dialog = Adw.AlertDialog(heading="Change router settings?", body=body)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("apply", "Apply")
    dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("cancel")
    dialog.connect("response", lambda _d, resp: on_yes() if resp == "apply" else None)
    dialog.present(ctx.window)


def apply_plans(ctx: AppContext, plans: list[ChangePlan], done: Callable[[], None] | None = None) -> None:
    from percy.router import RouterSettings

    def work() -> None:
        with ctx.router() as router:
            rset = RouterSettings(router)
            for plan in plans:
                rset.apply(plan)

    def finished(_r) -> None:
        ctx.toast("Router updated")
        if done:
            done()

    confirm_plans(ctx, plans, lambda: ctx.run(work, finished, "Changing the router"))
