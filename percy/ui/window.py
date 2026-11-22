from __future__ import annotations

from gi.repository import Adw, GLib, Gtk

from percy.ui.pages import PAGES
from percy.ui.widgets import AppContext, Page


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application, ctx: AppContext) -> None:
        super().__init__(application=app, title="Percy", default_width=1100, default_height=760)
        self.ctx = ctx
        ctx.window = self
        self.pages: dict[str, Page] = {key: cls(ctx) for key, cls in PAGES}

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        for key, page in self.pages.items():
            self.stack.add_named(page, key)

        self.sidebar = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.sidebar.add_css_class("navigation-sidebar")
        self._keys = []
        for key, page in self.pages.items():
            row = Gtk.Box(spacing=12, margin_top=8, margin_bottom=8, margin_start=8)
            row.append(Gtk.Image.new_from_icon_name(page.icon))
            row.append(Gtk.Label(label=page.title, xalign=0))
            self.sidebar.append(row)
            self._keys.append(key)
        self.sidebar.connect("row-selected", self._on_select)

        side_view = Adw.ToolbarView()
        side_view.add_top_bar(Adw.HeaderBar(title_widget=Adw.WindowTitle(title="Percy", subtitle="home network")))
        side_view.set_content(Gtk.ScrolledWindow(child=self.sidebar, vexpand=True))

        self.content_title = Adw.WindowTitle(title="Overview")
        header = Adw.HeaderBar(title_widget=self.content_title)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh")
        refresh.connect("clicked", lambda _b: self.current_page().refresh())
        header.pack_end(refresh)
        content_view = Adw.ToolbarView()
        content_view.add_top_bar(header)
        content_view.set_content(self.stack)

        self.content_page = Adw.NavigationPage(child=content_view, title="Overview")
        split = Adw.NavigationSplitView(
            sidebar=Adw.NavigationPage(child=side_view, title="Percy"), content=self.content_page)
        self.toasts = Adw.ToastOverlay(child=split)
        self.set_content(self.toasts)

        bp = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 640sp"))
        bp.add_setter(split, "collapsed", True)
        self.add_breakpoint(bp)
        self.split = split
        self.sidebar.select_row(self.sidebar.get_row_at_index(0))

    def current_page(self) -> Page:
        return self.pages[self.stack.get_visible_child_name() or "overview"]

    def _on_select(self, _box, row) -> None:
        if row is None:
            return
        key = self._keys[row.get_index()]
        page = self.pages[key]
        self.stack.set_visible_child_name(key)
        self.content_title.set_title(page.title)
        self.content_page.set_title(page.title)
        self.split.set_show_content(True)
        page.refresh()

    def show_page(self, key: str, device: str | None = None) -> None:
        if key == "activity" and device is not None:
            self.pages["activity"].device_mac = device
        row = self.sidebar.get_row_at_index(self._keys.index(key))
        if self.sidebar.get_selected_row() is row:
            self.pages[key].refresh()  # same row: row-selected won't fire again
        else:
            self.sidebar.select_row(row)

    def toast(self, message: str) -> None:
        # Toast titles are Pango markup; messages can quote router data, so escape them.
        self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(message), timeout=4))
