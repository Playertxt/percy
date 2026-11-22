"""GTK4 / libadwaita desktop app entry point."""
from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw  # noqa: E402

from percy import APP_ID  # noqa: E402
from percy.activity.store import Store  # noqa: E402
from percy.config import DB_FILE, load_settings  # noqa: E402
from percy.ui.widgets import AppContext  # noqa: E402
from percy.ui.window import MainWindow  # noqa: E402


class PercyApp(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID)
        self.ctx: AppContext | None = None

    def do_activate(self) -> None:
        if self.ctx is None:
            self.ctx = AppContext(settings=load_settings(), store=Store(DB_FILE))
        window = self.get_active_window() or MainWindow(self, self.ctx)
        window.present()


def run() -> int:
    return PercyApp().run(sys.argv[:1])
