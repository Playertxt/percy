"""Build the real window and open every page, off-screen.

Runs only under the GTK Broadway backend (an in-memory display served on
localhost), so it never puts a window on the user's screen:

    gtk4-broadwayd --address 127.0.0.1 --port 18085 :7 &
    GDK_BACKEND=broadway BROADWAY_DISPLAY=:7 pytest tests/test_ui_smoke.py
"""
import os
import time

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("GDK_BACKEND") != "broadway",
                                reason="needs the off-screen Broadway display")


def pump(seconds=1.0):
    from gi.repository import GLib

    ctx = GLib.MainContext.default()
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        ctx.iteration(False)
        time.sleep(0.01)


def test_every_page_builds(store, monkeypatch):
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gio

    from percy import secrets
    from percy.config import Settings
    from percy.monitor import systemd
    from percy.services.docker import Docker
    from percy.ui.pages import PAGES
    from percy.ui.widgets import AppContext
    from percy.ui.window import MainWindow

    # Never touch the real keyring, docker or systemd from a test.
    monkeypatch.setattr(secrets, "get_secret", lambda name: None)
    monkeypatch.setattr(Docker, "state", lambda self, name: "missing")
    monkeypatch.setattr(systemd, "is_active", lambda: False)

    store.upsert_devices([("AA:00:00:00:00:01", "192.168.1.50", "phone", "5 GHz")])
    results = {}

    def on_activate(app):
        ctx = AppContext(settings=Settings(dns_host_ip="192.168.1.104"), store=store)
        win = MainWindow(app, ctx)
        win.present()
        for key, _cls in PAGES:
            win.show_page(key)
            pump(0.6)
            results[key] = win.stack.get_visible_child_name()
        win.show_page("activity", device="AA:00:00:00:00:01")
        pump(0.3)
        results["activity-device"] = win.pages["activity"].device_mac
        win.close()
        app.quit()

    app = Adw.Application(application_id="io.github.percy.SmokeTest",
                          flags=Gio.ApplicationFlags.NON_UNIQUE)
    app.connect("activate", on_activate)
    app.run([])

    assert [results[k] for k, _ in PAGES] == [k for k, _ in PAGES]
    assert results["activity-device"] == "AA:00:00:00:00:01"
