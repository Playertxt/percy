"""Run blocking work (router, docker, network) off the GTK main thread."""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable

from gi.repository import GLib

log = logging.getLogger(__name__)


def run_async(work: Callable[[], Any], on_done: Callable[[Any], None],
              on_error: Callable[[Exception], None]) -> None:
    def target() -> None:
        try:
            result = work()
        except Exception as exc:  # reported to the UI, never swallowed
            log.exception("Background task failed")
            GLib.idle_add(_once, on_error, exc)
            return
        GLib.idle_add(_once, on_done, result)

    threading.Thread(target=target, daemon=True).start()


def _once(callback: Callable[[Any], None], value: Any) -> bool:
    callback(value)
    return GLib.SOURCE_REMOVE
