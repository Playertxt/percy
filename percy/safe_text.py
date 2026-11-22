"""Make text from the network safe to show: device names, SSIDs, UPnP descriptions and
domains can be set by anything on the LAN, so they may carry terminal escape codes."""
from __future__ import annotations

import re

# C0 and C1 control characters except tab and newline (ESC starts terminal escape sequences).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
MAX_FIELD = 500


def clean(text: object, max_len: int = MAX_FIELD) -> str:
    value = _CONTROL.sub("", str(text))
    return value if len(value) <= max_len else value[:max_len] + "…"


class SafeStream:
    """Wraps stdout/stderr so every CLI print drops control characters."""

    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        return self._stream.write(_CONTROL.sub("", text))

    def __getattr__(self, name: str):
        return getattr(self._stream, name)
