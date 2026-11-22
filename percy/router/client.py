"""Session with a TP-Link router that speaks the DEV2 "GDPR" web API.

Target: TP-Link XC220-G3v (GPON). Login and encryption come from the
``tplinkrouterc6u`` library's EX client, which handles the same DEV2 data model;
this module adds generic object reads/writes on top so settings can be probed
by name instead of hard-coded per firmware.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from tplinkrouterc6u.client.ex import TPLinkEXClient, TPLinkEXClientGCM

log = logging.getLogger(__name__)

ROOT_STACK = "0,0,0,0,0,0"
ADD_OPERATION = "ao"
WRONG_PASSWORD_HINT = "wrong user or password"


class RouterError(RuntimeError):
    """The router could not be reached or answered unexpectedly."""


class RouterAuthError(RouterError):
    """The router rejected the username or password."""


@dataclass(frozen=True)
class RouterDevice:
    mac: str
    ip: str
    hostname: str
    connection: str  # "wired", "2.4 GHz", "5 GHz", "guest 2.4 GHz", ...
    active: bool


@dataclass(frozen=True)
class RouterInfo:
    model: str
    firmware: str
    hardware: str
    lan_ip: str | None
    wan_ip: str | None
    cpu_percent: float | None
    mem_percent: float | None
    wifi_2g: bool | None
    wifi_5g: bool | None
    guest_2g: bool | None
    guest_5g: bool | None


_CONNECTION_LABELS = {
    "wired": "wired",
    "host_2g": "2.4 GHz",
    "host_5g": "5 GHz",
    "host_5g_2": "5 GHz",
    "host_6g": "6 GHz",
    "guest_2g": "guest 2.4 GHz",
    "guest_5g": "guest 5 GHz",
    "guest_5g_2": "guest 5 GHz",
    "iot_2g": "IoT 2.4 GHz",
    "iot_5g": "IoT 5 GHz",
}

ClientFactory = Callable[[str, str, str, int], Any]


def _default_factories() -> tuple[ClientFactory, ...]:
    def make(cls):
        return lambda host, user, pwd, timeout: cls(host, pwd, username=user, timeout=timeout)

    return (make(TPLinkEXClient), make(TPLinkEXClientGCM))


def format_field(key: str, value: str) -> str:
    """Render one ``"key":"value"`` pair the way the DEV2 API expects, JSON-escaped."""
    return f"{json.dumps(str(key))}:{json.dumps(str(value))}"


class Router:
    """One logged-in session. Use as a context manager so the session is closed."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        timeout: int = 15,
        factories: Iterable[ClientFactory] | None = None,
    ) -> None:
        if not password:
            raise RouterAuthError("No router password set. Enter it in Settings first.")
        self._host = host if host.startswith(("http://", "https://")) else f"http://{host}"
        self._username = username
        self._password = password
        self._timeout = timeout
        self._factories = tuple(factories) if factories is not None else _default_factories()
        self._client: Any = None

    # -- session ---------------------------------------------------------
    def connect(self) -> "Router":
        errors: list[str] = []
        for factory in self._factories:
            client = factory(self._host, self._username, self._password, self._timeout)
            try:
                client.authorize()
            except Exception as exc:  # library raises plain Exceptions/asserts
                message = str(exc) or type(exc).__name__
                # Stop at the first wrong-password answer: retrying with another
                # cipher variant only burns login attempts and can lock the admin page.
                if WRONG_PASSWORD_HINT in message.lower():
                    raise RouterAuthError(
                        "The router rejected the username or password. "
                        "TP-Link fiber routers such as the XC220 log in as 'user', not 'admin'."
                    ) from exc
                errors.append(f"{type(client).__name__}: {message}")
                continue
            self._client = client
            return self
        raise RouterError(
            f"Could not log in to the router as '{self._username}'. A wrong username makes TP-Link fiber "
            "routers send an unreadable reply; try `percy login --username user`. Details: " + " | ".join(errors))

    def close(self) -> None:
        if self._client is None:
            return
        try:
            self._client.logout()
        except Exception as exc:
            log.debug("Router logout failed (ignored): %s", exc)
        self._client = None

    def __enter__(self) -> "Router":
        return self.connect()

    def __exit__(self, *_exc) -> None:
        self.close()

    @property
    def client(self) -> Any:
        if self._client is None:
            raise RouterError("Not connected to the router")
        return self._client

    # -- generic object access ------------------------------------------
    def read(self, oid: str, *, many: bool = True, stack: str = ROOT_STACK,
             attrs: Iterable[str] = ()) -> list[dict]:
        """Read a DEV2 object. ``many`` lists every instance; attrs=() returns all fields."""
        item = self.client.ActItem
        op = item.GL if many else item.GO
        act = item(op, oid, stack, attrs=list(attrs))
        try:
            _, values = self.client.req_act([act])
        except Exception as exc:
            raise RouterError(f"Reading {oid} failed: {exc}") from exc
        data = values[0] if values else None
        if not data:
            # Single-instance objects (Telnet, UPnP, DMZ...) answer only a plain get on the XC220.
            return self.read(oid, many=False, stack=stack, attrs=attrs) if many else []
        rows = data if isinstance(data, list) else [data]
        return [dict(row) for row in rows if isinstance(row, Mapping)]

    def write(self, oid: str, stack: str, changes: Mapping[str, str]) -> None:
        if not changes:
            return
        item = self.client.ActItem
        act = item(item.SET, oid, stack, attrs=[format_field(k, v) for k, v in changes.items()])
        try:
            self.client.req_act([act])
        except Exception as exc:
            raise RouterError(f"Changing {oid} failed: {exc}") from exc

    def add(self, oid: str, parent_stack: str, fields: Mapping[str, str]) -> None:
        """Create a new instance (e.g. a DHCP reservation) under ``parent_stack``."""
        item = self.client.ActItem
        # The XC220 web UI adds with operation "ao" (gdprProxy.js); the library's "add" breaks the connection.
        act = item(ADD_OPERATION, oid, ROOT_STACK, parent_stack, attrs=[format_field(k, v) for k, v in fields.items()])
        try:
            self.client.req_act([act])
        except Exception as exc:
            raise RouterError(f"Adding {oid} failed: {exc}") from exc

    # -- high level ------------------------------------------------------
    def info(self) -> RouterInfo:
        try:
            fw = self.client.get_firmware()
            status = self.client.get_status()
        except Exception as exc:
            raise RouterError(f"Reading router status failed: {exc}") from exc
        return RouterInfo(
            model=getattr(fw, "model", "") or "TP-Link router",
            firmware=getattr(fw, "firmware_version", "") or "",
            hardware=getattr(fw, "hardware_version", "") or "",
            lan_ip=_safe(status, "lan_ipv4_addr"),
            wan_ip=_safe(status, "wan_ipv4_addr"),
            cpu_percent=_percent(_safe(status, "cpu_usage")),
            mem_percent=_percent(_safe(status, "mem_usage")),
            wifi_2g=_safe(status, "wifi_2g_enable"),
            wifi_5g=_safe(status, "wifi_5g_enable"),
            guest_2g=_safe(status, "guest_2g_enable"),
            guest_5g=_safe(status, "guest_5g_enable"),
        )

    def devices(self) -> list[RouterDevice]:
        try:
            status = self.client.get_status()
        except Exception as exc:
            raise RouterError(f"Reading connected devices failed: {exc}") from exc
        result = []
        for dev in getattr(status, "devices", []) or []:
            conn = getattr(getattr(dev, "type", None), "value", "unknown")
            result.append(RouterDevice(
                mac=str(getattr(dev, "macaddr", "") or "").upper().replace("-", ":"),
                ip=str(getattr(dev, "ipaddr", "") or ""),
                hostname=getattr(dev, "hostname", "") or "",
                connection=_CONNECTION_LABELS.get(conn, conn),
                active=bool(getattr(dev, "active", True)),
            ))
        return result

    def set_wifi_enabled(self, band_connection: str, enabled: bool) -> None:
        from tplinkrouterc6u.common.package_enum import Connection

        try:
            self.client.set_wifi(Connection(band_connection), enabled)
        except Exception as exc:
            raise RouterError(f"Switching Wi-Fi {band_connection} failed: {exc}") from exc


def _safe(obj: Any, attr: str) -> Any:
    try:
        value = getattr(obj, attr)
    except Exception:
        return None
    return None if value is None else (value if isinstance(value, (bool, int, float)) else str(value))


def _percent(value: Any) -> float | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return round(number * 100, 1) if number <= 1 else round(number, 1)
