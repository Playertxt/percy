"""Passwords and API keys live in the desktop keyring (Secret Service), never in files."""
from __future__ import annotations

import os

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

SERVICE = "percy"
ROUTER_PASSWORD = "router-password"
ADGUARD_PASSWORD = "adguard-password"
ANTHROPIC_KEY = "anthropic-api-key"


class SecretStoreError(RuntimeError):
    pass


def get_secret(name: str) -> str | None:
    if name == ANTHROPIC_KEY and os.environ.get("ANTHROPIC_API_KEY"):
        return os.environ["ANTHROPIC_API_KEY"]
    try:
        return keyring.get_password(SERVICE, name)
    except KeyringError as exc:
        raise SecretStoreError(f"Could not read '{name}' from the system keyring: {exc}") from exc


def set_secret(name: str, value: str) -> None:
    if not value:
        raise ValueError("Refusing to store an empty secret")
    try:
        keyring.set_password(SERVICE, name, value)
    except KeyringError as exc:
        raise SecretStoreError(f"Could not save '{name}' to the system keyring: {exc}") from exc


def delete_secret(name: str) -> None:
    try:
        keyring.delete_password(SERVICE, name)
    except PasswordDeleteError:
        pass
    except KeyringError as exc:
        raise SecretStoreError(f"Could not delete '{name}' from the system keyring: {exc}") from exc
