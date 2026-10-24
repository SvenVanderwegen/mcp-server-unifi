"""The API key of the user behind the current MCP request (``MCP_AUTH_MODE=user_key``).

In per-user mode no UniFi key is configured on the server. Each person logs in
through ``user_oauth`` with their own Site Manager API key; for the duration of
each MCP request, :class:`UserKeyMiddleware` places that key in a context
variable and :meth:`Settings.get_key_configs` returns it as the only configured
key. Everything downstream (client, registry, multi-key routing) then sees a
single-key deployment whose key is the caller's own, so a request can only ever
reach the consoles that person's UniFi account can reach.

The key's label is derived from a digest of the key itself. The client keeps one
HTTP connection per label and the registry one cache per label, so two people
never share a connection or a cached host list.
"""

from __future__ import annotations

import hashlib
from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import APIKeyConfig

_current: ContextVar[APIKeyConfig | None] = ContextVar("unifi_user_key", default=None)


def user_id_for_key(api_key: str) -> str:
    """Stable identifier for a UniFi API key, safe to log and store in the clear."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:24]


def key_config_for(api_key: str) -> APIKeyConfig:
    """The key config a user's requests run under."""
    from .config import APIKeyConfig

    return APIKeyConfig(key=api_key, label=f"user-{user_id_for_key(api_key)}")


def current_user_key() -> APIKeyConfig | None:
    """The calling user's key, or None outside a per-user request."""
    return _current.get()


def set_current_user_key(key: APIKeyConfig | None) -> object:
    """Set the calling user's key; returns a token for :func:`reset_current_user_key`."""
    return _current.set(key)


def reset_current_user_key(token: object) -> None:
    """Restore the previous value after a request."""
    _current.reset(token)  # type: ignore[arg-type]
