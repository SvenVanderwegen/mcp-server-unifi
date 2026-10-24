"""The API keys of the user behind the current MCP request (``MCP_AUTH_MODE=user_key``).

In per-user mode no UniFi key is configured on the server. Each person logs in
through ``user_oauth`` with their own Site Manager API key, or with one key per
UniFi Fabric when their sites span several (a key only ever sees the consoles of
the Fabric it was created in). For the duration of each MCP request,
:class:`UserKeyMiddleware` places those keys in a context variable and
:meth:`Settings.get_key_configs` returns them as the configured keys.
Everything downstream (client, registry, the upstream multi-key routing) then
sees an ordinary multi-key deployment whose keys are the caller's own, so a
request can only ever reach the consoles that person's UniFi account can reach.

Each key's label is the name the user gave it plus a digest of the key itself.
The client keeps one HTTP connection per label and the registry one cache per
label, so two people never share a connection or a cached host list, even when
they give their keys the same name.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import APIKeyConfig

_current: ContextVar[tuple[APIKeyConfig, ...]] = ContextVar("unifi_user_keys", default=())

_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9_-]+")


def _digest(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def user_id_for_keys(api_keys: Sequence[str]) -> str:
    """Stable identifier for a set of UniFi API keys, safe to log and store in the clear."""
    joined = "\n".join(sorted(_digest(k) for k in api_keys))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:24]


def user_id_for_key(api_key: str) -> str:
    """Identifier for a user who logged in with a single key."""
    return user_id_for_keys([api_key])


def key_label(name: str, api_key: str) -> str:
    """Label for one of a user's keys: their name for it plus a digest of the key."""
    slug = _LABEL_UNSAFE.sub("-", name).strip("-")[:40] or "fabric"
    return f"{slug}-{_digest(api_key)[:8]}"


def key_configs_for(entries: Sequence[tuple[str, str]]) -> tuple[APIKeyConfig, ...]:
    """The key configs a user's requests run under, from (name, key) pairs."""
    from .config import APIKeyConfig

    return tuple(APIKeyConfig(key=key, label=key_label(name, key)) for name, key in entries)


def key_config_for(api_key: str) -> APIKeyConfig:
    """The key config for a single key."""
    return key_configs_for([("fabric", api_key)])[0]


def current_user_keys() -> tuple[APIKeyConfig, ...]:
    """The calling user's keys, or empty outside a per-user request."""
    return _current.get()


def current_user_key() -> APIKeyConfig | None:
    """The calling user's first (default) key, or None outside a per-user request."""
    keys = _current.get()
    return keys[0] if keys else None


def set_current_user_keys(keys: Sequence[APIKeyConfig]) -> object:
    """Set the calling user's keys; returns a token for :func:`reset_current_user_key`."""
    return _current.set(tuple(keys))


def set_current_user_key(key: APIKeyConfig | None) -> object:
    """Set a single key for the calling user."""
    return _current.set((key,) if key is not None else ())


def reset_current_user_key(token: object) -> None:
    """Restore the previous value after a request."""
    _current.reset(token)  # type: ignore[arg-type]
