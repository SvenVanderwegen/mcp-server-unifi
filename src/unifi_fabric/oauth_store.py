"""Persistent state for per-user mode: OAuth clients, user keys and tokens.

One SQLite file holds everything that must survive a restart:

- registered OAuth clients (dynamic client registration),
- each user's UniFi Site Manager API key, encrypted at rest,
- issued access and refresh tokens.

Tokens are stored as SHA-256 digests, never in the clear: a copy of the file
must not be enough to call the MCP endpoint as someone. The UniFi API keys
cannot be hashed (they are sent to api.ui.com on every call), so they are
encrypted with Fernet under MCP_SECRET_KEY instead. The file alone then yields
no usable credential; the file plus the secret does, so keep the two apart
(volume vs. stack env).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import sqlite3
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from mcp.shared.auth import OAuthClientInformationFull

_logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    info TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL,
    validated_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    digest TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_user ON tokens (user_id);
CREATE INDEX IF NOT EXISTS tokens_grant ON tokens (grant_id);
"""


def token_digest(token: str) -> str:
    """Digest under which a token is stored and looked up."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _fernet_for(secret: str) -> Fernet:
    # Fernet wants 32 url-safe base64 bytes; deriving them lets the operator
    # use any sufficiently long string (openssl rand -hex 32) as the secret.
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


@dataclass(frozen=True)
class StoredUser:
    """A user's UniFi key as stored after a successful login."""

    user_id: str
    name: str
    api_key: str
    validated_at: float


@dataclass(frozen=True)
class StoredToken:
    """An issued access or refresh token, looked up by its digest."""

    kind: str
    grant_id: str
    client_id: str
    user_id: str
    scopes: list[str]
    resource: str | None
    expires_at: int


class OAuthStore:
    """Thread-safe SQLite store for the OAuth state.

    Every operation is a short local query, so callers on the event loop call
    it directly; a lock serializes access because one connection is shared.
    """

    def __init__(self, path: str, secret_keys: Iterable[str]) -> None:
        secrets_list = [s for s in secret_keys if s]
        if not secrets_list:
            raise ValueError("OAuthStore requires at least one secret key")
        self._fernet = MultiFernet([_fernet_for(s) for s in secrets_list])

        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        _logger.info("OAuth store opened at %s", path)

    def close(self) -> None:
        """Close the underlying database."""
        with self._lock:
            self._db.close()

    # Clients ----------------------------------------------------------------

    def save_client(self, client: OAuthClientInformationFull) -> None:
        """Store a dynamically registered client."""
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO clients (client_id, info, created_at) VALUES (?, ?, ?)",
                (client.client_id, client.model_dump_json(), time.time()),
            )

    def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Load a registered client, or None."""
        with self._lock:
            row = self._db.execute(
                "SELECT info FROM clients WHERE client_id = ?", (client_id,)
            ).fetchone()
        if row is None:
            return None
        return OAuthClientInformationFull.model_validate(json.loads(row[0]))

    # Users ------------------------------------------------------------------

    def upsert_user(self, user_id: str, name: str, api_key: str) -> None:
        """Store (or replace) a user's display name and encrypted API key."""
        encrypted = self._fernet.encrypt(api_key.encode("utf-8")).decode("ascii")
        now = time.time()
        with self._lock:
            self._db.execute(
                "INSERT INTO users (user_id, name, api_key, validated_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET "
                "name = excluded.name, api_key = excluded.api_key, "
                "validated_at = excluded.validated_at, updated_at = excluded.updated_at",
                (user_id, name, encrypted, now, now),
            )

    def get_user(self, user_id: str) -> StoredUser | None:
        """Load a user with the API key decrypted, or None.

        A key that no configured secret can decrypt (the secret was changed
        without keeping the old one for rotation) reads as no user: the client
        is sent back through the login page rather than failing.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT user_id, name, api_key, validated_at FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            api_key = self._fernet.decrypt(row[2].encode("ascii")).decode("utf-8")
        except InvalidToken:
            _logger.warning(
                "Stored API key for user %s cannot be decrypted with the configured "
                "MCP_SECRET_KEY; the user must log in again",
                user_id,
            )
            return None
        return StoredUser(user_id=row[0], name=row[1], api_key=api_key, validated_at=row[3])

    def mark_validated(self, user_id: str, when: float | None = None) -> None:
        """Record that the user's key was just accepted by the Site Manager API."""
        with self._lock:
            self._db.execute(
                "UPDATE users SET validated_at = ? WHERE user_id = ?",
                (time.time() if when is None else when, user_id),
            )

    def delete_user(self, user_id: str) -> None:
        """Forget a user's key and every token issued to them."""
        with self._lock:
            self._db.execute("DELETE FROM tokens WHERE user_id = ?", (user_id,))
            self._db.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

    # Tokens -----------------------------------------------------------------

    def add_token(
        self,
        token: str,
        *,
        kind: str,
        grant_id: str,
        client_id: str,
        user_id: str,
        scopes: list[str],
        resource: str | None,
        expires_at: int,
    ) -> None:
        """Store an issued token under its digest."""
        with self._lock:
            self._db.execute(
                "INSERT INTO tokens (digest, kind, grant_id, client_id, user_id, scopes, "
                "resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    token_digest(token),
                    kind,
                    grant_id,
                    client_id,
                    user_id,
                    " ".join(scopes),
                    resource,
                    expires_at,
                ),
            )

    def get_token(self, token: str, kind: str) -> StoredToken | None:
        """Look up an unexpired token of the given kind, or None."""
        with self._lock:
            row = self._db.execute(
                "SELECT kind, grant_id, client_id, user_id, scopes, resource, expires_at "
                "FROM tokens WHERE digest = ? AND kind = ?",
                (token_digest(token), kind),
            ).fetchone()
        if row is None:
            return None
        stored = StoredToken(
            kind=row[0],
            grant_id=row[1],
            client_id=row[2],
            user_id=row[3],
            scopes=row[4].split() if row[4] else [],
            resource=row[5],
            expires_at=row[6],
        )
        if stored.expires_at < time.time():
            return None
        return stored

    def delete_grant(self, grant_id: str) -> None:
        """Revoke every token of one grant (an access/refresh pair lineage)."""
        with self._lock:
            self._db.execute("DELETE FROM tokens WHERE grant_id = ?", (grant_id,))

    def delete_token(self, token: str) -> None:
        """Revoke a single token."""
        with self._lock:
            self._db.execute("DELETE FROM tokens WHERE digest = ?", (token_digest(token),))

    def purge_expired(self) -> int:
        """Drop expired tokens; returns how many were removed."""
        with self._lock:
            cursor = self._db.execute("DELETE FROM tokens WHERE expires_at < ?", (time.time(),))
        return cursor.rowcount
