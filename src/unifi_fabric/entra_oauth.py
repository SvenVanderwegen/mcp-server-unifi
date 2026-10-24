"""Microsoft sign-in mode (``MCP_AUTH_MODE=entra``): one shared set of UniFi keys.

A Site Manager API key belongs to one Fabric and carries admin rights there, so
asking every colleague to create a key in every Fabric does not scale. In this
mode the server holds the keys itself (``UNIFI_API_KEYS``, one per Fabric) and
people prove who they are with their Microsoft 365 account instead.

The server stays its own OAuth authorization server towards Claude and Copilot
(the same endpoints, client registration and token store as ``user_key`` mode,
see ``user_oauth``); only the step where the user proves who they are changes.
``/authorize`` sends the browser to Microsoft Entra, and the callback accepts a
user only when Entra vouches for them as a member of the configured tenant.

Flow::

    client ──/authorize──▶ 302 login.microsoftonline.com/{tenant}/…/authorize
    user   ──signs in with Microsoft──▶ /oauth/entra/callback?code=…&state=txn
    server ──code──▶ Entra /token ──id_token (tenant checked)──▶ client redirect?code=…
    client ──/token──▶ access + refresh token (subject = the user's Entra object ID)
    client ──/mcp, Bearer──▶ tools run on the server's UNIFI_API_KEYS

Leavers: the user's Entra refresh token is stored encrypted and redeemed again
every ``MCP_OAUTH_REVALIDATE_INTERVAL`` seconds. Once Entra refuses it (account
disabled or deleted, sessions revoked) the user and every token issued to them
are dropped. Which colleagues may sign in at all is decided in Entra: set
"Assignment required" on the app and assign a group.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .config import MCPTransportSettings
from .oauth_store import OAuthStore
from .user_oauth import (
    _PAGE_HEADERS,
    OAUTH_SCOPE,
    PENDING_LOGIN_TTL,
    UserKeyOAuthProvider,
    _PendingLogin,
)

_logger = logging.getLogger(__name__)

CALLBACK_PATH = "/oauth/entra/callback"

ENTRA_AUTHORITY = "https://login.microsoftonline.com"

# offline_access yields the refresh token used to notice leavers.
ENTRA_SCOPES = "openid profile email offline_access"

# The stored "key" entry under which a user's Entra refresh token is kept.
REFRESH_ENTRY = "entra-refresh-token"

ENTRA_TIMEOUT = 15.0

# Token errors that mean Entra no longer vouches for the user.
_REJECTING_ERRORS = {"invalid_grant", "interaction_required", "consent_required"}


class EntraRejectedError(Exception):
    """Entra refused the sign-in or no longer accepts the user's refresh token."""


class EntraUnavailableError(Exception):
    """Entra could not be asked, or the app registration is misconfigured."""


@dataclass
class _EntraPending(_PendingLogin):
    verifier: str = ""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def id_token_claims(id_token: str) -> dict[str, Any]:
    """Claims of an ID token received straight from Entra's token endpoint.

    The token comes over TLS from the token endpoint in exchange for our own
    client secret, so its origin is already established (OpenID Connect Core
    3.1.3.7); the claims are still checked against the tenant and app.
    """
    try:
        payload = id_token.split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as exc:
        raise EntraRejectedError("unreadable ID token") from exc
    if not isinstance(data, dict):
        raise EntraRejectedError("unreadable ID token")
    return data


class EntraOAuthProvider(UserKeyOAuthProvider):
    """OAuth authorization server whose users sign in with Microsoft Entra."""

    def __init__(self, transport: MCPTransportSettings, store: OAuthStore) -> None:
        super().__init__(transport, store, api_base_url="")
        self.tenant_id = transport.entra_tenant_id.lower()
        self.endpoint = f"{ENTRA_AUTHORITY}/{self.tenant_id}/oauth2/v2.0"
        self.issuer = f"{ENTRA_AUTHORITY}/{self.tenant_id}/v2.0"
        self.callback_url = f"{self.public_url}{CALLBACK_PATH}"

    # Authorization ----------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        self._purge()
        if not params.scopes:
            params = params.model_copy(update={"scopes": [OAUTH_SCOPE]})
        txn = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        self._pending[txn] = _EntraPending(
            client_id=client.client_id or "",
            client_name=client.client_name or "",
            params=params,
            expires_at=time.time() + PENDING_LOGIN_TTL,
            verifier=verifier,
        )
        query = urlencode(
            {
                "client_id": self.settings.entra_client_id,
                "response_type": "code",
                "redirect_uri": self.callback_url,
                "response_mode": "query",
                "scope": ENTRA_SCOPES,
                "state": txn,
                "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
                "code_challenge_method": "S256",
            }
        )
        return f"{self.endpoint}/authorize?{query}"

    async def complete_entra_login(self, txn: str, code: str) -> str:
        """Redeem Entra's code, check the user, and finish the authorization.

        Returns:
            The client redirect URL carrying our authorization code.

        Raises:
            AuthorizeError: The login attempt is unknown or expired.
            EntraRejectedError: Entra refused, or the user is not from our tenant.
            EntraUnavailableError: Entra could not be reached or rejected our app.
        """
        pending = self._pending.pop(txn, None)
        if not isinstance(pending, _EntraPending) or pending.expires_at < time.time() or not code:
            raise AuthorizeError(error="invalid_request", error_description="Login expired")
        tokens = await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.callback_url,
                "code_verifier": pending.verifier,
                "scope": ENTRA_SCOPES,
            }
        )
        claims = self._check_claims(id_token_claims(str(tokens.get("id_token", ""))))
        refresh = str(tokens.get("refresh_token", ""))
        if not refresh:
            raise EntraUnavailableError("Entra returned no refresh token; grant offline_access")

        user_id = f"entra-{claims['oid']}"
        name = str(claims.get("name") or claims.get("preferred_username") or claims["oid"])
        upn = str(claims.get("preferred_username") or "")
        label = f"{name} <{upn}>" if upn and upn != name else name
        self.store.upsert_user(user_id, label[:200], [(REFRESH_ENTRY, refresh)])
        _logger.info("User %s (%s) signed in with Microsoft", user_id, label)
        return self._grant_code(pending, user_id)

    def _check_claims(self, claims: dict[str, Any]) -> dict[str, Any]:
        """Accept only an unexpired ID token issued by our tenant for our app."""
        if str(claims.get("tid", "")).lower() != self.tenant_id:
            raise EntraRejectedError("account from another tenant")
        if claims.get("iss") != self.issuer:
            raise EntraRejectedError("unexpected issuer")
        if claims.get("aud") != self.settings.entra_client_id:
            raise EntraRejectedError("ID token for another app")
        if not isinstance(claims.get("exp"), int | float) or claims["exp"] < time.time():
            raise EntraRejectedError("expired ID token")
        if not claims.get("oid"):
            raise EntraRejectedError("ID token without object ID")
        return claims

    async def _token_request(self, data: dict[str, str]) -> dict[str, Any]:
        body = {
            **data,
            "client_id": self.settings.entra_client_id,
            "client_secret": self.settings.entra_client_secret,
        }
        try:
            async with httpx.AsyncClient(timeout=ENTRA_TIMEOUT) as client:
                resp = await client.post(f"{self.endpoint}/token", data=body)
        except httpx.HTTPError as exc:
            raise EntraUnavailableError(type(exc).__name__) from None
        try:
            payload = resp.json()
        except ValueError:
            raise EntraUnavailableError(f"HTTP {resp.status_code}, non-JSON") from None
        if not isinstance(payload, dict):
            raise EntraUnavailableError(f"HTTP {resp.status_code}, unexpected body")
        if resp.is_success:
            return payload
        error = str(payload.get("error", ""))
        if error in _REJECTING_ERRORS:
            raise EntraRejectedError(error)
        # invalid_client and friends: our app registration or secret is wrong
        # (an expired secret, typically). That is the operator's problem, not
        # a verdict on the user.
        raise EntraUnavailableError(f"HTTP {resp.status_code} {error}".strip())

    # Revalidation -----------------------------------------------------------

    async def _revalidate(self, user_id: str, keys: list[tuple[str, str]]) -> bool:
        """Redeem the stored Entra refresh token. False once Entra refuses the user."""
        refresh = dict(keys).get(REFRESH_ENTRY, "")
        user = self.store.get_user(user_id)
        try:
            if not refresh or user is None:
                raise EntraRejectedError("no Entra refresh token stored")
            tokens = await self._token_request(
                {"grant_type": "refresh_token", "refresh_token": refresh, "scope": ENTRA_SCOPES}
            )
        except EntraRejectedError as exc:
            _logger.info("Entra no longer accepts user %s (%s); signing them out", user_id, exc)
            self.store.delete_user(user_id)
            return False
        except EntraUnavailableError as exc:
            # An Entra outage or an expired app secret must not log everyone out
            # on the spot; it is logged loudly so the operator notices.
            _logger.error("Could not revalidate user %s with Entra: %s", user_id, exc)
            return True
        # Entra rotates refresh tokens; keep the newest.
        self.store.upsert_user(
            user_id, user.name, [(REFRESH_ENTRY, str(tokens.get("refresh_token") or refresh))]
        )
        return True


class AuditMiddleware(Middleware):
    """Log who called which tool: the UniFi keys are shared, so UniFi itself cannot tell."""

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        token = get_access_token()
        who = (token.claims.get("name") or token.claims.get("sub")) if token else "anonymous"
        _logger.info("Tool call %s by %s", getattr(context.message, "name", "?"), who)
        return await call_next(context)


# Callback page ----------------------------------------------------------------


def _error_page(title: str, detail: str, status: int) -> HTMLResponse:
    body = (
        '<!doctype html><html lang="nl"><head><meta charset="utf-8"><title>UniFi koppelen</title>'
        '<meta name="viewport" content="width=device-width, initial-scale=1"></head>'
        '<body style="font-family:system-ui,sans-serif;padding:16px;max-width:560px">'
        f"<h1>{html.escape(title)}</h1><p>{html.escape(detail)}</p>"
        "<p>Start het koppelen opnieuw vanuit Claude of Copilot.</p></body></html>"
    )
    return HTMLResponse(body, status_code=status, headers=_PAGE_HEADERS)


def install_entra_routes(app: Any, provider: EntraOAuthProvider) -> None:
    """Register the Entra redirect target on a FastMCP app (served without bearer auth)."""

    @app.custom_route(CALLBACK_PATH, methods=["GET"])
    async def entra_callback(request: Request) -> Response:
        query = request.query_params
        txn = query.get("state", "")
        if query.get("error"):
            # The user cancelled, or Entra refused them (not assigned to the app,
            # blocked by conditional access). Its description says which.
            provider.abandon_login(txn)
            _logger.info("Microsoft sign-in refused: %s", query.get("error"))
            return _error_page(
                "Aanmelden bij Microsoft is niet gelukt",
                query.get("error_description", "") or query.get("error", ""),
                403,
            )
        try:
            target = await provider.complete_entra_login(txn, query.get("code", ""))
        except AuthorizeError:
            return _error_page("Deze aanmelding is verlopen", "", 400)
        except EntraRejectedError as exc:
            _logger.warning("Microsoft sign-in rejected: %s", exc)
            return _error_page(
                "Geen toegang",
                "Meld je aan met je account van de organisatie die deze server beheert.",
                403,
            )
        except EntraUnavailableError as exc:
            _logger.error("Microsoft sign-in failed: %s", exc)
            return _error_page(
                "Microsoft is momenteel niet bereikbaar",
                "Probeer het straks opnieuw. Blijft het mislukken, verwittig dan de beheerder.",
                503,
            )
        return RedirectResponse(target, status_code=302, headers=_PAGE_HEADERS)
