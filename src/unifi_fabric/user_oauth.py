"""Per-user mode (``MCP_AUTH_MODE=user_key``): this server as its own OAuth server.

Claude (custom connectors) and Microsoft Copilot connect to a remote MCP server
through OAuth 2.1 with PKCE. FastMCP's :class:`OAuthProvider` serves the
standard endpoints (metadata, ``/authorize``, ``/token``, ``/register``,
``/revoke``); this module supplies the provider behind them and the one piece
they leave to the server: the page where the user proves who they are.

That page asks for the user's own UniFi Site Manager API key, checks it against
``api.ui.com``, and only then issues an authorization code. The key is stored
encrypted (see ``oauth_store``) and every MCP request made with the resulting
access token runs on that key (see ``user_keys`` and :class:`UserKeyMiddleware`),
so each person reaches exactly the consoles their own UniFi account can reach,
with their own permissions.

Flow::

    client ──/authorize──▶ provider.authorize() ──302──▶ /oauth/login?txn=…
    user   ──POST API key──▶ GET /v1/hosts ──302──▶ client redirect_uri?code=…
    client ──/token──▶ access + refresh token (subject = digest of the key)
    client ──/mcp, Bearer──▶ UserKeyMiddleware ──▶ tools run on that user's key
"""

from __future__ import annotations

import asyncio
import html
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from fastmcp.server.auth import AccessToken, OAuthProvider
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from . import ui
from .config import MCPTransportSettings
from .oauth_store import OAuthStore
from .user_keys import (
    key_configs_for,
    reset_current_user_key,
    set_current_user_keys,
    user_id_for_keys,
)

_logger = logging.getLogger(__name__)

# The single scope this server knows. Clients that ask for none get it; it
# exists so a hand-configured client (Copilot) has something to put in its
# scope field.
OAUTH_SCOPE = "unifi"

LOGIN_PATH = "/oauth/login"

# A pending login (between /authorize and the form submit) and an issued
# authorization code live this long, in memory only: a restart in the middle of
# a login just means trying again.
PENDING_LOGIN_TTL = 600
AUTH_CODE_TTL = 300

# Rejected keys tolerated on one login attempt before it is discarded.
MAX_LOGIN_ATTEMPTS = 5

# Short timeout for the key check: the user is waiting on the login page.
KEY_CHECK_TIMEOUT = 15.0


# Most keys one login may link: one per UniFi Fabric the user works in.
MAX_KEYS_PER_USER = 25


class KeyRejectedError(Exception):
    """The Site Manager API refused a key.

    ``names`` lists the user's names for the refused keys, when known.
    """

    def __init__(self, message: str = "", names: list[str] | None = None) -> None:
        super().__init__(message)
        self.names = names or []


def parse_keys(text: str) -> list[tuple[str, str]]:
    """Parse the login form's keys field into (name, key) pairs.

    One key per line, optionally prefixed with a name for its Fabric:
    ``VBC: <key>`` or ``VBC = <key>``. A bare key gets a generated name. Blank
    lines and repeated keys are skipped.

    Raises:
        ValueError: More than :data:`MAX_KEYS_PER_USER` keys.
    """
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        name, key = "", line
        for sep in (":", "="):
            head, found, tail = line.partition(sep)
            if found and head.strip() and tail.strip():
                name, key = head.strip(), tail.strip()
                break
        if key in seen:
            continue
        seen.add(key)
        entries.append((name or f"fabric{len(entries) + 1}", key))
    if len(entries) > MAX_KEYS_PER_USER:
        raise ValueError(f"At most {MAX_KEYS_PER_USER} keys")
    return entries


class UniFiUnreachableError(Exception):
    """The Site Manager API could not be asked."""


class UserAuthorizationCode(AuthorizationCode):
    """Authorization code bound to the key the user logged in with."""

    user_id: str


class UserRefreshToken(RefreshToken):
    """Refresh token that remembers its grant, so rotation can revoke its pair."""

    grant_id: str


@dataclass
class _PendingLogin:
    client_id: str
    client_name: str
    params: AuthorizationParams
    expires_at: float
    attempts: int = 0


@dataclass
class _Revalidations:
    """Per-user locks so a burst of requests triggers one revalidation, not N."""

    locks: dict[str, asyncio.Lock] = field(default_factory=dict)

    def lock_for(self, user_id: str) -> asyncio.Lock:
        return self.locks.setdefault(user_id, asyncio.Lock())


def redirect_uri_allowed(uri: str, allowed_hosts: list[str]) -> bool:
    """Whether a dynamically registered client may use this redirect URI.

    The login page hands an authorization code to whatever redirect URI the
    client registered, so open registration would let anyone phish a
    colleague's key through this very page. ``allowed_hosts`` entries match a
    hostname exactly, or any subdomain when they start with ".". Loopback
    redirects may use plain http (native clients listen on localhost);
    everything else must be https.
    """
    parsed = urlparse(uri)
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        return False
    for entry in allowed_hosts:
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry.startswith("."):
            if host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


async def check_api_key(api_base_url: str, api_key: str) -> int:
    """Ask the Site Manager API whether it accepts a key.

    Returns:
        The number of consoles (hosts) the key can see.

    Raises:
        KeyRejectedError: The API answered 401/403.
        UniFiUnreachableError: The API could not be reached or failed.
    """
    try:
        async with httpx.AsyncClient(
            base_url=api_base_url,
            headers={"X-API-KEY": api_key, "Accept": "application/json"},
            timeout=KEY_CHECK_TIMEOUT,
        ) as client:
            resp = await client.get("/v1/hosts")
    except httpx.HTTPError as exc:
        raise UniFiUnreachableError(type(exc).__name__) from None
    if resp.status_code in (401, 403):
        raise KeyRejectedError(f"HTTP {resp.status_code}")
    if resp.is_error:
        raise UniFiUnreachableError(f"HTTP {resp.status_code}")
    try:
        data = resp.json().get("data", [])
    except ValueError:
        raise UniFiUnreachableError("non-JSON response") from None
    return len(data) if isinstance(data, list) else 0


class UserKeyOAuthProvider(OAuthProvider):
    """OAuth authorization server whose users authenticate with a UniFi API key."""

    def __init__(
        self, transport: MCPTransportSettings, store: OAuthStore, api_base_url: str
    ) -> None:
        super().__init__(
            base_url=transport.public_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=[OAUTH_SCOPE],
                default_scopes=[OAUTH_SCOPE],
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.settings = transport
        self.store = store
        self.api_base_url = api_base_url
        self.public_url = transport.public_url.rstrip("/")
        self._pending: dict[str, _PendingLogin] = {}
        self._codes: dict[str, UserAuthorizationCode] = {}
        self._revalidations = _Revalidations()
        self._static_client = self._build_static_client()

    def _build_static_client(self) -> OAuthClientInformationFull | None:
        if not self.settings.oauth_client_id:
            return None
        return OAuthClientInformationFull(
            client_id=self.settings.oauth_client_id,
            client_secret=self.settings.oauth_client_secret,
            client_name="Pre-registered client",
            redirect_uris=[AnyUrl(u) for u in self.settings.oauth_client_redirect_uris],
            token_endpoint_auth_method=self.settings.oauth_client_auth_method,
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=OAUTH_SCOPE,
        )

    # Clients ----------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if self._static_client is not None and secrets.compare_digest(
            client_id.encode(), (self._static_client.client_id or "").encode()
        ):
            return self._static_client
        return self.store.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not redirect_uri_allowed(str(uri), self.settings.oauth_allowed_redirect_hosts):
                _logger.warning("Refused client registration with redirect URI %s", uri)
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=(
                        f"Redirect URI {uri} is not allowed. The server operator can "
                        "add its host to MCP_OAUTH_ALLOWED_REDIRECT_HOSTS."
                    ),
                )
        self.store.save_client(client_info)
        _logger.info(
            "Registered OAuth client %s (%s)",
            client_info.client_id,
            client_info.client_name or "unnamed",
        )

    # Authorization ----------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        self._purge()
        if not params.scopes:
            params = params.model_copy(update={"scopes": [OAUTH_SCOPE]})
        txn = secrets.token_urlsafe(32)
        self._pending[txn] = _PendingLogin(
            client_id=client.client_id or "",
            client_name=client.client_name or "",
            params=params,
            expires_at=time.time() + PENDING_LOGIN_TTL,
        )
        return f"{self.public_url}{LOGIN_PATH}?txn={txn}"

    def pending_login(self, txn: str) -> _PendingLogin | None:
        """A pending login that has not expired, or None."""
        pending = self._pending.get(txn)
        if pending is None or pending.expires_at < time.time():
            self._pending.pop(txn, None)
            return None
        return pending

    async def complete_login(
        self, txn: str, name: str, keys: list[tuple[str, str]] | str
    ) -> tuple[str, int]:
        """Check the submitted keys and finish the authorization.

        ``keys`` holds one (name, key) pair per UniFi Fabric, or a single key.
        Every key must be accepted; one refused key fails the whole login so the
        user never ends up silently missing a Fabric.

        Returns:
            The client redirect URL carrying the authorization code, and the
            number of consoles the keys can see together.

        Raises:
            AuthorizeError: The login attempt is unknown or used up.
            KeyRejectedError: The Site Manager API refused a key.
            UniFiUnreachableError: The Site Manager API could not be reached.
        """
        if isinstance(keys, str):
            keys = [("fabric1", keys)]
        pending = self.pending_login(txn)
        if pending is None:
            raise AuthorizeError(error="invalid_request", error_description="Login expired")
        try:
            hosts = await self._check_keys(keys)
        except KeyRejectedError:
            pending.attempts += 1
            if pending.attempts >= MAX_LOGIN_ATTEMPTS:
                self._pending.pop(txn, None)
                _logger.warning(
                    "Login for client %s abandoned after too many rejected keys",
                    pending.client_id,
                )
            raise
        self._pending.pop(txn, None)

        user_id = user_id_for_keys([key for _name, key in keys])
        self.store.upsert_user(user_id, name, keys)
        _logger.info(
            "User %s (%s) logged in with %d key(s); they see %d console(s)",
            user_id,
            name,
            len(keys),
            hosts,
        )
        return self._grant_code(pending, user_id), hosts

    def _grant_code(self, pending: _PendingLogin, user_id: str) -> str:
        """Issue the authorization code for a finished login; returns the client redirect."""
        code = secrets.token_urlsafe(32)
        params = pending.params
        self._codes[code] = UserAuthorizationCode(
            code=code,
            scopes=params.scopes or [OAUTH_SCOPE],
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=pending.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            user_id=user_id,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    def abandon_login(self, txn: str) -> str | None:
        """Cancel a pending login; returns the client redirect carrying the error."""
        pending = self._pending.pop(txn, None)
        if pending is None:
            return None
        return construct_redirect_uri(
            str(pending.params.redirect_uri),
            error="access_denied",
            error_description="The user cancelled the login",
            state=pending.params.state,
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> UserAuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # Single use: popping before issuing means a replayed code finds
        # nothing, even when two exchanges race.
        code = self._codes.pop(authorization_code.code, None)
        if code is None:
            raise TokenError(error="invalid_grant", error_description="Code already used")
        self.store.purge_expired()
        return self._issue(
            client_id=client.client_id or "",
            user_id=code.user_id,
            scopes=code.scopes,
            resource=code.resource,
            grant_id=secrets.token_urlsafe(16),
        )

    # Tokens -----------------------------------------------------------------

    def _issue(
        self,
        *,
        client_id: str,
        user_id: str,
        scopes: list[str],
        resource: str | None,
        grant_id: str,
    ) -> OAuthToken:
        now = int(time.time())
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        common: dict[str, Any] = {
            "grant_id": grant_id,
            "client_id": client_id,
            "user_id": user_id,
            "scopes": scopes,
            "resource": resource,
        }
        self.store.add_token(
            access,
            kind="access",
            expires_at=now + self.settings.oauth_access_token_ttl,
            **common,
        )
        self.store.add_token(
            refresh,
            kind="refresh",
            expires_at=now + self.settings.oauth_refresh_token_ttl,
            **common,
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",  # noqa: S106 -- token type, not a credential
            expires_in=self.settings.oauth_access_token_ttl,
            scope=" ".join(scopes) if scopes else None,
            refresh_token=refresh,
        )

    async def _check_keys(self, keys: list[tuple[str, str]]) -> int:
        """Check every key concurrently; returns the total console count."""
        results = await asyncio.gather(
            *(check_api_key(self.api_base_url, key) for _name, key in keys),
            return_exceptions=True,
        )
        rejected = [
            name
            for (name, _key), result in zip(keys, results, strict=True)
            if isinstance(result, KeyRejectedError)
        ]
        if rejected:
            raise KeyRejectedError("rejected", names=rejected)
        for result in results:
            if isinstance(result, BaseException):
                raise result
        return sum(r for r in results if isinstance(r, int))

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> UserRefreshToken | None:
        stored = self.store.get_token(refresh_token, "refresh")
        if stored is None or stored.client_id != client.client_id:
            return None
        return UserRefreshToken(
            token=refresh_token,
            client_id=stored.client_id,
            scopes=stored.scopes,
            expires_at=stored.expires_at,
            grant_id=stored.grant_id,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        stored = self.store.get_token(refresh_token.token, "refresh")
        if stored is None:
            raise TokenError(error="invalid_grant", error_description="Refresh token revoked")
        # Rotation: the old refresh token and its access token die with the
        # exchange, so a leaked refresh token stops working once the real
        # client uses it.
        self.store.delete_grant(stored.grant_id)
        if self.store.get_user(stored.user_id) is None:
            raise TokenError(
                error="invalid_grant",
                error_description="The UniFi API key for this user is gone; log in again",
            )
        return self._issue(
            client_id=stored.client_id,
            user_id=stored.user_id,
            scopes=scopes or stored.scopes,
            resource=stored.resource,
            grant_id=stored.grant_id,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        stored = self.store.get_token(token, "access")
        if stored is None:
            return None
        user = self.store.get_user(stored.user_id)
        if user is None:
            return None
        if time.time() - user.validated_at > self.settings.oauth_revalidate_interval:
            async with self._revalidations.lock_for(stored.user_id):
                # Another request may have revalidated while this one waited.
                user = self.store.get_user(stored.user_id)
                if user is None:
                    return None
                if time.time() - user.validated_at > self.settings.oauth_revalidate_interval:
                    if not await self._revalidate(user.user_id, list(user.keys)):
                        return None
        return AccessToken(
            token=token,
            client_id=stored.client_id,
            scopes=stored.scopes,
            expires_at=stored.expires_at,
            resource=stored.resource,
            claims={"sub": stored.user_id, "user_id": stored.user_id, "name": user.name},
        )

    async def _revalidate(self, user_id: str, keys: list[tuple[str, str]]) -> bool:
        """Re-check stored keys. False only when UniFi says a key is no longer valid."""
        try:
            await self._check_keys(keys)
        except KeyRejectedError as exc:
            _logger.info(
                "Stored key(s) %s of user %s rejected by UniFi; forgetting the user",
                ", ".join(exc.names),
                user_id,
            )
            self.store.delete_user(user_id)
            return False
        except UniFiUnreachableError as exc:
            # An outage at api.ui.com must not log everyone out; the tool calls
            # themselves will report the outage.
            _logger.warning("Could not revalidate user %s: %s", user_id, exc)
            return True
        self.store.mark_validated(user_id)
        return True

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        stored = self.store.get_token(token.token, "access") or self.store.get_token(
            token.token, "refresh"
        )
        if stored is not None:
            self.store.delete_grant(stored.grant_id)
        else:
            self.store.delete_token(token.token)

    # Housekeeping -----------------------------------------------------------

    def _purge(self) -> None:
        now = time.time()
        for txn in [t for t, p in self._pending.items() if p.expires_at < now]:
            del self._pending[txn]
        for code in [c for c, a in self._codes.items() if a.expires_at < now]:
            del self._codes[code]


class UserKeyMiddleware(Middleware):
    """Run every MCP request on the calling user's own UniFi keys.

    The transport has already authenticated the bearer token; this looks up the
    keys that token was issued for and places them in the ``user_keys`` context
    for the duration of the request. A request without one fails rather than
    falling back to any other key.
    """

    def __init__(self, store: OAuthStore) -> None:
        self.store = store

    async def on_request(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        token = get_access_token()
        user_id = (token.claims.get("user_id") if token is not None else None) or None
        user = self.store.get_user(user_id) if user_id else None
        if user is None:
            raise PermissionError(
                "No UniFi API key is linked to this session. Reconnect the connector "
                "and log in with your UniFi API key."
            )
        reset = set_current_user_keys(key_configs_for(user.keys))
        try:
            return await call_next(context)
        finally:
            reset_current_user_key(reset)


# Login page -----------------------------------------------------------------

_PAGE_HEADERS = ui.PAGE_HEADERS

_LOGIN_BODY = """<section class="panel" aria-labelledby="t"><div class="panel-body">
  <div><h1 class="title" id="t">UniFi koppelen</h1>
  <p class="lead">{client}</p></div>
  {message}
  <form method="post" action="{action}" class="stack">
    <input type="hidden" name="txn" value="{txn}">
    <div class="field"><label class="label" for="name">Je naam</label>
    <input class="input" id="name" name="name" type="text" autocomplete="name" required
           maxlength="100" value="{name}"></div>
    <div class="field"><label class="label" for="api_key">Persoonlijke UniFi API key(s)</label>
    <textarea class="input" id="api_key" name="api_key" rows="4" autocomplete="off"
              spellcheck="false" required
              placeholder="Eén key per regel, bv.&#10;VBC: abc123&#10;Klant X: def456"></textarea>
    <p class="hint">Werk je in meerdere fabrics? Een key ziet alleen de fabric waarin hij
    gemaakt is, dus zet één key per fabric op een eigen regel. De naam voor de dubbele
    punt is optioneel.</p></div>
    <div class="actions">
      <button class="btn btn--lg btn--ghost" type="submit" name="action" value="cancel"
              formnovalidate>Annuleren</button>
      <button class="btn btn--lg btn--primary" type="submit" name="action"
              value="login">Koppelen</button>
    </div>
  </form>
  <details>
    <summary>Waar vind ik mijn API key?</summary>
    Meld je aan op <em>unifi.ui.com</em>, kies linksboven de juiste fabric, open
    <em>API Keys</em> in het menu links en kies <em>Create API Key</em>. Herhaal dat
    voor elke fabric waarin je werkt.
    De assistent ziet dan precies de consoles die jouw UniFi-account ziet, en alles
    wat hij doet gebeurt met jouw rechten.
  </details>
</div></section>"""


def _render(
    provider: UserKeyOAuthProvider,
    txn: str,
    *,
    message: str = "",
    name: str = "",
    status: int = 200,
) -> HTMLResponse:
    pending = provider.pending_login(txn)
    client = ""
    if pending is not None:
        target = urlparse(str(pending.params.redirect_uri)).hostname or ""
        app = pending.client_name or "Een toepassing"
        client = (
            f"{html.escape(app)} vraagt toegang tot UniFi en stuurt je daarna terug naar "
            f"<strong>{html.escape(target)}</strong>."
        )
    body = _LOGIN_BODY.format(
        client=client,
        message=ui.banner(html.escape(message), "danger") if message else "",
        action=html.escape(LOGIN_PATH),
        txn=html.escape(txn),
        name=html.escape(name),
    )
    return ui.page("UniFi koppelen", body, status=status)


def _expired_page() -> HTMLResponse:
    return ui.message_page(
        "Deze aanmelding is verlopen",
        "Start het koppelen opnieuw vanuit Claude of Copilot.",
        status=400,
    )


def install_login_routes(app: Any, provider: UserKeyOAuthProvider) -> None:
    """Register the login page on a FastMCP app.

    Custom routes are served without bearer authentication, which is the point:
    the user has no token yet.
    """
    ui.install_ui_routes(app)

    @app.custom_route(LOGIN_PATH, methods=["GET"])
    async def login_form(request: Request) -> Response:
        txn = request.query_params.get("txn", "")
        if provider.pending_login(txn) is None:
            return _expired_page()
        return _render(provider, txn)

    @app.custom_route(LOGIN_PATH, methods=["POST"])
    async def login_submit(request: Request) -> Response:
        form = await request.form()
        txn = str(form.get("txn", ""))
        name = str(form.get("name", "")).strip()[:100]
        try:
            keys = parse_keys(str(form.get("api_key", "")))
        except ValueError:
            return _render(
                provider,
                txn,
                message=f"Je kan maximaal {MAX_KEYS_PER_USER} keys tegelijk koppelen.",
                name=name,
                status=400,
            )

        if form.get("action") == "cancel":
            target = provider.abandon_login(txn)
            if target is None:
                return _expired_page()
            return RedirectResponse(target, status_code=302, headers=_PAGE_HEADERS)

        if provider.pending_login(txn) is None:
            return _expired_page()
        if not name or not keys:
            return _render(
                provider, txn, message="Vul je naam en API key in.", name=name, status=400
            )
        try:
            target, _hosts = await provider.complete_login(txn, name, keys)
        except KeyRejectedError as exc:
            if provider.pending_login(txn) is None:
                return _expired_page()
            which = ", ".join(exc.names) if len(keys) > 1 else ""
            message = (
                f"UniFi aanvaardt deze key(s) niet: {which}. Controleer ze en probeer opnieuw."
                if which
                else "UniFi aanvaardt deze API key niet. Controleer hem en probeer opnieuw."
            )
            return _render(provider, txn, message=message, name=name, status=401)
        except AuthorizeError:
            return _expired_page()
        except UniFiUnreachableError as exc:
            _logger.error("Site Manager API unreachable during login: %s", exc)
            return _render(
                provider,
                txn,
                message="UniFi is momenteel niet bereikbaar. Probeer het straks opnieuw.",
                name=name,
                status=503,
            )
        return RedirectResponse(target, status_code=302, headers=_PAGE_HEADERS)
