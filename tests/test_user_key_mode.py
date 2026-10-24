"""Per-user key mode (``MCP_AUTH_MODE=user_key``): login, tokens, and key isolation.

Drives the whole flow in-process through the server's streamable-http ASGI app:
dynamic client registration, ``/authorize`` with PKCE, the login page with a
UniFi API key (the Site Manager API is stubbed with respx), the token exchange,
and finally real MCP tool calls carrying the bearer token. The core assertion is
that every upstream request rides the *calling user's* key, and that two users
never see each other's cached hosts.

All hosts, keys and secrets are obviously-synthetic test values.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib
import json
import secrets
import time
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from unifi_fabric.config import MCPTransportSettings, Settings
from unifi_fabric.oauth_store import OAuthStore
from unifi_fabric.user_keys import current_user_key, key_config_for, user_id_for_key
from unifi_fabric.user_oauth import redirect_uri_allowed

_PUBLIC_URL = "https://unifi-mcp.example.test"
_SECRET = "s" * 40
_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
_API = "https://api.ui.com"

_KEY_ALICE = "alice-unifi-key-0000000000"
_KEY_BOB = "bob-unifi-key-11111111111"

_HOSTS = {
    _KEY_ALICE: [{"id": "console-alice", "name": "Alice-HQ", "reportedState": {}}],
    _KEY_BOB: [{"id": "console-bob", "name": "Bob-Branch", "reportedState": {}}],
}

_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _hosts_response(request: httpx.Request) -> httpx.Response:
    key = request.headers.get("X-API-KEY", "")
    if key not in _HOSTS:
        return httpx.Response(401, json={"message": "unauthorized"})
    return httpx.Response(200, json={"data": _HOSTS[key], "httpStatusCode": 200})


def _env(monkeypatch, tmp_path, **extra: str) -> None:
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_AUTH_MODE", "user_key")
    monkeypatch.setenv("MCP_PUBLIC_URL", _PUBLIC_URL)
    monkeypatch.setenv("MCP_SECRET_KEY", _SECRET)
    monkeypatch.setenv("MCP_OAUTH_DB_PATH", str(tmp_path / "oauth.sqlite3"))
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def user_key_app(monkeypatch, tmp_path):
    """Factory -> (server module, async client) for a user_key-mode server."""

    @contextlib.asynccontextmanager
    async def _make(**extra: str) -> AsyncIterator[tuple[object, httpx.AsyncClient]]:
        _env(monkeypatch, tmp_path, **extra)
        import unifi_fabric.server as srv

        importlib.reload(srv)
        app = srv.mcp.http_app()
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url=_PUBLIC_URL) as client:
                yield srv, client

    yield _make
    # The server builds its FastMCP app at import time; reload it without the
    # user_key environment so later test modules get the default server back.
    for var in ("MCP_AUTH_MODE", "MCP_PUBLIC_URL", "MCP_SECRET_KEY", "MCP_OAUTH_DB_PATH"):
        monkeypatch.delenv(var, raising=False)
    import unifi_fabric.server as srv

    importlib.reload(srv)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


async def _register(client: httpx.AsyncClient, redirect: str = _REDIRECT) -> httpx.Response:
    return await client.post(
        "/register",
        json={
            "redirect_uris": [redirect],
            "client_name": "Claude",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )


async def _start_login(client: httpx.AsyncClient, client_id: str) -> tuple[str, str]:
    """Run /authorize; returns (login page path, PKCE verifier)."""
    verifier, challenge = _pkce()
    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": _REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st-1",
            "resource": f"{_PUBLIC_URL}/mcp",
        },
    )
    assert resp.status_code == 302, resp.text
    login = urlparse(resp.headers["location"])
    assert login.path == "/oauth/login"
    return f"{login.path}?{login.query}", verifier


def _txn(login_path: str) -> str:
    return parse_qs(urlparse(login_path).query)["txn"][0]


async def _login(client: httpx.AsyncClient, api_key: str) -> dict:
    """Full login for one user; returns the token response."""
    reg = (await _register(client)).json()
    login_path, verifier = await _start_login(client, reg["client_id"])
    page = await client.get(login_path)
    assert page.status_code == 200
    assert "UniFi API key" in page.text
    resp = await client.post(
        "/oauth/login",
        data={"txn": _txn(login_path), "name": "Test User", "api_key": api_key, "action": "login"},
    )
    assert resp.status_code == 302, resp.text
    target = urlparse(resp.headers["location"])
    query = parse_qs(target.query)
    assert f"{target.scheme}://{target.netloc}{target.path}" == _REDIRECT
    assert query["state"] == ["st-1"]
    token = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": _REDIRECT,
            "client_id": reg["client_id"],
            "code_verifier": verifier,
            "resource": f"{_PUBLIC_URL}/mcp",
        },
    )
    assert token.status_code == 200, token.text
    body = token.json()
    body["client_id"] = reg["client_id"]
    return body


def _parse_rpc(resp: httpx.Response) -> dict:
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:])
        raise AssertionError(f"no data in SSE response: {resp.text!r}")
    return resp.json()


async def _call_tool(client: httpx.AsyncClient, token: str, name: str, args: dict) -> dict:
    headers = {**_MCP_HEADERS, "Authorization": f"Bearer {token}"}
    init = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "user-key-test", "version": "1.0"},
            },
        },
    )
    assert init.status_code == 200, init.text
    session = init.headers.get("mcp-session-id")
    if session:
        headers["mcp-session-id"] = session
    await client.post(
        "/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    resp = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        },
    )
    assert resp.status_code == 200, resp.text
    return _parse_rpc(resp)


def _tool_text(rpc: dict) -> str:
    return "".join(c.get("text", "") for c in rpc["result"]["content"])


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfig:
    def test_requires_public_url_and_secret(self, monkeypatch):
        monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
        with pytest.raises(ValueError, match="MCP_PUBLIC_URL"):
            MCPTransportSettings(auth_mode="user_key")
        with pytest.raises(ValueError, match="MCP_SECRET_KEY"):
            MCPTransportSettings(auth_mode="user_key", public_url=_PUBLIC_URL)

    def test_rejects_short_secret_and_plain_http(self, monkeypatch):
        monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
        with pytest.raises(ValueError, match="at least 32"):
            MCPTransportSettings(auth_mode="user_key", public_url=_PUBLIC_URL, secret_key="short")
        with pytest.raises(ValueError, match="https"):
            MCPTransportSettings(
                auth_mode="user_key", public_url="http://mcp.example.test", secret_key=_SECRET
            )

    def test_static_client_needs_secret_and_redirects(self, monkeypatch):
        monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
        with pytest.raises(ValueError, match="set together"):
            MCPTransportSettings(
                auth_mode="user_key",
                public_url=_PUBLIC_URL,
                secret_key=_SECRET,
                oauth_client_id="m365-copilot",
            )
        with pytest.raises(ValueError, match="REDIRECT_URIS"):
            MCPTransportSettings(
                auth_mode="user_key",
                public_url=_PUBLIC_URL,
                secret_key=_SECRET,
                oauth_client_id="m365-copilot",
                oauth_client_secret="c" * 40,
            )

    def test_csv_env_lists(self, monkeypatch, tmp_path):
        _env(monkeypatch, tmp_path)
        monkeypatch.setenv("MCP_SECRET_KEY", f"{_SECRET},{'t' * 40}")
        monkeypatch.setenv("MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "claude.ai, .example.test")
        s = MCPTransportSettings()
        assert s.secret_key == [_SECRET, "t" * 40]
        assert s.oauth_allowed_redirect_hosts == ["claude.ai", ".example.test"]
        assert s.user_key_mode

    def test_user_key_overrides_configured_keys(self):
        from unifi_fabric.user_keys import reset_current_user_key, set_current_user_key

        settings = Settings(api_key="env-key")
        token = set_current_user_key(key_config_for(_KEY_ALICE))
        try:
            assert [k.key for k in settings.get_key_configs()] == [_KEY_ALICE]
        finally:
            reset_current_user_key(token)
        assert [k.key for k in settings.get_key_configs()] == ["env-key"]


def test_redirect_uri_allowlist():
    hosts = ["claude.ai", ".consent.azure-apim.net", "localhost"]
    assert redirect_uri_allowed("https://claude.ai/api/mcp/auth_callback", hosts)
    assert redirect_uri_allowed("https://global.consent.azure-apim.net/redirect", hosts)
    assert redirect_uri_allowed("http://localhost:3334/callback", hosts)
    assert not redirect_uri_allowed("http://claude.ai/cb", hosts)
    assert not redirect_uri_allowed("https://evil.example/cb", hosts)
    assert not redirect_uri_allowed("https://claude.ai.evil.example/cb", hosts)


def test_store_encrypts_keys_and_hashes_tokens(tmp_path):
    path = tmp_path / "s.sqlite3"
    store = OAuthStore(str(path), [_SECRET])
    store.upsert_user("u1", "Alice", _KEY_ALICE)
    store.add_token(
        "tok-plain",
        kind="access",
        grant_id="g",
        client_id="c",
        user_id="u1",
        scopes=["unifi"],
        resource=None,
        expires_at=int(time.time()) + 60,
    )
    store.close()
    raw = path.read_bytes()
    assert _KEY_ALICE.encode() not in raw
    assert b"tok-plain" not in raw
    reopened = OAuthStore(str(path), ["x" * 40, _SECRET])  # rotation: old secret still decrypts
    user = reopened.get_user("u1")
    assert user is not None and user.api_key == _KEY_ALICE
    assert OAuthStore(str(path), ["y" * 40]).get_user("u1") is None


# ---------------------------------------------------------------------------
# Live request path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refuses_server_wide_key(user_key_app, monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "server-wide-key")
    with pytest.raises(RuntimeError, match="remove UNIFI_API_KEY"):
        async with user_key_app() as (_srv, client):
            await client.get("/health")


@pytest.mark.asyncio
async def test_mcp_requires_token_and_health_is_open(user_key_app):
    async with user_key_app() as (_srv, client):
        assert (await client.get("/health")).status_code == 200
        resp = await client.post("/mcp", headers=_MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 401
        meta = await client.get("/.well-known/oauth-authorization-server")
        assert meta.status_code == 200
        assert meta.json()["authorization_endpoint"] == f"{_PUBLIC_URL}/authorize"


@pytest.mark.asyncio
async def test_registration_refuses_foreign_redirect(user_key_app):
    async with user_key_app() as (_srv, client):
        resp = await _register(client, "https://evil.example/cb")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_login_rejects_unknown_key(user_key_app):
    async with user_key_app() as (_srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.get(f"{_API}/v1/hosts").mock(side_effect=_hosts_response)
            reg = (await _register(client)).json()
            login_path, _ = await _start_login(client, reg["client_id"])
            resp = await client.post(
                "/oauth/login",
                data={"txn": _txn(login_path), "name": "X", "api_key": "wrong", "action": "login"},
            )
            assert resp.status_code == 401
            assert "aanvaardt deze API key niet" in resp.text


@pytest.mark.asyncio
async def test_each_user_runs_on_their_own_key(user_key_app):
    async with user_key_app() as (_srv, client):
        with respx.mock(assert_all_called=False) as mock:
            hosts_route = mock.get(f"{_API}/v1/hosts").mock(side_effect=_hosts_response)

            alice = await _login(client, _KEY_ALICE)
            bob = await _login(client, _KEY_BOB)

            alice_hosts = _tool_text(
                await _call_tool(client, alice["access_token"], "list_hosts", {})
            )
            bob_hosts = _tool_text(await _call_tool(client, bob["access_token"], "list_hosts", {}))

        assert "Alice-HQ" in alice_hosts and "Bob-Branch" not in alice_hosts
        assert "Bob-Branch" in bob_hosts and "Alice-HQ" not in bob_hosts
        used = {c.request.headers["X-API-KEY"] for c in hosts_route.calls}
        assert used == {_KEY_ALICE, _KEY_BOB}
        assert current_user_key() is None


@pytest.mark.asyncio
async def test_refresh_rotates_and_revalidation_drops_deleted_key(user_key_app, monkeypatch):
    async with user_key_app(MCP_OAUTH_REVALIDATE_INTERVAL="1") as (srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.get(f"{_API}/v1/hosts").mock(side_effect=_hosts_response)
            alice = await _login(client, _KEY_ALICE)

            refreshed = await client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": alice["refresh_token"],
                    "client_id": alice["client_id"],
                },
            )
            assert refreshed.status_code == 200, refreshed.text
            new = refreshed.json()
            reuse = await client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": alice["refresh_token"],
                    "client_id": alice["client_id"],
                },
            )
            assert reuse.status_code in (400, 401)

            # The key is deleted in UniFi; the next check after the interval drops it.
            _HOSTS_BACKUP = _HOSTS.pop(_KEY_ALICE)
            try:
                store = srv.mcp.auth.store
                store.mark_validated(user_id_for_key(_KEY_ALICE), when=time.time() - 60)
                resp = await client.post(
                    "/mcp",
                    headers={**_MCP_HEADERS, "Authorization": f"Bearer {new['access_token']}"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )
                assert resp.status_code == 401
                assert store.get_user(user_id_for_key(_KEY_ALICE)) is None
            finally:
                _HOSTS[_KEY_ALICE] = _HOSTS_BACKUP


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_method", ["client_secret_post", "client_secret_basic"])
async def test_preregistered_client_for_copilot(user_key_app, auth_method):
    """Microsoft 365 Copilot uses a fixed client id + secret instead of registration."""
    client_secret = "c" * 40
    copilot_redirect = "https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect"
    env = {
        "MCP_OAUTH_CLIENT_ID": "m365-copilot",
        "MCP_OAUTH_CLIENT_SECRET": client_secret,
        "MCP_OAUTH_CLIENT_REDIRECT_URIS": copilot_redirect,
        "MCP_OAUTH_CLIENT_AUTH_METHOD": auth_method,
    }
    async with user_key_app(**env) as (_srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.get(f"{_API}/v1/hosts").mock(side_effect=_hosts_response)
            verifier, challenge = _pkce()
            resp = await client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": "m365-copilot",
                    "redirect_uri": copilot_redirect,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "st-2",
                },
            )
            assert resp.status_code == 302, resp.text
            login = urlparse(resp.headers["location"])
            resp = await client.post(
                "/oauth/login",
                data={
                    "txn": parse_qs(login.query)["txn"][0],
                    "name": "Colleague",
                    "api_key": _KEY_BOB,
                    "action": "login",
                },
            )
            assert resp.status_code == 302
            code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": copilot_redirect,
                "code_verifier": verifier,
            }
            kwargs: dict = {}
            # The MCP SDK wants client_id in the form body even with Basic auth.
            data["client_id"] = "m365-copilot"
            if auth_method == "client_secret_basic":
                kwargs["auth"] = ("m365-copilot", client_secret)
            else:
                data["client_secret"] = client_secret
            token = await client.post("/token", data=data, **kwargs)
            assert token.status_code == 200, token.text
            rpc = await _call_tool(client, token.json()["access_token"], "list_hosts", {})
        assert "Bob-Branch" in _tool_text(rpc)
