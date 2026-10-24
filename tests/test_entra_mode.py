"""Microsoft sign-in mode (``MCP_AUTH_MODE=entra``): Entra login, shared keys, leavers.

Drives the flow in-process through the server's ASGI app, with Microsoft Entra's
token endpoint and the Site Manager API stubbed by respx: client registration,
``/authorize`` (which must send the browser to Entra), the Entra callback, the
token exchange, and real tool calls that must ride the server's own
``UNIFI_API_KEYS``.

All tenants, keys, users and secrets are obviously-synthetic test values.
"""

from __future__ import annotations

import base64
import contextlib
import importlib
import json
import logging
import time
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from tests.test_user_key_mode import (
    _API,
    _KEY_ALICE,
    _KEY_BOB,
    _MCP_HEADERS,
    _PUBLIC_URL,
    _REDIRECT,
    _SECRET,
    _call_tool,
    _host_response,
    _hosts_response,
    _pkce,
    _register,
    _tool_text,
)
from unifi_fabric.config import MCPTransportSettings

_TENANT = "00000000-0000-4000-8000-0000000000aa"
_OTHER_TENANT = "00000000-0000-4000-8000-0000000000bb"
_APP_ID = "00000000-0000-4000-8000-0000000000cc"
_APP_SECRET = "entra-app-secret-for-tests"
_TOKEN_URL = f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"

_SHARED_KEYS = json.dumps(
    [{"key": _KEY_ALICE, "label": "fabric-a"}, {"key": _KEY_BOB, "label": "fabric-b"}]
)

_ENTRA_ENV = {
    "FASTMCP_TRANSPORT": "streamable-http",
    "MCP_AUTH_MODE": "entra",
    "MCP_PUBLIC_URL": _PUBLIC_URL,
    "MCP_SECRET_KEY": _SECRET,
    "MCP_ENTRA_TENANT_ID": _TENANT,
    "MCP_ENTRA_CLIENT_ID": _APP_ID,
    "MCP_ENTRA_CLIENT_SECRET": _APP_SECRET,
    "UNIFI_API_KEYS": _SHARED_KEYS,
}


def _id_token(**overrides: object) -> str:
    claims: dict[str, object] = {
        "iss": f"https://login.microsoftonline.com/{_TENANT}/v2.0",
        "aud": _APP_ID,
        "tid": _TENANT,
        "oid": "11111111-1111-4111-8111-111111111111",
        "name": "Test Colleague",
        "preferred_username": "colleague@example.test",
        "exp": int(time.time()) + 3600,
    }
    claims.update(overrides)

    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'RS256', 'typ': 'JWT'})}.{part(claims)}.c2ln"


class _Entra:
    """Stub of Entra's token endpoint; ``refresh_ok`` flips to False for a leaver."""

    def __init__(self, id_token: str) -> None:
        self.id_token = id_token
        self.refresh_ok = True
        self.requests: list[dict[str, list[str]]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode())
        self.requests.append(form)
        assert form["client_secret"] == [_APP_SECRET]
        if form["grant_type"] == ["refresh_token"] and not self.refresh_ok:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(
            200,
            json={
                "access_token": "graph-token",
                "id_token": self.id_token,
                "refresh_token": f"entra-refresh-{len(self.requests)}",
            },
        )


@pytest.fixture
def entra_app(monkeypatch, tmp_path):
    """Factory -> (server module, async client) for an entra-mode server."""

    @contextlib.asynccontextmanager
    async def _make(**extra: str) -> AsyncIterator[tuple[object, httpx.AsyncClient]]:
        for k, v in {**_ENTRA_ENV, "MCP_OAUTH_DB_PATH": str(tmp_path / "o.db"), **extra}.items():
            monkeypatch.setenv(k, v)
        import unifi_fabric.server as srv

        importlib.reload(srv)
        srv._settings = None
        app = srv.mcp.http_app()
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url=_PUBLIC_URL) as client:
                yield srv, client

    yield _make
    for var in [*_ENTRA_ENV, "MCP_OAUTH_DB_PATH", "MCP_OAUTH_REVALIDATE_INTERVAL"]:
        if var != "FASTMCP_TRANSPORT":
            monkeypatch.delenv(var, raising=False)
    import unifi_fabric.server as srv

    importlib.reload(srv)
    srv._settings = None


async def _sign_in(client: httpx.AsyncClient) -> tuple[httpx.Response, dict, str]:
    """Run /authorize and the Entra callback; returns (callback response, client, verifier)."""
    reg = (await _register(client)).json()
    verifier, challenge = _pkce()
    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": reg["client_id"],
            "redirect_uri": _REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st-1",
            "resource": f"{_PUBLIC_URL}/mcp",
        },
    )
    assert resp.status_code == 302, resp.text
    entra = urlparse(resp.headers["location"])
    assert entra.netloc == "login.microsoftonline.com"
    assert entra.path == f"/{_TENANT}/oauth2/v2.0/authorize"
    query = parse_qs(entra.query)
    assert query["client_id"] == [_APP_ID]
    assert query["redirect_uri"] == [f"{_PUBLIC_URL}/oauth/entra/callback"]
    assert query["code_challenge_method"] == ["S256"]
    callback = await client.get(
        "/oauth/entra/callback", params={"code": "entra-code", "state": query["state"][0]}
    )
    return callback, reg, verifier


async def _login(client: httpx.AsyncClient) -> dict:
    callback, reg, verifier = await _sign_in(client)
    assert callback.status_code == 302, callback.text
    target = urlparse(callback.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == _REDIRECT
    token = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": parse_qs(target.query)["code"][0],
            "redirect_uri": _REDIRECT,
            "client_id": reg["client_id"],
            "code_verifier": verifier,
            "resource": f"{_PUBLIC_URL}/mcp",
        },
    )
    assert token.status_code == 200, token.text
    return {**token.json(), "client_id": reg["client_id"]}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_config_requires_entra_app_and_a_real_tenant(monkeypatch):
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    base = {"auth_mode": "entra", "public_url": _PUBLIC_URL, "secret_key": _SECRET}
    with pytest.raises(ValueError, match="MCP_ENTRA_TENANT_ID"):
        MCPTransportSettings(**base)
    app = {"entra_client_id": _APP_ID, "entra_client_secret": _APP_SECRET}
    for tenant in ("common", "organizations", "consumers"):
        with pytest.raises(ValueError, match="GUID"):
            MCPTransportSettings(**base, **app, entra_tenant_id=tenant)
    with pytest.raises(ValueError, match="MCP_SECRET_KEY"):
        MCPTransportSettings(
            auth_mode="entra", public_url=_PUBLIC_URL, entra_tenant_id=_TENANT, **app
        )
    s = MCPTransportSettings(**base, **app, entra_tenant_id=_TENANT)
    assert s.entra_mode and not s.user_key_mode


@pytest.mark.asyncio
async def test_entra_mode_starts_without_keys(entra_app):
    # Keys can be added on /admin later, so an empty UNIFI_API_KEYS is not fatal.
    async with entra_app(UNIFI_API_KEYS="[]") as (_srv, client):
        assert (await client.get("/health")).status_code == 200


# ---------------------------------------------------------------------------
# Sign-in and the shared keys
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_colleague_signs_in_and_uses_every_shared_key(entra_app, caplog):
    entra = _Entra(_id_token())
    async with entra_app() as (srv, client):
        assert (
            await client.post("/mcp", headers=_MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1})
        ).status_code == 401
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_TOKEN_URL).mock(side_effect=entra)
            hosts_route = mock.get(f"{_API}/v1/hosts").mock(side_effect=_hosts_response)
            host_route = mock.get(url__regex=rf"{_API}/v1/hosts/.+").mock(
                side_effect=_host_response
            )
            token = await _login(client)
            # The lifespan's logging.basicConfig(force=True) drops caplog's root
            # handler, so listen on the module logger itself.
            audit = logging.getLogger("unifi_fabric.entra_oauth")
            audit.addHandler(caplog.handler)
            try:
                hosts = _tool_text(
                    await _call_tool(client, token["access_token"], "list_hosts", {})
                )
                bob_host = _tool_text(
                    await _call_tool(
                        client, token["access_token"], "get_host", {"host": "Bob-Branch"}
                    )
                )
            finally:
                audit.removeHandler(caplog.handler)

    # The code exchange went to Entra with our PKCE verifier and secret.
    assert entra.requests[0]["grant_type"] == ["authorization_code"]
    assert entra.requests[0]["code"] == ["entra-code"]
    assert entra.requests[0]["code_verifier"]
    # Both shared Fabric keys serve every colleague.
    assert "Alice-HQ" in hosts and "Bob-Branch" in hosts
    assert "console-bob" in bob_host
    assert host_route.calls
    assert {c.request.headers["X-API-KEY"] for c in host_route.calls} == {_KEY_BOB}
    assert {c.request.headers["X-API-KEY"] for c in hosts_route.calls} == {_KEY_ALICE, _KEY_BOB}
    # UniFi only sees the shared key, so the server logs who did what.
    assert "Tool call get_host by Test Colleague <colleague@example.test>" in caplog.text
    # Entra's refresh token is stored encrypted, never in the clear.
    user = srv.mcp.auth.store.get_user("entra-11111111-1111-4111-8111-111111111111")
    assert user is not None and user.keys[0][1].startswith("entra-refresh-")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"tid": _OTHER_TENANT, "iss": f"https://login.microsoftonline.com/{_OTHER_TENANT}/v2.0"},
        {"aud": "some-other-app"},
        {"exp": int(time.time()) - 10},
        {"oid": ""},
    ],
    ids=["other-tenant", "other-app", "expired", "no-oid"],
)
async def test_sign_in_refuses_tokens_not_meant_for_us(entra_app, overrides):
    async with entra_app() as (_srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_TOKEN_URL).mock(side_effect=_Entra(_id_token(**overrides)))
            callback, _reg, _verifier = await _sign_in(client)
    assert callback.status_code == 403
    assert "Geen toegang" in callback.text


@pytest.mark.asyncio
async def test_entra_error_and_replayed_state(entra_app):
    async with entra_app() as (_srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_TOKEN_URL).mock(side_effect=_Entra(_id_token()))
            reg = (await _register(client)).json()
            _verifier, challenge = _pkce()
            resp = await client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": reg["client_id"],
                    "redirect_uri": _REDIRECT,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
            )
            state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
            # Not assigned to the app: Entra sends the user back with an error.
            refused = await client.get(
                "/oauth/entra/callback",
                params={
                    "error": "access_denied",
                    "error_description": "AADSTS50105: <not assigned>",
                    "state": state,
                },
            )
            assert refused.status_code == 403
            assert "AADSTS50105: &lt;not assigned&gt;" in refused.text
            # The login is gone: the same state cannot be completed afterwards.
            replay = await client.get(
                "/oauth/entra/callback", params={"code": "entra-code", "state": state}
            )
            assert replay.status_code == 400


@pytest.mark.asyncio
async def test_entra_unreachable_and_misconfigured_app(entra_app):
    async with entra_app() as (_srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_TOKEN_URL).mock(
                return_value=httpx.Response(401, json={"error": "invalid_client"})
            )
            callback, _reg, _verifier = await _sign_in(client)
            assert callback.status_code == 503
            mock.post(_TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
            callback, _reg, _verifier = await _sign_in(client)
            assert callback.status_code == 503


@pytest.mark.asyncio
async def test_leaver_is_signed_out_at_the_next_revalidation(entra_app):
    entra = _Entra(_id_token())
    async with entra_app(MCP_OAUTH_REVALIDATE_INTERVAL="1") as (srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_TOKEN_URL).mock(side_effect=entra)
            mock.get(f"{_API}/v1/hosts").mock(side_effect=_hosts_response)
            token = await _login(client)
            store = srv.mcp.auth.store
            user_id = "entra-11111111-1111-4111-8111-111111111111"
            headers = {**_MCP_HEADERS, "Authorization": f"Bearer {token['access_token']}"}
            ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}

            # Still employed: Entra redeems the refresh token and rotates it.
            store.mark_validated(user_id, when=time.time() - 60)
            assert (await client.post("/mcp", headers=headers, json=ping)).status_code != 401
            assert entra.requests[-1]["grant_type"] == ["refresh_token"]
            assert entra.requests[-1]["refresh_token"] == ["entra-refresh-1"]
            assert store.get_user(user_id).keys[0][1] == "entra-refresh-2"

            # Account disabled in Entra: the next check signs them out.
            entra.refresh_ok = False
            store.mark_validated(user_id, when=time.time() - 60)
            assert (await client.post("/mcp", headers=headers, json=ping)).status_code == 401
            assert store.get_user(user_id) is None


@pytest.mark.asyncio
async def test_entra_outage_keeps_users_signed_in(entra_app):
    async with entra_app(MCP_OAUTH_REVALIDATE_INTERVAL="1") as (srv, client):
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post(_TOKEN_URL).mock(side_effect=_Entra(_id_token()))
            token = await _login(client)
            route.mock(side_effect=httpx.ConnectError("down"))
            store = srv.mcp.auth.store
            user_id = "entra-11111111-1111-4111-8111-111111111111"
            store.mark_validated(user_id, when=time.time() - 60)
            resp = await client.post(
                "/mcp",
                headers={**_MCP_HEADERS, "Authorization": f"Bearer {token['access_token']}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert resp.status_code != 401
            assert store.get_user(user_id) is not None


def test_unreadable_id_token():
    from unifi_fabric.entra_oauth import EntraRejectedError, id_token_claims

    for bad in ("", "not-a-jwt", "a.bm90LWpzb24.c", "a.WzFd.c"):
        with pytest.raises(EntraRejectedError):
            id_token_claims(bad)
