"""Admin page for the shared Fabric keys (``MCP_AUTH_MODE=entra``).

The ``entra_app`` fixture comes from ``test_entra_mode`` via ``conftest``.

The server starts with one key from the stack environment (Fabric A); an admin
signs in with Microsoft (Entra stubbed with respx, ID token carrying the admin
app role), adds Fabric B's key on /admin, and from the next MCP request on both
Fabrics' consoles are served. All values are obviously-synthetic test data.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from tests.test_entra_mode import _TOKEN_URL, _Entra, _id_token, _login
from tests.test_user_key_mode import (
    _API,
    _KEY_ALICE,
    _KEY_BOB,
    _call_tool,
    _hosts_response,
    _tool_text,
)
from unifi_fabric.oauth_store import OAuthStore

_ONLY_ALICE = json.dumps([{"key": _KEY_ALICE, "label": "fabric-a"}])


async def _admin_sign_in(client: httpx.AsyncClient) -> httpx.Response:
    """GET /admin without a session, sign in at the stubbed Entra; returns the callback."""
    start = await client.get("/admin")
    assert start.status_code == 302
    entra = urlparse(start.headers["location"])
    assert entra.netloc == "login.microsoftonline.com"
    state = parse_qs(entra.query)["state"][0]
    return await client.get("/oauth/entra/callback", params={"code": "admin-code", "state": state})


def _csrf(page: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', page)
    assert match, page
    return match.group(1)


def _key_id(page: str, name: str) -> str:
    row = next(r for r in page.split("<tr>") if f"<td>{name}</td>" in r)
    match = re.search(r'name="key_id" value="([^"]+)"', row)
    assert match, row
    return match.group(1)


@pytest.mark.asyncio
async def test_admin_adds_a_fabric_key_that_serves_the_next_request(entra_app):
    async with entra_app(UNIFI_API_KEYS=_ONLY_ALICE) as (srv, client):
        with respx.mock(assert_all_called=False) as mock:
            entra = mock.post(_TOKEN_URL).mock(side_effect=_Entra(_id_token()))
            mock.get(f"{_API}/v1/hosts").mock(side_effect=_hosts_response)
            user = await _login(client)
            before = _tool_text(await _call_tool(client, user["access_token"], "list_hosts", {}))

            entra.mock(side_effect=_Entra(_id_token(roles=["UniFi.Admin"])))
            callback = await _admin_sign_in(client)
            assert callback.status_code == 302
            assert callback.headers["location"] == "/admin"
            cookie = callback.headers["set-cookie"]
            assert "HttpOnly" in cookie and "Path=/admin" in cookie and "Secure" in cookie

            page = await client.get("/admin")
            assert page.status_code == 200
            assert "Aangemeld als Test Colleague" in page.text
            assert "fabric-a" in page.text
            assert _KEY_ALICE not in page.text  # keys are shown masked only

            added = await client.post(
                "/admin",
                data={
                    "csrf": _csrf(page.text),
                    "action": "add",
                    "name": "Fabric B",
                    "api_key": _KEY_BOB,
                },
            )
            assert added.status_code == 200, added.text
            assert "Key Fabric B toegevoegd: hij ziet 1 console(s)." in added.text
            assert _KEY_BOB not in added.text

            after = _tool_text(await _call_tool(client, user["access_token"], "list_hosts", {}))

            deleted = await client.post(
                "/admin",
                data={
                    "csrf": _csrf(added.text),
                    "action": "delete",
                    "key_id": _key_id(added.text, "Fabric B"),
                },
            )
            assert "Key Fabric B verwijderd." in deleted.text
            gone = _tool_text(await _call_tool(client, user["access_token"], "list_hosts", {}))

    assert "Alice-HQ" in before and "Bob-Branch" not in before
    assert "Alice-HQ" in after and "Bob-Branch" in after
    assert "Bob-Branch" not in gone
    assert srv.mcp.auth.store.list_fabric_keys() == []


@pytest.mark.asyncio
async def test_admin_page_needs_the_admin_role(entra_app):
    async with entra_app() as (_srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_TOKEN_URL).mock(side_effect=_Entra(_id_token(roles=["Something.Else"])))
            callback = await _admin_sign_in(client)
            assert callback.status_code == 403
            assert "rol UniFi.Admin" in callback.text
            assert "set-cookie" not in callback.headers
            # Still no session: /admin sends the browser to Microsoft again.
            assert (await client.get("/admin")).status_code == 302
            # A POST without a session never reaches the store.
            resp = await client.post("/admin", data={"action": "add", "name": "x", "api_key": "y"})
            assert resp.status_code == 303


@pytest.mark.asyncio
async def test_admin_entra_error_and_expired_sign_in(entra_app):
    async with entra_app() as (_srv, client):
        start = await client.get("/admin")
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        refused = await client.get(
            "/oauth/entra/callback",
            params={"error": "access_denied", "error_description": "AADSTS50105", "state": state},
        )
        assert refused.status_code == 403 and "AADSTS50105" in refused.text
        # That sign-in is used up; the same state now reads as an ordinary
        # (unknown) MCP login.
        replay = await client.get("/oauth/entra/callback", params={"code": "c", "state": state})
        assert replay.status_code == 400


@pytest.mark.asyncio
async def test_admin_actions_check_csrf_keys_and_duplicates(entra_app):
    async with entra_app(UNIFI_API_KEYS=_ONLY_ALICE) as (srv, client):
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_TOKEN_URL).mock(side_effect=_Entra(_id_token(roles=["UniFi.Admin"])))
            hosts = mock.get(f"{_API}/v1/hosts").mock(side_effect=_hosts_response)
            await _admin_sign_in(client)
            page = await client.get("/admin")
            csrf = _csrf(page.text)

            forged = await client.post(
                "/admin", data={"csrf": "forged", "action": "add", "name": "X", "api_key": "k"}
            )
            assert forged.status_code == 403

            def add(name: str, key: str) -> dict[str, str]:
                return {"csrf": csrf, "action": "add", "name": name, "api_key": key}

            empty = await client.post("/admin", data=add("", ""))
            assert empty.status_code == 400
            refused = await client.post("/admin", data=add("Fout", "not-a-real-key"))
            assert refused.status_code == 400 and "aanvaardt deze key niet" in refused.text
            duplicate = await client.post("/admin", data=add("Again", _KEY_ALICE))
            assert duplicate.status_code == 400 and "staat al in de lijst" in duplicate.text

            added = await client.post("/admin", data=add("Fabric B", _KEY_BOB))
            key_id = _key_id(added.text, "Fabric B")
            tested = await client.post(
                "/admin", data={"csrf": csrf, "action": "test", "key_id": key_id}
            )
            assert "Key Fabric B werkt" in tested.text
            hosts.mock(return_value=httpx.Response(401, json={}))
            revoked = await client.post(
                "/admin", data={"csrf": csrf, "action": "test", "key_id": key_id}
            )
            assert "UniFi weigert key Fabric B" in revoked.text
            hosts.mock(side_effect=httpx.ConnectError("down"))
            down = await client.post(
                "/admin", data={"csrf": csrf, "action": "test", "key_id": key_id}
            )
            assert "niet bereikbaar" in down.text
            unreachable = await client.post("/admin", data=add("Later", "another-key-123456"))
            assert unreachable.status_code == 503
            missing = await client.post(
                "/admin", data={"csrf": csrf, "action": "delete", "key_id": "nope"}
            )
            assert missing.status_code == 404
            unknown = await client.post(
                "/admin", data={"csrf": csrf, "action": "explode", "key_id": key_id}
            )
            assert unknown.status_code == 400

            logout = await client.post("/admin/logout", data={"csrf": csrf})
            assert logout.status_code == 200
            assert (await client.get("/admin")).status_code == 302
        assert [k.name for k in srv.mcp.auth.store.list_fabric_keys()] == ["Fabric B"]


def test_shared_keys_are_encrypted_at_rest(tmp_path):
    path = tmp_path / "keys.sqlite3"
    store = OAuthStore(str(path), ["k" * 40])
    store.add_fabric_key("vbc-1", "VBC", _KEY_BOB, "Admin <admin@example.test>")
    store.close()
    assert _KEY_BOB.encode() not in path.read_bytes()
    reopened = OAuthStore(str(path), ["k" * 40])
    assert [(k.name, k.api_key) for k in reopened.list_fabric_keys()] == [("VBC", _KEY_BOB)]
    # A changed secret cannot decrypt the key: it is skipped, not served garbled.
    assert OAuthStore(str(path), ["z" * 40]).list_fabric_keys() == []
    assert reopened.delete_fabric_key("vbc-1") and not reopened.delete_fabric_key("vbc-1")
    assert reopened.unseal("garbage", 60) is None
