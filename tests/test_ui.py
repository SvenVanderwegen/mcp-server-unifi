"""House style of the server's own pages (VBC Intern design system)."""

from __future__ import annotations

import httpx
import pytest
from fastmcp import FastMCP

from unifi_fabric import ui


@pytest.fixture
async def client():
    mcp = FastMCP("ui-test")
    ui.install_ui_routes(mcp)
    app = mcp.http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        yield c


async def test_bundled_fonts_are_served_and_nothing_else(client):
    font = await client.get(f"{ui.FONT_PATH}/Inter-500.woff2")
    assert font.status_code == 200
    assert font.headers["content-type"] == "font/woff2"
    assert font.content[:4] == b"wOF2"
    for name in ("Inter-OFL.txt", "..%2Fui.py", "Inter-700.woff2"):
        assert (await client.get(f"{ui.FONT_PATH}/{name}")).status_code == 404


def test_page_is_self_contained_with_logo_tokens_and_dark_theme():
    resp = ui.page("UniFi keys", "<p>x</p>", layout="app", header="<span>h</span>")
    body = resp.body.decode()
    csp = resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "font-src 'self'" in csp
    assert "script" not in body
    assert 'aria-label="VBC computers en meer"' in body
    assert "--brand:#e51432" in body and "prefers-color-scheme:dark" in body
    assert f"url({ui.FONT_PATH}/Inter-600.woff2)" in body
    assert '<header class="topbar">' in body and "<span>h</span>" in body
    assert resp.headers["cache-control"] == "no-store"


def test_message_page_and_banner():
    resp = ui.message_page("Geen toegang", "Eerste zin.", "", "Tweede zin.", status=403)
    body = resp.body.decode()
    assert resp.status_code == 403
    assert body.count('<p class="text">') == 2
    assert 'class="backdrop auth"' in body
    assert 'role="alert"' in ui.banner("Fout", "danger")
    assert 'role="status"' in ui.banner("Goed", "success")
