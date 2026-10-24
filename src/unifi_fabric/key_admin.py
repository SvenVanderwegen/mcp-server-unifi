"""Admin page for the shared Fabric keys (``MCP_AUTH_MODE=entra``).

In Microsoft sign-in mode every user runs on the server's own UniFi keys, one
per Fabric. Besides ``UNIFI_API_KEYS`` in the stack environment, admins can add,
test and remove keys on ``/admin`` without a redeploy. Those keys are stored
Fernet-encrypted in the OAuth store and take effect on the next request.

Access: a Microsoft sign-in (the same Entra app and tenant as the MCP login)
whose ID token carries the app role ``MCP_ENTRA_ADMIN_ROLE``. The session is a
sealed, HttpOnly cookie scoped to ``/admin``; every form carries a CSRF token
bound to that session.
"""

from __future__ import annotations

import html
import json
import logging
import secrets
import time
from collections.abc import Callable
from typing import Any

from fastmcp.server.middleware import Middleware, MiddlewareContext
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from . import ui
from .config import APIKeyConfig
from .entra_oauth import EntraOAuthProvider, install_entra_routes
from .oauth_store import OAuthStore
from .user_keys import key_configs_for, key_label, reset_current_user_key, set_current_user_keys
from .user_oauth import _PAGE_HEADERS, KeyRejectedError, UniFiUnreachableError, check_api_key

_logger = logging.getLogger(__name__)

ADMIN_PATH = "/admin"
SESSION_COOKIE = "unifi_admin"
SESSION_TTL = 8 * 3600
MAX_NAME_LENGTH = 60


def shared_key_configs(
    store: OAuthStore, env_keys: Callable[[], list[APIKeyConfig]]
) -> list[APIKeyConfig]:
    """The keys every request runs on: the stack's, then the admin page's."""
    stored = key_configs_for([(k.name, k.api_key) for k in store.list_fabric_keys()])
    configs = list(env_keys())
    seen = {c.key for c in configs}
    configs.extend(c for c in stored if c.key not in seen)
    return configs


class SharedKeysMiddleware(Middleware):
    """Run every MCP request on the shared keys, including the ones added on /admin."""

    def __init__(self, store: OAuthStore, env_keys: Callable[[], list[APIKeyConfig]]) -> None:
        self.store = store
        self.env_keys = env_keys

    async def on_request(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        reset = set_current_user_keys(shared_key_configs(self.store, self.env_keys))
        try:
            return await call_next(context)
        finally:
            reset_current_user_key(reset)


# Session ----------------------------------------------------------------------


def _session(request: Request, store: OAuthStore) -> dict[str, str] | None:
    raw = request.cookies.get(SESSION_COOKIE, "")
    sealed = store.unseal(raw, SESSION_TTL) if raw else None
    if sealed is None:
        return None
    try:
        data = json.loads(sealed)
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("csrf") else None


def _who(session: dict[str, str]) -> str:
    name, upn = session.get("name", ""), session.get("upn", "")
    return f"{name} <{upn}>" if upn and upn != name else name or upn or "?"


# Page -------------------------------------------------------------------------

_TITLE = "UniFi keys"


def _page(body: str, status: int = 200, header: str = "") -> HTMLResponse:
    return ui.page(_TITLE, body, status=status, layout="app", header=header)


def _mask(key: str) -> str:
    return f"…{key[-4:]}" if len(key) > 8 else "…"


def _render(
    store: OAuthStore,
    env_keys: Callable[[], list[APIKeyConfig]],
    session: dict[str, str],
    *,
    message: str = "",
    ok: bool = True,
    name: str = "",
    status: int = 200,
) -> HTMLResponse:
    e = html.escape
    csrf = e(session["csrf"])
    rows = []
    for cfg in env_keys():
        rows.append(
            f'<tr><td>{e(cfg.label)}</td><td class="is-mono">{e(_mask(cfg.key))}</td>'
            '<td class="is-muted">Stackvariabele <code>UNIFI_API_KEYS</code></td><td></td></tr>'
        )
    for k in store.list_fabric_keys():
        added = time.strftime("%d/%m/%Y %H:%M", time.localtime(k.added_at))
        rows.append(
            f'<tr><td>{e(k.name)}</td><td class="is-mono">{e(_mask(k.api_key))}</td>'
            f'<td class="is-muted">{e(k.added_by)}, {e(added)}</td><td class="is-actions">'
            f'<form method="post" action="{ADMIN_PATH}">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="key_id" value="{e(k.key_id)}">'
            '<button class="btn btn--sm" name="action" value="test">Testen</button>'
            '<button class="btn btn--sm btn--danger" name="action" value="delete">'
            "Verwijderen</button></form></td></tr>"
        )
    table = (
        '<div class="table-wrap"><table><thead><tr><th>Naam</th><th>Key</th>'
        "<th>Toegevoegd</th><th></th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
        if rows
        else '<p class="empty">Er zijn nog geen keys. Voeg hieronder de eerste toe.</p>'
    )
    notice = ui.banner(e(message), "success" if ok else "danger") if message else ""
    header = (
        f'<span class="who">Aangemeld als {e(_who(session))}</span>'
        f'<form method="post" action="{ADMIN_PATH}/logout">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        '<button class="btn btn--ghost">Afmelden</button></form>'
    )
    body = f"""
{notice}
<section class="panel" aria-labelledby="keys">
  <div class="panel-head"><h2 class="panel-title" id="keys">Keys per fabric</h2></div>
  <div class="panel-body"><p class="text">Iedereen die de UniFi-connector gebruikt, werkt met
  deze keys: één per fabric, met de rechten van de key.</p></div>
  {table}
</section>
<section class="panel" aria-labelledby="add">
  <div class="panel-head"><h2 class="panel-title" id="add">Key toevoegen</h2></div>
  <form class="panel-body" method="post" action="{ADMIN_PATH}">
    <p class="text">Maak de key op unifi.ui.com: kies de fabric linksboven, open
    <em>API Keys</em> en kies <em>Create API Key</em>. Hij wordt eerst getest en daarna
    versleuteld bewaard. Hij werkt meteen, zonder herstart.</p>
    <input type="hidden" name="csrf" value="{csrf}">
    <div class="field"><label class="label" for="name">Naam van de fabric</label>
    <input class="input" id="name" name="name" type="text" required
           maxlength="{MAX_NAME_LENGTH}" value="{e(name)}" placeholder="bv. VBC"></div>
    <div class="field"><label class="label" for="api_key">API key</label>
    <input class="input" id="api_key" name="api_key" type="password" required
           autocomplete="off"></div>
    <div class="actions"><button class="btn btn--lg btn--primary" name="action"
    value="add">Testen en toevoegen</button></div>
  </form>
</section>"""
    return _page(body, status, header)


def _denied(reason: str) -> HTMLResponse:
    return ui.message_page(
        "Geen toegang",
        html.escape(reason),
        status=403,
        link=f'<div class="actions"><a class="btn btn--lg btn--primary" '
        f'href="{ADMIN_PATH}">Opnieuw aanmelden</a></div>',
    )


# Routes -----------------------------------------------------------------------


def install_admin_routes(
    app: Any,
    provider: EntraOAuthProvider,
    env_keys: Callable[[], list[APIKeyConfig]],
    api_base_url: str,
) -> None:
    """Register /admin and the Entra callback (which also serves the MCP login)."""
    store = provider.store
    secure = provider.public_url.startswith("https://")

    async def on_admin_login(claims: dict[str, Any] | None, reason: str) -> Response:
        if claims is None:
            return _denied(reason)
        session = {
            "sub": str(claims["oid"]),
            "name": str(claims.get("name") or ""),
            "upn": str(claims.get("preferred_username") or ""),
            "csrf": secrets.token_urlsafe(24),
        }
        _logger.info("Admin %s signed in", _who(session))
        resp = RedirectResponse(ADMIN_PATH, status_code=302, headers=_PAGE_HEADERS)
        resp.set_cookie(
            SESSION_COOKIE,
            store.seal(json.dumps(session)),
            max_age=SESSION_TTL,
            path=ADMIN_PATH,
            secure=secure,
            httponly=True,
            samesite="lax",
        )
        return resp

    install_entra_routes(app, provider, on_admin_login)

    @app.custom_route(ADMIN_PATH, methods=["GET"])
    async def admin_page(request: Request) -> Response:
        session = _session(request, store)
        if session is None:
            return RedirectResponse(provider.start_admin_login(), status_code=302)
        return _render(store, env_keys, session)

    @app.custom_route(f"{ADMIN_PATH}/logout", methods=["POST"])
    async def admin_logout(request: Request) -> Response:
        resp = _page(
            f'<section><h1>Afgemeld</h1><p><a href="{ADMIN_PATH}">Opnieuw aanmelden</a></p>'
            "</section>"
        )
        resp.delete_cookie(SESSION_COOKIE, path=ADMIN_PATH)
        return resp

    @app.custom_route(ADMIN_PATH, methods=["POST"])
    async def admin_action(request: Request) -> Response:
        session = _session(request, store)
        if session is None:
            return RedirectResponse(ADMIN_PATH, status_code=303)
        form = await request.form()
        if not secrets.compare_digest(str(form.get("csrf", "")), session["csrf"]):
            return _denied("Het formulier is verlopen. Laad de pagina opnieuw.")
        action = str(form.get("action", ""))
        who = _who(session)

        if action == "add":
            name = str(form.get("name", "")).strip()[:MAX_NAME_LENGTH]
            api_key = str(form.get("api_key", "")).strip()
            if not name or not api_key:
                return _render(
                    store,
                    env_keys,
                    session,
                    message="Vul een naam en een key in.",
                    ok=False,
                    name=name,
                    status=400,
                )
            known = {c.key for c in shared_key_configs(store, env_keys)}
            if api_key in known:
                return _render(
                    store,
                    env_keys,
                    session,
                    message="Deze key staat al in de lijst.",
                    ok=False,
                    name=name,
                    status=400,
                )
            try:
                consoles = await check_api_key(api_base_url, api_key)
            except KeyRejectedError:
                return _render(
                    store,
                    env_keys,
                    session,
                    ok=False,
                    name=name,
                    status=400,
                    message="UniFi aanvaardt deze key niet. Controleer hem en probeer opnieuw.",
                )
            except UniFiUnreachableError:
                return _render(
                    store,
                    env_keys,
                    session,
                    ok=False,
                    name=name,
                    status=503,
                    message="UniFi is momenteel niet bereikbaar. Probeer het straks opnieuw.",
                )
            store.add_fabric_key(key_label(name, api_key), name, api_key, who)
            _logger.info("Admin %s added shared key %r (%d consoles)", who, name, consoles)
            return _render(
                store,
                env_keys,
                session,
                message=f"Key {name} toegevoegd: hij ziet {consoles} console(s).",
            )

        key_id = str(form.get("key_id", ""))
        entry = next((k for k in store.list_fabric_keys() if k.key_id == key_id), None)
        if entry is None:
            return _render(
                store,
                env_keys,
                session,
                message="Die key bestaat niet meer.",
                ok=False,
                status=404,
            )
        if action == "delete":
            store.delete_fabric_key(key_id)
            _logger.info("Admin %s removed shared key %r", who, entry.name)
            return _render(store, env_keys, session, message=f"Key {entry.name} verwijderd.")
        if action == "test":
            try:
                consoles = await check_api_key(api_base_url, entry.api_key)
            except KeyRejectedError:
                return _render(
                    store,
                    env_keys,
                    session,
                    ok=False,
                    message=f"UniFi weigert key {entry.name}: hij is ingetrokken of verlopen.",
                )
            except UniFiUnreachableError:
                return _render(
                    store,
                    env_keys,
                    session,
                    ok=False,
                    message="UniFi is momenteel niet bereikbaar.",
                )
            return _render(
                store,
                env_keys,
                session,
                message=f"Key {entry.name} werkt: hij ziet {consoles} console(s).",
            )
        return _render(store, env_keys, session, message="Onbekende actie.", ok=False, status=400)
