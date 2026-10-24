"""House style of the server's own web pages: the VBC Intern design system.

The login page (``user_key`` mode), the Microsoft callback errors and ``/admin``
(``entra`` mode) all render through :func:`page`, so they share one stylesheet:
the design system's tokens as CSS variables (light, and dark through
``prefers-color-scheme``), Inter served from this package, and the official VBC
logo inlined as SVG. The pages load nothing external and run no script.
"""

from __future__ import annotations

from importlib import resources
from typing import Any, Literal

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

FONT_PATH = "/ui/fonts"

PAGE_HEADERS = {
    # The pages take credentials: never cache them, never let another site frame
    # them (clickjacking the submit button), load nothing external. No
    # form-action directive: browsers apply it to the redirect that follows the
    # submit, which goes to the client's own domain.
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'"
    ),
}

_STATIC = resources.files("unifi_fabric") / "static"
_FONTS = ("Inter-400.woff2", "Inter-500.woff2", "Inter-600.woff2")


def _svg(name: str, label: str, height: int) -> str:
    svg = (_STATIC / name).read_text(encoding="utf-8")
    return svg.replace(
        "<svg ", f'<svg class="logo" role="img" aria-label="{label}" height="{height}" ', 1
    )


_LOGO_HORIZONTAL = _svg("vbc-logo-horizontaal.svg", "VBC computers en meer", 28)
_LOGO_VERTICAL = _svg("vbc-logo-verticaal.svg", "VBC computers en meer", 72)

_FONT_FACES = "".join(
    f"@font-face{{font-family:Inter;font-style:normal;font-weight:{w};font-display:swap;"
    f"src:url({FONT_PATH}/Inter-{w}.woff2) format('woff2')}}"
    for w in (400, 500, 600)
)

# Tokens from the design system's tokens.json (light, then dark).
_TOKENS = """
:root{color-scheme:light;
--bg:#fafafa;--surface-card:#ffffff;--control:#ffffff;--control-hover:#fafafa;
--bg-subtle:#f4f4f5;--bg-inset:#fafafa;--bg-hover:#f4f4f5;
--border:#e4e4e7;--border-soft:#e4e4e7cc;--border-subtle:#f4f4f5;--border-strong:#d4d4d8;
--fg:#18181b;--fg-2:#3f3f46;--muted:#52525b;--subtle:#71717a;--icon:#71717a;
--primary:#18181b;--on-primary:#ffffff;--primary-hover:#e51432;--on-primary-hover:#ffffff;
--brand:#e51432;--focus-field:#e5143299;--logo-red:#e41432;--logo-ink:#313e5e;
--danger:#dc2626;--danger-soft:#fef2f2;--danger-line:#fecaca;--danger-ink:#991b1b;
--success:#047857;--success-soft:#ecfdf5;--success-ring:#d1fae5;
--grid-line:#18181b0f;--glow-brand:#e514321a;
--shadow-card:0 1px 2px #18181b08;
--focus-ring:0 0 0 2px #fafafa,0 0 0 4px #e51432;--field-focus:0 0 0 4px #e514321a;
--radius-sm:4px;--radius-lg:8px;--radius-xl:12px;--radius-2xl:16px;
--font-sans:"Inter",ui-sans-serif,system-ui,sans-serif;
--font-mono:"Geist Mono",ui-monospace,"Cascadia Mono",Menlo,monospace}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;
--bg:#09090b;--surface-card:#ffffff0a;--control:#ffffff0d;--control-hover:#ffffff1a;
--bg-subtle:#ffffff0d;--bg-inset:#ffffff08;--bg-hover:#ffffff0d;
--border:#ffffff1a;--border-soft:#ffffff1a;--border-subtle:#ffffff0d;--border-strong:#ffffff33;
--fg:#f4f4f5;--fg-2:#d4d4d8;--muted:#a1a1aa;--subtle:#8b8b94;--icon:#a1a1aa;
--primary:#ffffff;--on-primary:#18181b;
--focus-field:#e51432b3;--logo-ink:#ffffff;
--danger:#f87171;--danger-soft:#ef44441a;--danger-line:#ef444433;--danger-ink:#fca5a5;
--success:#34d399;--success-soft:#10b9811a;--success-ring:#10b98133;
--grid-line:#ffffff0d;--glow-brand:#e5143224;--shadow-card:none;
--focus-ring:0 0 0 2px #09090b,0 0 0 4px #e51432;--field-focus:0 0 0 4px #e5143226}}
"""

_CSS = (
    _FONT_FACES
    + _TOKENS
    + """
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{background:var(--bg);color:var(--fg);font:14px/20px var(--font-sans);
font-feature-settings:"cv11","ss01";-webkit-font-smoothing:antialiased}
a{color:var(--fg);text-underline-offset:2px}
a:hover{color:var(--brand)}
a:focus-visible,button:focus-visible,summary:focus-visible{outline:none;
box-shadow:var(--focus-ring);border-radius:var(--radius-sm)}
h1,h2,p{margin:0}
code,.mono{font-family:var(--font-mono);font-size:13px}
.logo .m{fill:var(--logo-red)}.logo .w{fill:var(--logo-ink)}
.logo{display:block;width:auto}
.backdrop{position:relative;isolation:isolate;overflow:hidden;min-height:100vh}
.backdrop::before{content:"";position:absolute;inset:0;z-index:-1;pointer-events:none;
background-image:linear-gradient(to right,var(--grid-line) 1px,transparent 1px),
linear-gradient(to bottom,var(--grid-line) 1px,transparent 1px);background-size:44px 44px;
-webkit-mask-image:radial-gradient(ellipse 70% 55% at 50% 35%,#000 20%,transparent 75%);
mask-image:radial-gradient(ellipse 70% 55% at 50% 35%,#000 20%,transparent 75%)}
.backdrop::after{content:"";position:absolute;z-index:-1;pointer-events:none;left:50%;
top:-224px;width:896px;height:512px;margin-left:-448px;border-radius:9999px;
background:var(--glow-brand);filter:blur(64px)}
.auth{display:flex;flex-direction:column;align-items:center;gap:32px;padding:48px 16px}
.auth .panel{width:100%;max-width:440px}
.panel{border:1px solid var(--border-soft);border-radius:var(--radius-2xl);
background:var(--surface-card);box-shadow:var(--shadow-card);min-width:0}
.panel-head{display:flex;align-items:center;gap:8px;min-height:48px;padding:0 16px;
border-bottom:1px solid var(--border-subtle)}
.panel-title{font-size:14px;line-height:20px;font-weight:600}
.panel-body,.stack{display:flex;flex-direction:column;gap:16px}
.panel-body{padding:16px}
.auth .panel-body{padding:24px}
.title{font-size:16px;line-height:24px;font-weight:600}
.lead{color:var(--muted)}
.text{color:var(--muted)}
.topbar{display:flex;align-items:center;gap:16px;height:64px;padding:0 24px;flex-wrap:wrap}
.topbar .title{margin-left:4px}
.topbar .who{margin-left:auto;color:var(--muted)}
.content{max-width:960px;margin:0 auto;padding:8px 24px 48px;display:flex;
flex-direction:column;gap:16px}
@media (max-width:810px){.content{padding:8px 16px 32px}.topbar{padding:0 16px;height:auto;
min-height:64px}}
.field{display:flex;flex-direction:column;gap:6px;min-width:0}
.label{font-weight:500;color:var(--fg)}
.hint{font-size:12px;line-height:16px;color:var(--subtle)}
.input{width:100%;height:40px;margin:0;padding:0 12px;border:1px solid var(--border);
border-radius:var(--radius-xl);background:var(--control);color:var(--fg);font:inherit;
outline:none;transition:border-color .15s,box-shadow .15s}
.input::placeholder{color:var(--subtle)}
.input:focus{border-color:var(--focus-field);box-shadow:var(--field-focus)}
textarea.input{height:auto;padding:10px 12px;resize:vertical;font-family:var(--font-mono);
font-size:13px;-webkit-text-security:disc}
.actions{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:36px;
padding:0 12px;border-radius:var(--radius-xl);border:1px solid var(--border);
background:var(--control);color:var(--fg-2);font:inherit;font-weight:500;white-space:nowrap;
cursor:pointer;text-decoration:none;transition:background-color .15s,color .15s,
border-color .15s}
.btn:hover{background:var(--control-hover);color:var(--fg)}
.btn:active{transform:scale(.98)}
.btn--lg{height:40px;padding:0 16px}
.btn--sm{height:32px;padding:0 10px;border-radius:var(--radius-lg);font-size:13px}
.btn--primary{background:var(--primary);border-color:transparent;color:var(--on-primary)}
.btn--primary:hover{background:var(--primary-hover);color:var(--on-primary-hover)}
.btn--ghost{background:transparent;border-color:transparent;color:var(--muted)}
.btn--ghost:hover{background:var(--bg-hover);color:var(--fg)}
.btn--danger{background:var(--danger-soft);border-color:var(--danger-line);
color:var(--danger-ink)}
.btn--danger:hover{background:var(--danger-soft);border-color:var(--danger);
color:var(--danger-ink)}
.banner{display:flex;gap:10px;padding:12px;border:1px solid transparent;
border-radius:var(--radius-xl);background:var(--bg-subtle);color:var(--muted)}
.banner--danger{border-color:var(--danger-line);background:var(--danger-soft);
color:var(--danger-ink)}
.banner--success{border-color:var(--success-ring);background:var(--success-soft);
color:var(--fg)}
.banner-dot{flex:none;width:7px;height:7px;margin-top:6px;border-radius:9999px;
background:var(--icon)}
.banner--danger .banner-dot{background:var(--danger)}
.banner--success .banner-dot{background:var(--success)}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{height:40px;padding:0 12px;text-align:left;font-size:12px;line-height:16px;
font-weight:500;color:var(--subtle);background:var(--bg-inset);
border-bottom:1px solid var(--border-soft);white-space:nowrap}
td{height:44px;padding:0 12px;border-bottom:1px solid var(--border-subtle);white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
th:first-child,td:first-child{padding-left:16px}
th:last-child,td:last-child{padding-right:16px}
tbody tr:hover{background:var(--bg-hover)}
td.is-muted{color:var(--muted)}
td.is-mono{font-family:var(--font-mono);font-size:13px;color:var(--muted)}
td.is-actions{text-align:right;white-space:nowrap}
td.is-actions form{display:inline-flex;gap:8px}
.empty{padding:32px 16px;text-align:center;color:var(--muted)}
details{color:var(--muted)}
summary{cursor:pointer;color:var(--fg-2);font-weight:500}
details[open] summary{margin-bottom:8px}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""
)


def banner(text: str, tone: Literal["neutral", "danger", "success"] = "neutral") -> str:
    """A notice line (already-escaped ``text``) in the design system's Banner style."""
    role = "alert" if tone == "danger" else "status"
    return (
        f'<div class="banner banner--{tone}" role="{role}">'
        f'<span class="banner-dot" aria-hidden="true"></span><p>{text}</p></div>'
    )


def page(
    title: str,
    body: str,
    *,
    status: int = 200,
    layout: Literal["auth", "app"] = "auth",
    header: str = "",
) -> HTMLResponse:
    """A full page around already-escaped ``body`` HTML (``title``, ``header`` too).

    ``auth``: the sign-in layout, the vertical logo above one centred panel on the
    grid backdrop. ``app``: a working screen, a top bar with the horizontal logo,
    ``title`` and ``header`` (right-aligned), then ``body`` in a column.
    """
    if layout == "auth":
        main = f'<main class="backdrop auth">{_LOGO_VERTICAL}{body}</main>'
    else:
        main = (
            f'<header class="topbar">{_LOGO_HORIZONTAL}<span class="title">{title}</span>'
            f"{header}</header>"
            f'<main class="content">{body}</main>'
        )
    doc = (
        '<!doctype html><html lang="nl"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title}</title><style>{_CSS}</style></head><body>{main}</body></html>"
    )
    return HTMLResponse(doc, status_code=status, headers=PAGE_HEADERS)


def message_page(title: str, *paragraphs: str, status: int, link: str = "") -> HTMLResponse:
    """A sign-in layout page with one panel: a title, sentences and optional ``link`` HTML.

    ``title`` and ``paragraphs`` are already-escaped HTML.
    """
    text = "".join(f'<p class="text">{p}</p>' for p in paragraphs if p)
    return page(
        title,
        f'<section class="panel"><div class="panel-body"><h1 class="title">{title}</h1>'
        f"{text}{link}</div></section>",
        status=status,
    )


async def _font(request: Request) -> Response:
    name = request.path_params["name"]
    if name not in _FONTS:
        return Response(status_code=404)
    return Response(
        (_STATIC / "fonts" / name).read_bytes(),
        media_type="font/woff2",
        headers={"Cache-Control": "public, max-age=604800, immutable"},
    )


def install_ui_routes(app: Any) -> None:
    """Serve the bundled Inter files the pages' stylesheet points to."""
    app.custom_route(FONT_PATH + "/{name}", methods=["GET"])(_font)
