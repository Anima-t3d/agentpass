"""The PWA shell: manifest, service worker, icons, deep link, tabs, CSP."""

from __future__ import annotations

import json
import re

from agentpass.passkey import assets, pwa_assets
from agentpass.passkey.page import CSP
from agentpass.passkey.session import SESSION_COOKIE
from tests.test_passkey import env  # noqa: F401

EXPECTED_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
PNG = b"\x89PNG\r\n\x1a\n"


async def test_manifest_fields(env):  # noqa: F811
    r = await env.get("/manifest.webmanifest")  # no session needed
    assert r.status == 200
    assert r.headers["Content-Type"].startswith("application/manifest+json")
    m = json.loads(await r.text())
    assert m["name"] == "AgentPass"
    assert m["display"] == "standalone"
    assert m["start_url"] == "/" and m["scope"] == "/"
    assert m["background_color"] and m["theme_color"]
    icons = {(i["sizes"], i.get("purpose", "any")): i["src"] for i in m["icons"]}
    assert {("192x192", "any"), ("512x512", "any"), ("512x512", "maskable")} <= set(icons)
    for src in icons.values():
        r = await env.get(src)
        assert r.status == 200 and r.headers["Content-Type"] == "image/png"
        assert (await r.read()).startswith(PNG)


async def test_icons_unknown_name_is_404(env):  # noqa: F811
    assert (await env.get("/icons/nope.png")).status == 404
    assert (await env.get("/icons/..%2Fpage.py")).status == 404


async def test_sw_served_with_js_type_and_no_cache(env):  # noqa: F811
    r = await env.get("/sw.js")
    assert r.status == 200
    assert r.headers["Content-Type"].startswith("text/javascript")
    assert r.headers["Cache-Control"] == "no-cache"
    body = await r.text()
    for needle in ("install", "activate", "fetch", "caches.open", "/static/app.js"):
        assert needle in body, needle
    assert r.headers["Content-Security-Policy"] == EXPECTED_CSP


def test_sw_never_caches_api_responses():
    sw = pwa_assets.SW_JS
    assert "/api/" in sw  # explicit network-only branch
    assert "cache.put" not in sw or "isApi" in sw
    # the API branch returns before any cache write
    api = sw.index("isApi(")
    assert sw.index("cache.put") > api


async def test_deep_link_serves_shell_for_any_id_without_leaking_data(env):  # noqa: F811
    await env.send("secret-id-1", args={"to": "victim@example.com"})
    shell = await (await env.get("/")).text()
    for approval_id in ("secret-id-1", "does-not-exist"):
        r = await env.get(f"/a/{approval_id}")  # no session on purpose
        assert r.status == 200
        assert r.headers["Content-Type"].startswith("text/html")
        text = await r.text()
        assert text == shell
        for leaked in ("secret-id-1", "victim@example.com", "gmail_send", "hermes"):
            assert leaked not in text


async def test_csp_allows_manifest_worker_img_self_only(env):  # noqa: F811
    assert CSP == EXPECTED_CSP
    for path in ("/", "/a/x", "/manifest.webmanifest", "/sw.js", "/icons/icon-192.png"):
        r = await env.get(path)
        assert r.headers["Content-Security-Policy"] == EXPECTED_CSP, path
    for directive in ("img-src", "manifest-src", "worker-src"):
        assert f"{directive} 'self';" in CSP
    assert "unsafe" not in CSP and "data:" not in CSP and "blob:" not in CSP


def test_shell_html_links_manifest_icons_and_has_tabs_without_inline_code():
    html = assets.INDEX_HTML
    assert 'rel="manifest" href="/manifest.webmanifest"' in html
    assert 'rel="apple-touch-icon"' in html and 'name="theme-color"' in html
    for tab in ("pending", "history", "devices"):
        assert f'id="tab-{tab}"' in html and f'id="panel-{tab}"' in html
    assert html.count('role="tab"') == 3 and 'role="tablist"' in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "style=" not in html and not re.search(r"\son\w+=", html)
    assert 'id="offline"' in html


def test_script_registers_sw_wires_tabs_and_deep_link():
    js = assets.APP_JS
    for needle in (
        "serviceWorker.register('/sw.js'",
        "\\/a\\/",
        "This request is no longer pending",
        "switchTab",
        "Not connected to Tailscale",
    ):
        assert needle in js, needle
    assert (
        "No passkey enrolled yet. Open an enrolment link from `agentpass passkey enroll` first."
        in js
    )


def test_css_is_dark_by_default_with_light_variant_and_reduced_motion():
    css = assets.APP_CSS
    assert "@media (prefers-color-scheme:light)" in css
    assert "@media (prefers-color-scheme:dark)" not in css
    root = css[css.index(":root{") :]
    assert "--bg:#0b1017" in root.split("@media")[0]
    assert "@media (prefers-reduced-motion:reduce)" in css
    assert ".tabs" in css and "@media (max-width" in css


# --- carried fix: a re-login drops the token the request already carried ---


async def test_login_drops_the_session_token_the_request_carried(env):  # noqa: F811
    await env.sign_in()
    old = env.session
    assert env.channel.page.sessions.get(old) is not None
    r = await env.post("/api/login", {"credential": await env.login_assertion()})
    assert r.status == 200
    new = r.cookies[SESSION_COOKIE].value
    assert new != old
    assert env.channel.page.sessions.get(old) is None
    assert env.channel.page.sessions.get(new) is not None
