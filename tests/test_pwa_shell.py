"""The PWA shell: manifest, service worker, icons, deep link, tabs, CSP."""

from __future__ import annotations

import fnmatch
import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

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


# The worker's behaviour (never caching /api/*, push, actions, the offline queue) is tested
# in tests/js/sw-logic.test.mjs with stubbed globals; here: that the shipped worker is that file.
SW_LOGIC = Path(pwa_assets.__file__).parent / "static" / "sw-logic.mjs"


def test_sw_is_built_from_the_tested_logic_file():
    source = SW_LOGIC.read_text(encoding="utf-8")
    assert "export function setup" in source
    sw = pwa_assets.SW_JS
    assert "export " not in sw  # a classic worker has no modules
    assert sw.startswith("'use strict';")
    assert "function setup(self, env)" in sw
    assert re.search(r"^setup\(self, \{", sw, re.MULTILINE)
    assert "idbStore(indexedDB)" in sw
    # every function the node tests pin is in the shipped worker
    for name in ("notificationFor", "decideClick", "queueDecision", "resolvedText"):
        assert f"function {name}(" in sw
    assert "must stay static" in source  # the cached shell holds no per-user content


def test_sw_logic_file_ships_in_the_package():
    root = Path(__file__).parent.parent
    cfg = tomllib.loads((root / "pyproject.toml").read_text())
    patterns = cfg["tool"]["setuptools"]["package-data"]["agentpass"]
    rel = SW_LOGIC.relative_to(root / "src" / "agentpass").as_posix()
    assert any(fnmatch.fnmatch(rel, pat) for pat in patterns), (rel, patterns)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_service_worker_logic_node_tests_pass():
    root = Path(__file__).parent.parent
    run = subprocess.run(
        ["node", "--test", *sorted(str(p) for p in (root / "tests" / "js").glob("*.test.mjs"))],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]


async def test_served_worker_has_a_version_and_the_queue_tag(env):  # noqa: F811
    body = await (await env.get("/sw.js")).text()
    assert "__VERSION__" not in body
    assert re.search(r"agentpass-shell-[0-9a-f]{12}", body)
    assert "agentpass-actions" in body and "/api/push/action" in body


def test_app_script_has_history_and_devices_views():
    js = assets.APP_JS
    for needle in (
        "/api/history",
        "One-tap enable refused",
        "Enable notifications on this device",
        "Notification.requestPermission()",
        "pushManager.subscribe({userVisibleOnly: true, applicationServerKey",
        "/api/push/subscribe",
        "/one-tap/options",
        "assertWith(await api(base + '/one-tap/options'",
        "Approve from the notification without a fingerprint, for requests that don't "
        "require a passkey.",
        "intent://#Intent;package=com.tailscale.ipn;end",
        "/Android/i.test(navigator.userAgent)",
        "retry-actions",
        "' (notification)'",
        "'Resolved by'",
    ):
        assert needle in js, needle
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js


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
