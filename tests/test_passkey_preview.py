"""The approval page with previews: data served, escaping of hostile strings, strict assets."""

from __future__ import annotations

import re

from agentpass.passkey import assets
from agentpass.passkey.page import CSP, DISPLAY_LIMIT, display_safe
from agentpass.passkey.verify import approval_challenge
from agentpass.preview import LookupNote, Preview, Section, Unavailable
from tests.test_passkey import HOST, env  # noqa: F401

HOSTILE = "<img src=x onerror=alert(1)><script>alert(2)</script>\"'&"
BIDI = "evil‮gpj.exe ⁦x⁩ \x00 \x1b[31m"


def _preview(**kw) -> Preview:
    base = {
        "title": f"Delete {HOSTILE}",
        "summary": "s",
        "built_at": "2026-10-29T10:00:00Z",
        "sections": [
            Section("kv", "Repo", [[HOSTILE, BIDI]]),
            Section("diff", "Diff", f"@@ -1 +1 @@\n-{HOSTILE}\n+{BIDI}"),
            Section("list", "Items", [HOSTILE]),
            Section("table", "Rows", [[HOSTILE, BIDI]]),
            Section("text", "Body", "y" * (DISPLAY_LIMIT + 50)),
        ],
        "warnings": [HOSTILE],
        "lookups": [LookupNote("repo", "failed", "HTTP 404", "")],
        "confirm_text": "acme/widgets",
    }
    return Preview(**{**base, **kw}).seal()


async def _pending(env):  # noqa: F811
    r = await env.client.get("/api/pending", headers={"Host": HOST})
    return (await r.json())["pending"]


async def _send(env, **kw):  # noqa: F811
    req = await env.send("p1", {"to": BIDI, "body": HOSTILE}, **kw)
    return req


async def test_preview_and_note_are_served_with_the_pending_item(env):  # noqa: F811
    preview = _preview()
    await _send(env, preview=preview, agent_note="because I said so")
    (item,) = await _pending(env)
    assert item["agent_note"] == "because I said so"
    assert item["preview"]["confirm_text"] == "acme/widgets"
    assert [s["kind"] for s in item["preview"]["sections"]] == [
        "kv",
        "diff",
        "list",
        "table",
        "text",
    ]
    assert item["preview"]["lookups"][0]["detail"] == "HTTP 404"


async def test_markup_is_data_not_html_but_control_and_bidi_are_escaped(env):  # noqa: F811
    await _send(env, preview=_preview(), agent_note=f"note {HOSTILE} {BIDI}")
    (item,) = await _pending(env)
    pv = item["preview"]
    assert pv["title"] == f"Delete {HOSTILE}"  # kept verbatim: the page uses textContent
    assert pv["sections"][0]["data"][0] == [HOSTILE, BIDI.translate(_ESC)]
    assert "‮" not in str(item) and "\x00" not in str(item) and "\x1b" not in str(item)
    assert "\\u202e" in item["agent_note"] and "\\u0000" in item["agent_note"]
    assert item["args"]["to"] == BIDI.translate(_ESC)


_ESC = {0x202E: "\\u202e", 0x2066: "\\u2066", 0x2069: "\\u2069", 0: "\\u0000", 0x1B: "\\u001b"}


async def test_very_long_values_are_cut_and_labelled(env):  # noqa: F811
    await _send(env, preview=_preview())
    (item,) = await _pending(env)
    body = item["preview"]["sections"][4]["data"]
    assert len(body) < DISPLAY_LIMIT + 100 and "50 more characters not shown" in body
    assert display_safe("z" * 10) == "z" * 10


async def test_display_escaping_never_touches_the_signed_args(env):  # noqa: F811
    req = await _send(env, preview=_preview())
    pending = env.channel.page.pending["p1"]
    assert pending.args == req.args and "‮" in pending.args["to"]
    assert pending.challenge() == approval_challenge(
        "p1", "hermes", "gmail_send", req.args, pending.expires_at
    )


async def test_unavailable_preview_and_no_preview(env):  # noqa: F811
    await _send(env, preview=Unavailable("timeout", "2026-10-29T10:00:00Z"))
    (item,) = await _pending(env)
    assert item["preview"] == {"unavailable": "timeout", "built_at": "2026-10-29T10:00:00Z"}
    await env.channel.finalize("p1", None)
    await _send(env)
    (item,) = await _pending(env)
    assert item["preview"] is None and item["agent_note"] is None


async def test_preview_is_never_part_of_the_challenge(env):  # noqa: F811
    req = await _send(env, preview=_preview(), agent_note="one")
    first = env.channel.page.pending["p1"].challenge()
    env.channel.page.pending["p1"].preview = {"unavailable": "x"}
    env.channel.page.pending["p1"].agent_note = "two"
    assert env.channel.page.pending["p1"].challenge() == first
    assert first == approval_challenge(
        "p1", "hermes", "gmail_send", req.args, env.channel.page.pending["p1"].expires_at
    )


# --- assets and headers ---


async def test_every_page_and_asset_carries_the_strict_headers(env):  # noqa: F811
    for path in ("/", "/enroll", "/static/app.js", "/static/app.css", "/api/pending"):
        r = await env.client.get(path, headers={"Host": HOST})
        assert r.status == 200, path
        assert r.headers["Content-Security-Policy"] == CSP
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Referrer-Policy"] == "no-referrer"
        assert r.headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in CSP and "'unsafe-inline'" not in CSP
    assert "unsafe-eval" not in CSP and "img-src" not in CSP  # images fall under 'none'


def test_script_never_parses_markup_or_runs_strings():
    js = assets.APP_JS
    for banned in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "setTimeout('",
        "DOMParser",
        "createContextualFragment",
        ".style.",
        "'style'",
    ):
        assert banned not in js, banned
    assert "Unverified text from the agent" in js


def test_html_has_no_inline_script_style_or_handlers_and_no_external_resources():
    for html in (assets.INDEX_HTML, assets.ENROLL_HTML):
        assert not re.search(r"<script(?![^>]*\bsrc=)", html)
        assert "style=" not in html and not re.search(r"\son\w+=", html)
        assert not re.search(r"(?:src|href)=[\"']https?:", html)
    css = assets.APP_CSS
    assert "url(" not in css and "@import" not in css and "http" not in css


def test_css_has_tokens_both_themes_reduced_motion_and_readable_sizes():
    css = assets.APP_CSS
    assert "--fs-sm:.875rem" in css and "--font:system-ui" in css and "--mono:" in css
    assert "@media (prefers-color-scheme:dark)" in css
    assert "@media (prefers-reduced-motion:reduce)" in css
    assert ":focus-visible" in css and "position:sticky" in css
    sizes = [float(x) for x in re.findall(r"font-size:([\d.]+)rem", css)]
    assert not [x for x in sizes if x < 0.875]
    assert "font-size:1" not in css.replace("font-size:1.", "")  # no bare px below the scale
    assert not re.search(r"font(?:-size)?:[^;]*\b(?:1[0-3]|[0-9])px", css)
