"""Passkey sign-in: a page session for listing, never a substitute for an approval's assertion."""

from __future__ import annotations

import json
from pathlib import Path

from agentpass.passkey.page import FAILURE_LIMIT
from agentpass.passkey.session import (
    ABSOLUTE_TTL,
    CHALLENGE_TTL,
    IDLE_TTL,
    SESSION_COOKIE,
    Session,
    SessionStore,
)
from tests.test_passkey import Authenticator, b64d, env, rejections  # noqa: F401


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _challenge_of(assertion: dict) -> str:
    return json.loads(b64d(assertion["response"]["clientDataJSON"]))["challenge"]


def _cookie_attrs(header: str) -> list[str]:
    return [p.strip() for p in header.split(";")]


# --- the store ---


def test_store_defaults_and_challenge_ttl():
    assert (IDLE_TTL, ABSOLUTE_TTL, CHALLENGE_TTL) == (12 * 3600, 7 * 86400, 120)
    clock = Clock()
    s = SessionStore(clock=clock)
    c = s.new_challenge()
    assert isinstance(c, bytes) and len(c) == 32
    assert s.consume_challenge(c) and not s.consume_challenge(c)
    late = s.new_challenge()
    clock.now += CHALLENGE_TTL + 1
    assert not s.consume_challenge(late)
    assert not s.consume_challenge(b"\x00" * 32)


def test_store_session_lifetimes():
    clock = Clock()
    s = SessionStore(idle=100, absolute=1000, clock=clock)
    token = s.create("cred-1")
    sess = s.get(token)
    assert isinstance(sess, Session) and sess.credential_id == "cred-1" and sess.token == token
    for _ in range(15):  # use keeps it alive past the idle window ...
        clock.now += 60
        assert s.get(token) is not None
    clock.now += 101  # ... until it sits idle
    assert s.get(token) is None
    start = clock.now
    t2 = s.create("cred-1")
    while s.get(t2) is not None:  # absolute cap even when used constantly
        clock.now += 50
    assert 1000 <= clock.now - start < 1050
    t3 = s.create("cred-1")
    s.drop(t3)
    assert s.get(t3) is None and s.get("") is None and s.get("nope") is None


# --- the routes ---


async def test_login_sets_strict_cookie(env):  # noqa: F811
    await env.enrol()
    r = await env.post("/api/login", {"credential": await env.login_assertion()})
    assert r.status == 200, await r.text()
    assert await r.json() == {"ok": True}
    header = next(v for v in r.headers.getall("Set-Cookie") if v.startswith(SESSION_COOKIE + "="))
    attrs = _cookie_attrs(header)
    assert {"HttpOnly", "Secure", "SameSite=Strict", "Path=/"} <= set(attrs)
    assert not any(a.lower().startswith("domain") for a in attrs)
    token = r.cookies[SESSION_COOKIE].value
    assert len(token) >= 32
    sess = env.channel.page.sessions.get(token)
    assert sess is not None and sess.credential_id == env.store.list()[0].id
    assert env.store.list()[0].sign_count == 1  # login advances the counter like an approve


async def test_login_options_offer_enrolled_keys_and_a_fresh_challenge(env):  # noqa: F811
    r = await env.post("/api/login/options")
    assert r.status == 409  # nothing enrolled yet
    await env.enrol()
    a = await (await env.post("/api/login/options")).json()
    b = await (await env.post("/api/login/options")).json()
    assert a["challenge"] != b["challenge"] and len(b64d(a["challenge"])) == 32
    assert a["userVerification"] == "required" and a["rpId"] == "gate.example.ts.net"
    assert [c["id"] for c in a["allowCredentials"]] == [env.store.list()[0].id]
    assert (await env.post("/api/login/options", csrf=False)).status == 403  # CSRF guard


async def test_login_challenge_is_single_use(env):  # noqa: F811
    await env.enrol()
    assertion = await env.login_assertion()
    assert (await env.post("/api/login", {"credential": assertion})).status == 200
    r = await env.post("/api/login", {"credential": assertion})
    assert r.status == 403 and SESSION_COOKIE not in r.cookies
    # re-signing the spent challenge (counter moves on) is refused too
    spent = env.auth.assert_(_challenge_of(assertion))
    assert (await env.post("/api/login", {"credential": spent})).status == 403
    assert len(await rejections(env.db)) == 2


async def test_login_challenge_expires(env):  # noqa: F811
    await env.enrol()
    clock = Clock()
    env.channel.page.sessions = SessionStore(clock=clock)
    assertion = await env.login_assertion()
    clock.now += CHALLENGE_TTL + 1
    assert (await env.post("/api/login", {"credential": assertion})).status == 403


async def test_approval_challenge_cannot_sign_in(env):  # noqa: F811
    await env.enrol()
    await env.send("a1")
    r = await env.post("/api/approvals/a1/challenge")
    assertion = env.auth.assert_((await r.json())["challenge"])
    r = await env.post("/api/login", {"credential": assertion})
    assert r.status == 403 and SESSION_COOKIE not in r.cookies


async def test_login_with_unknown_credential_is_refused_and_throttled(env):  # noqa: F811
    await env.enrol()
    other = Authenticator()
    hdr = {"X-Real-IP": "100.64.0.9"}
    for _ in range(FAILURE_LIMIT):
        r = await env.post("/api/login/options")
        cred = other.assert_((await r.json())["challenge"])
        r = await env.post("/api/login", {"credential": cred}, headers=hdr)
        assert r.status == 403 and SESSION_COOKIE not in r.cookies
    rows = await rejections(env.db)
    assert len(rows) == FAILURE_LIMIT
    assert all(x.request_id == "login" and "100.64.0.9" in x.resolved_by for x in rows)
    assert rows[0].execution_result == {"reason": "unknown credential"}
    # locked out: even the real passkey is refused from that source
    good = await env.login_assertion()
    r = await env.post("/api/login", {"credential": good}, headers=hdr)
    assert r.status == 429 and SESSION_COOKIE not in r.cookies
    r = await env.post("/api/login", {"credential": good}, headers={"X-Real-IP": "100.64.0.10"})
    assert r.status == 200


async def test_malformed_login_bodies_are_refused(env):  # noqa: F811
    await env.enrol()
    for body in ({}, {"credential": None}, {"credential": {"id": "x"}}, {"credential": "x"}):
        r = await env.post("/api/login", body)
        assert r.status == 403 and SESSION_COOKIE not in r.cookies
    assert len(await rejections(env.db)) == 4


async def test_pending_requires_session(env):  # noqa: F811
    await env.send("a1")
    r = await env.get("/api/pending")
    assert r.status == 401
    assert await r.json() == {"error": "sign in"}
    assert r.headers["X-Frame-Options"] == "DENY"  # hardened like any other response
    r = await env.get("/api/pending", headers={"Cookie": f"{SESSION_COOKIE}=forged"})
    assert r.status == 401
    (item,) = await env.pending()
    assert item["approval_id"] == "a1"


async def test_expired_session_is_401(env):  # noqa: F811
    clock = Clock()
    env.channel.page.sessions = SessionStore(clock=clock)
    await env.sign_in()
    assert (await env.get("/api/pending")).status == 200
    clock.now += IDLE_TTL + 1  # idle
    r = await env.get("/api/pending")
    assert r.status == 401 and await r.json() == {"error": "sign in"}

    env.session = ""
    await env.sign_in()
    for _ in range(ABSOLUTE_TTL // (IDLE_TTL // 2)):  # used every 6 h, still capped at 7 d
        clock.now += IDLE_TTL // 2
        r = await env.get("/api/pending")
        if r.status == 401:
            break
    assert r.status == 401 and await r.json() == {"error": "sign in"}
    assert clock.now - 1_000_000.0 >= ABSOLUTE_TTL


async def test_logout_drops_session(env):  # noqa: F811
    await env.sign_in()
    token = env.session
    assert (await env.get("/api/pending")).status == 200
    assert (await env.post("/api/logout", csrf=False)).status == 403  # CSRF guard
    r = await env.post("/api/logout")
    assert r.status == 200 and await r.json() == {"ok": True}
    header = next(v for v in r.headers.getall("Set-Cookie") if v.startswith(SESSION_COOKIE + "="))
    assert "Max-Age=0" in header
    assert env.channel.page.sessions.get(token) is None
    assert (await env.get("/api/pending")).status == 401
    env.session = ""
    assert (await env.post("/api/logout")).status == 200  # idempotent


async def test_approve_still_needs_its_own_assertion(env):  # noqa: F811
    await env.sign_in()
    await env.send("a1")
    for body in ({}, {"approved": True}, {"credential": None}):
        assert (await env.post("/api/approvals/a1/approve", body)).status == 403
    # a fresh login assertion is no approval assertion either
    r = await env.approve("a1", await env.login_assertion())
    assert r.status == 403
    assert env.sink.answers == [] and "a1" in env.channel.page.pending
    # the per-approval assertion still works with the session present
    r = await env.post("/api/approvals/a1/challenge")
    assert (await env.approve("a1", env.auth.assert_((await r.json())["challenge"]))).status == 200
    ((_, answer),) = env.sink.answers
    assert answer.proof["kind"] == "webauthn"


def test_page_script_signs_in_on_401():
    from agentpass.passkey import assets

    js = assets.APP_JS
    for needle in (
        "status === 401",
        "'/api/login/options'",
        "'/api/login'",
        "Sign in with passkey",
    ):
        assert needle in js, needle


async def test_revoked_passkey_ends_its_session(env):  # noqa: F811
    await env.sign_in()
    token = env.session
    assert (await env.get("/api/pending")).status == 200
    Path(env.store.path).write_text(json.dumps({"credentials": []}))  # operator removes the key
    r = await env.get("/api/pending")
    assert r.status == 401 and await r.json() == {"error": "sign in"}
    assert env.channel.page.sessions.get(token) is None  # dropped, not just refused
    assert (await env.get("/api/history")).status == 401
