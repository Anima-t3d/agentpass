"""Passkey approval page: the proof cannot be produced by anything an agent holds.

A software authenticator (locally generated P-256 key) stands in for the owner's device;
the JSON endpoints are driven directly, with no network and no browser.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

import cbor2
import pytest
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from agentpass.approval import (
    Answer,
    AnswerStatus,
    ApprovalCoordinator,
    ApprovalReason,
    ApprovalRequest,
)
from agentpass.config import ConfigError
from agentpass.db import Database
from agentpass.passkey.channel import PasskeyChannel, issue_enrolment_url
from agentpass.passkey.page import CSRF_COOKIE, FAILURE_LIMIT, PasskeyConfig
from agentpass.passkey.store import EnrolmentTokens, PasskeyStore
from agentpass.passkey.verify import approval_challenge, canonical_json

ORIGIN = "https://gate.example.ts.net"
RP_ID = "gate.example.ts.net"
HOST = "gate.example.ts.net"


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Authenticator:
    """Minimal ES256 platform authenticator. The private key lives only here."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.counter = 0

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        )

    def register(self, options: dict, origin: str = ORIGIN) -> dict:
        client = json.dumps(
            {"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}
        ).encode()
        auth = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([0x45])  # UP | UV | AT
            + (0).to_bytes(4, "big")
            + bytes(16)
            + len(self.cred_id).to_bytes(2, "big")
            + self.cred_id
            + self._cose()
        )
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {
            "id": b64e(self.cred_id),
            "rawId": b64e(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64e(client),
                "attestationObject": b64e(att),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    def assert_(
        self,
        challenge_b64: str,
        *,
        origin: str = ORIGIN,
        counter: int | None = None,
        uv: bool = True,
    ) -> dict:
        self.counter = self.counter + 1 if counter is None else counter
        client = json.dumps(
            {"type": "webauthn.get", "challenge": challenge_b64, "origin": origin}
        ).encode()
        flags = 0x01 | (0x04 if uv else 0)
        auth = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([flags])
            + self.counter.to_bytes(4, "big")
        )
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": b64e(self.cred_id),
            "rawId": b64e(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64e(client),
                "authenticatorData": b64e(auth),
                "signature": b64e(sig),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }


@dataclass
class Req:
    approval_id: str
    agent_id: str
    tool: str
    args: dict
    risk: str = "high"
    expires_at: float = 0.0
    require: str = "passkey"


class Sink:
    def __init__(self) -> None:
        self.answers: list[tuple[str, object]] = []
        self.result = AnswerStatus.ACCEPTED

    async def answer(self, approval_id: str, answer: object) -> AnswerStatus:
        self.answers.append((approval_id, answer))
        return self.result


class Env:
    def __init__(self, channel, client, sink, db, auth, csrf):
        self.channel, self.client, self.sink, self.db, self.auth, self.csrf = (
            channel,
            client,
            sink,
            db,
            auth,
            csrf,
        )

    @property
    def store(self) -> PasskeyStore:
        return self.channel.store

    async def post(self, path, body=None, *, origin=ORIGIN, headers=None, csrf=True):
        h = {"Origin": origin, "Host": HOST, **(headers or {})}
        if csrf:  # the Secure cookie is not replayed by the test client over http
            h["X-CSRF"] = self.csrf
            h["Cookie"] = f"{CSRF_COOKIE}={self.csrf}"
        return await self.client.post(path, json=body or {}, headers=h)

    async def send(self, approval_id="a1", args=None, tool="gmail_send", ttl=300, **kw):
        req = Req(
            approval_id,
            "hermes",
            tool,
            args if args is not None else {"to": "x@y.z", "n": 1},
            expires_at=time.time() + ttl,
            **kw,
        )
        await self.channel.send(req)
        return req

    async def challenge(self, approval_id):
        r = await self.post(f"/api/approvals/{approval_id}/challenge")
        assert r.status == 200, await r.text()
        return (await r.json())["challenge"]

    async def approve(self, approval_id, credential, **kw):
        return await self.post(
            f"/api/approvals/{approval_id}/approve", {"credential": credential}, **kw
        )

    async def enrol(self):
        token = self.channel.page.tokens.issue()
        r = await self.post("/api/enroll/options", {"token": token})
        assert r.status == 200, await r.text()
        opts = await r.json()
        r = await self.post(
            "/api/enroll/verify",
            {"token": token, "label": "test phone", "credential": self.auth.register(opts)},
        )
        assert r.status == 200, await r.text()


@pytest.fixture
async def env(tmp_path):
    cfg = PasskeyConfig.from_mapping(
        {"enabled": True, "rp_id": RP_ID, "origin": ORIGIN}, str(tmp_path / "agentpass.db")
    )
    db = Database(str(tmp_path / "agentpass.db"))
    await db.initialize()
    channel = PasskeyChannel(cfg, db=db)
    sink = Sink()
    channel.page.answer = sink.answer
    client = TestClient(TestServer(channel.page.build_app()))
    await client.start_server()
    r = await client.get("/api/session", headers={"Host": HOST})
    csrf = (await r.json())["csrf"]
    e = Env(channel, client, sink, db, Authenticator(), csrf)
    yield e
    await client.close()
    await db.close()


async def rejections(db):
    return [x for x in await db.get_audit_log() if x.resolution == "approval_rejected"]


# --- canonical json / challenge ---


def test_canonical_json_is_deterministic():
    a = {"b": [1, {"z": 1, "a": "é"}], "a": None}
    b = {"a": None, "b": [1, {"a": "é", "z": 1}]}
    assert canonical_json(a) == canonical_json(b) == '{"a":null,"b":[1,{"a":"\\u00e9","z":1}]}'
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_challenge_covers_every_field():
    base = ("id", "agent", "tool", {"a": 1}, 1000)
    c = approval_challenge(*base)
    assert c == approval_challenge("id", "agent", "tool", {"a": 1}, "1970-01-01T00:16:40Z")
    for variant in (
        ("id2", "agent", "tool", {"a": 1}, 1000),
        ("id", "agent2", "tool", {"a": 1}, 1000),
        ("id", "agent", "tool2", {"a": 1}, 1000),
        ("id", "agent", "tool", {"a": 2}, 1000),
        ("id", "agent", "tool", {"a": 1}, 1001),
        ("i", "dagent", "tool", {"a": 1}, 1000),  # field boundaries are unambiguous
    ):
        assert approval_challenge(*variant) != c


# --- config ---


@pytest.mark.parametrize(
    "override",
    [
        {"host": "0.0.0.0"},
        {"origin": "http://gate.example.ts.net"},
        {"origin": ""},
        {"rp_id": "other.net"},
        {"origin": "https://gate.example.ts.net/path"},
    ],
)
def test_config_rejects_unsafe_values(override):
    raw = {"enabled": True, "rp_id": RP_ID, "origin": ORIGIN, **override}
    with pytest.raises(ConfigError):
        PasskeyConfig.from_mapping(raw, "/tmp/x/agentpass.db")


def test_config_defaults(tmp_path):
    cfg = PasskeyConfig.from_mapping({"rp_id": RP_ID, "origin": ORIGIN}, str(tmp_path / "a.db"))
    assert (cfg.host, cfg.port, cfg.enabled) == ("127.0.0.1", 8206, False)
    assert cfg.store_path == str(tmp_path / "passkeys.json")


# --- enrolment and storage ---


async def test_enrolment_stores_public_key_only(env):
    await env.enrol()
    path = Path(env.store.path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text())
    (cred,) = data["credentials"]
    assert set(cred) == {"id", "public_key", "sign_count", "transports", "created_at", "label"}
    assert cred["transports"] == ["internal"] and cred["label"] == "test phone"
    pem_der = env.auth.key.private_numbers().private_value.to_bytes(32, "big")
    raw = path.read_bytes()
    assert pem_der not in raw and b64e(pem_der).encode() not in raw
    assert b"PRIVATE" not in raw and b'"d"' not in raw
    # nothing else (tokens, lock files) is group/world readable either
    for f in path.parent.iterdir():
        assert stat.S_IMODE(f.stat().st_mode) & 0o077 == 0, f


def test_enrolment_token_is_one_time_and_expires(tmp_path):
    t = EnrolmentTokens(tmp_path / "e.json")
    tok = t.issue(now=1000)
    assert tok not in (tmp_path / "e.json").read_text()  # only a hash is stored
    assert t.is_valid(tok, now=1599) and not t.is_valid(tok, now=1601)
    assert t.consume(tok, now=1100) and not t.consume(tok, now=1100)
    assert not t.consume(t.issue(now=1000), now=1601)
    assert stat.S_IMODE((tmp_path / "e.json").stat().st_mode) == 0o600


async def test_enrol_url_and_token_reuse(env):
    url = issue_enrolment_url(env.channel.config)
    assert url.startswith(ORIGIN + "/enroll?token=")
    token = url.split("token=")[1]
    r = await env.post("/api/enroll/options", {"token": token})
    opts = await r.json()
    assert opts["authenticatorSelection"]["residentKey"] == "required"
    assert opts["authenticatorSelection"]["userVerification"] == "required"
    body = {"token": token, "credential": env.auth.register(opts)}
    assert (await env.post("/api/enroll/verify", body)).status == 200
    assert (await env.post("/api/enroll/verify", body)).status == 403  # token spent
    assert len(env.store.list()) == 1


async def test_enrol_rejects_bad_token_and_wrong_origin_registration(env):
    assert (await env.post("/api/enroll/options", {"token": "nope"})).status == 403
    token = env.channel.page.tokens.issue()
    opts = await (await env.post("/api/enroll/options", {"token": token})).json()
    bad = env.auth.register(opts, origin="https://evil.example")
    r = await env.post("/api/enroll/verify", {"token": token, "credential": bad})
    assert r.status == 403 and env.store.list() == []


# --- listing ---


async def test_pending_list_shows_full_args(env):
    args = {"to": "a@b.c", "body": "x" * 500, "nested": {"k": [1, 2]}}
    await env.send("a1", args)
    data = await (await env.client.get("/api/pending", headers={"Host": HOST})).json()
    (item,) = data["pending"]
    assert item["args"] == args and item["agent"] == "hermes" and item["tool"] == "gmail_send"
    assert item["risk"] == "high" and item["expires_at"].endswith("Z")
    await env.channel.finalize("a1", None)
    data = await (await env.client.get("/api/pending", headers={"Host": HOST})).json()
    assert data["pending"] == []


# --- approval ---


async def test_valid_assertion_approves_and_advances_counter(env):
    await env.enrol()
    await env.send("a1")
    ch = await env.challenge("a1")
    r = await env.approve("a1", env.auth.assert_(ch))
    assert r.status == 200
    ((aid, answer),) = env.sink.answers
    assert aid == "a1" and answer.approved and answer.channel == "passkey"
    assert answer.proof["kind"] == "webauthn" and answer.proof["sign_count"] == 1
    assert env.store.list()[0].sign_count == 1
    assert "a1" not in env.channel.page.pending
    assert await rejections(env.db) == []


async def test_challenge_endpoint_matches_shared_function(env):
    await env.enrol()
    req = await env.send("a1")
    ch = await env.challenge("a1")
    assert b64d(ch) == approval_challenge(
        req.approval_id, req.agent_id, req.tool, req.args, req.expires_at
    )


async def test_agent_bearer_token_cannot_approve(env):
    await env.enrol()
    await env.send("a1")
    bearer = {"Authorization": "Bearer agp_hermes_" + "s" * 32}
    for body in ({}, {"approved": True}, {"credential": None}, {"credential": {"id": "x"}}):
        r = await env.post("/api/approvals/a1/approve", body, headers=bearer)
        assert r.status == 403
    # the token also does not stand in for the CSRF check or the origin
    r = await env.post("/api/approvals/a1/approve", {}, headers=bearer, csrf=False)
    assert r.status == 403
    assert env.sink.answers == [] and "a1" in env.channel.page.pending
    assert len(await rejections(env.db)) == 4


async def test_assertion_for_request_a_cannot_approve_b(env):
    await env.enrol()
    await env.send("a1")
    await env.send("b1")
    assertion_a = env.auth.assert_(await env.challenge("a1"))
    r = await env.approve("b1", assertion_a)
    assert r.status == 403 and env.sink.answers == []
    assert "b1" in env.channel.page.pending


async def test_assertion_cannot_approve_altered_args(env):
    await env.enrol()
    req = await env.send("a1", {"to": "owner@example.com"})
    assertion = env.auth.assert_(await env.challenge("a1"))
    req_args_before = dict(req.args)
    # same id, agent, tool and expiry, different args (e.g. a re-registered request)
    await env.channel.send(
        Req("a1", "hermes", "gmail_send", {"to": "evil@example.com"}, expires_at=req.expires_at)
    )
    assert req.args == req_args_before
    r = await env.approve("a1", assertion)
    assert r.status == 403 and env.sink.answers == []


async def test_expired_approval_is_refused(env):
    await env.enrol()
    await env.send("a1", ttl=300)
    assertion = env.auth.assert_(await env.challenge("a1"))
    env.channel.page.pending["a1"].expires_at = time.time() - 1
    r = await env.approve("a1", assertion)
    assert r.status == 410 and env.sink.answers == []
    r = await env.post("/api/approvals/a1/challenge")
    assert r.status == 404  # no new challenge for an expired approval


async def test_replayed_assertion_with_old_counter_is_refused(env):
    await env.enrol()
    for aid in ("a1", "a2"):
        await env.send(aid)
    ch1 = await env.challenge("a1")
    assert (await env.approve("a1", env.auth.assert_(ch1, counter=5))).status == 200
    # a counter that does not increase (cloned authenticator or replay) is refused
    ch2 = await env.challenge("a2")
    for counter in (5, 3):
        r = await env.approve("a2", env.auth.assert_(ch2, counter=counter))
        assert r.status == 403
    assert len(env.sink.answers) == 1 and env.store.list()[0].sign_count == 5
    assert (await env.approve("a2", env.auth.assert_(ch2, counter=6))).status == 200


async def test_replay_of_same_assertion_after_resolution(env):
    await env.enrol()
    await env.send("a1")
    assertion = env.auth.assert_(await env.challenge("a1"))
    assert (await env.approve("a1", assertion)).status == 200
    assert (await env.approve("a1", assertion)).status == 404
    assert len(env.sink.answers) == 1


async def test_wrong_origin_is_refused(env):
    await env.enrol()
    await env.send("a1")
    ch = await env.challenge("a1")
    # browser-reported origin inside the signed clientData is wrong
    r = await env.approve("a1", env.auth.assert_(ch, origin="https://evil.example"))
    assert r.status == 403
    # request Origin header is wrong
    r = await env.approve("a1", env.auth.assert_(ch), origin="https://evil.example")
    assert r.status == 403
    # request Host is wrong
    r = await env.client.get("/api/pending", headers={"Host": "evil.example"})
    assert r.status == 421
    r = await env.client.post(
        "/api/approvals/a1/approve",
        json={},
        headers={
            "Host": "evil.example",
            "Origin": ORIGIN,
            "X-CSRF": env.csrf,
            "Cookie": f"{CSRF_COOKIE}={env.csrf}",
        },
    )
    assert r.status == 421
    assert env.sink.answers == []


async def test_user_verification_required(env):
    await env.enrol()
    await env.send("a1")
    ch = await env.challenge("a1")
    assert (await env.approve("a1", env.auth.assert_(ch, uv=False))).status == 403


async def test_unknown_credential_and_forged_signature(env):
    await env.enrol()
    await env.send("a1")
    ch = await env.challenge("a1")
    other = Authenticator()
    assert (await env.approve("a1", other.assert_(ch))).status == 403
    other.cred_id = env.auth.cred_id  # right id, wrong key
    assert (await env.approve("a1", other.assert_(ch))).status == 403
    assert env.sink.answers == []


async def test_deny_needs_no_signature_but_needs_csrf(env):
    await env.send("a1")
    assert (await env.post("/api/approvals/a1/deny", csrf=False)).status == 403
    assert (await env.post("/api/approvals/a1/deny")).status == 200
    ((aid, answer),) = env.sink.answers
    assert aid == "a1" and answer.approved is False and answer.proof is None


async def test_already_resolved_elsewhere(env):
    await env.enrol()
    await env.send("a1")
    env.sink.result = AnswerStatus.ALREADY_RESOLVED
    r = await env.approve("a1", env.auth.assert_(await env.challenge("a1")))
    assert r.status == 409


async def test_failed_attempts_are_audited_and_rate_limited(env):
    await env.enrol()
    await env.send("a1")
    hdr = {"X-Real-IP": "100.64.0.9"}
    for _ in range(FAILURE_LIMIT):
        assert (await env.approve("a1", None, headers=hdr)).status == 403
    rows = await rejections(env.db)
    assert len(rows) == FAILURE_LIMIT
    assert all("100.64.0.9" in r.resolved_by and r.request_id == "a1" for r in rows)
    assert rows[0].tool_name == "gmail_send" and rows[0].agent_id == "hermes"
    # locked out: even a valid assertion from that source is refused with 429
    good = env.auth.assert_(await env.challenge("a1"))
    assert (await env.approve("a1", good, headers=hdr)).status == 429
    # another source is not affected
    assert (await env.approve("a1", good, headers={"X-Real-IP": "100.64.0.10"})).status == 200


# --- headers, cookies, bind ---


async def test_security_headers_and_cookie(env):
    r = await env.client.get("/", headers={"Host": HOST})
    assert r.status == 200
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    r = await env.client.get("/api/session", headers={"Host": HOST})
    cookie = r.headers["Set-Cookie"]
    assert CSRF_COOKIE in cookie and "SameSite=Strict" in cookie and "HttpOnly" in cookie
    r = await env.post("/api/approvals/zz/deny")
    assert r.headers["X-Frame-Options"] == "DENY"  # errors carry headers too


async def test_channel_binds_loopback_only_and_implements_interface(tmp_path):
    cfg = PasskeyConfig.from_mapping(
        {"enabled": True, "rp_id": RP_ID, "origin": ORIGIN, "port": 0}, str(tmp_path / "a.db")
    )
    ch = PasskeyChannel(cfg)
    assert (ch.name, ch.trust, set(ch.proof_kinds)) == ("passkey", "trusted", {"webauthn"})
    sink = Sink()
    await ch.start(sink)
    try:
        socks = ch._runner.addresses
        assert socks and all(a[0] == "127.0.0.1" for a in socks)
        assert ch.page.answer == sink.answer
    finally:
        await ch.stop()


def test_cli_enroll_prints_url(tmp_path, capsys):
    from agentpass.__main__ import main

    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"storage: {{type: sqlite, path: {tmp_path}/data/agentpass.db}}\n"
        f"passkey: {{enabled: true, rp_id: {RP_ID}, origin: '{ORIGIN}'}}\n"
    )
    with pytest.raises(SystemExit) as exc:
        main(["passkey", "enroll", "--config", str(cfg)])
    assert exc.value.code == 0
    assert f"{ORIGIN}/enroll?token=" in capsys.readouterr().out
    assert (tmp_path / "data" / "passkey-enroll.json").exists()


# --- through the real coordinator (no stub sink or answer class) ---


@pytest.fixture
async def live(tmp_path):
    cfg = PasskeyConfig.from_mapping(
        {"enabled": True, "rp_id": RP_ID, "origin": ORIGIN, "port": 0},
        str(tmp_path / "agentpass.db"),
    )
    db = Database(str(tmp_path / "agentpass.db"))
    await db.initialize()
    channel = PasskeyChannel(cfg, db=db)
    coordinator = ApprovalCoordinator(db, [channel])
    await coordinator.start()
    client = TestClient(TestServer(channel.page.build_app()))
    await client.start_server()
    r = await client.get("/api/session", headers={"Host": HOST})
    e = Env(channel, client, None, db, Authenticator(), (await r.json())["csrf"])
    yield e, coordinator
    await client.close()
    await coordinator.stop()
    await db.close()


def _live_request(approval_id="L1") -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=approval_id,
        agent_id="hermes",
        tool="ha_fire_event",
        signature="ha_fire_event",
        args={"event": "x"},
        expires_at=time.time() + 60,
        require="passkey",
    )


async def _wait_pending(env, approval_id):
    for _ in range(200):
        if approval_id in env.channel.page.pending:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("request never reached the page")


async def test_passkey_approve_resolves_the_real_coordinator(live):
    env, coordinator = live
    await env.enrol()
    task = asyncio.create_task(coordinator.request(_live_request()))
    await _wait_pending(env, "L1")
    ch = await env.challenge("L1")
    r = await env.approve("L1", env.auth.assert_(ch))
    assert r.status == 200, await r.text()
    outcome = await task
    assert outcome.approved and outcome.reason is ApprovalReason.APPROVED
    assert outcome.channel == "passkey" and outcome.proof["kind"] == "webauthn"
    assert outcome.remembered is None


async def test_passkey_deny_resolves_the_real_coordinator(live):
    env, coordinator = live
    task = asyncio.create_task(coordinator.request(_live_request()))
    await _wait_pending(env, "L1")
    r = await env.post("/api/approvals/L1/deny")
    assert r.status == 200, await r.text()
    outcome = await task
    assert not outcome.approved and outcome.reason is ApprovalReason.DENIED
    assert outcome.channel == "passkey"


async def test_passkey_page_never_asks_to_remember(live):
    env, coordinator = live
    task = asyncio.create_task(coordinator.request(_live_request()))
    await _wait_pending(env, "L1")
    seen: list[Answer] = []
    original = env.channel.page.answer

    async def spy(approval_id, answer):
        seen.append(answer)
        return await original(approval_id, answer)

    env.channel.page.answer = spy
    assert (await env.post("/api/approvals/L1/deny")).status == 200
    await task
    assert type(seen[0]) is Answer and seen[0].remember is None


async def test_page_reports_an_unknown_request_as_409(live):
    env, _ = live
    await env.send("ghost")  # shown on the page, but the coordinator has no such request
    r = await env.post("/api/approvals/ghost/deny")
    assert r.status == 409
