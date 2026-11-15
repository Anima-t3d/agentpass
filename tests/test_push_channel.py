"""Push approval channel: notification actions resolve approvals, never past the rule.

A fake transport stands in for the browser push service; each test device decrypts what
it is sent with its own subscription keys, as the browser would.
"""

from __future__ import annotations

import asyncio
import logging
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp.test_utils import TestClient, TestServer

from agentpass.approval import (
    Answer,
    AnswerStatus,
    ApprovalCoordinator,
    ApprovalReason,
    ApprovalRequest,
    ChannelUnavailable,
    build_channels,
)
from agentpass.approval.coordinator import satisfies
from agentpass.config import ChannelConfig, ConfigError
from agentpass.db import Database
from agentpass.engine import Evaluation, PermissionEngine
from agentpass.executor import Executor
from agentpass.models import Decision
from agentpass.passkey.channel import PasskeyChannel
from agentpass.passkey.page import PasskeyConfig
from agentpass.passkey.session import SESSION_COOKIE
from agentpass.pipeline import ApprovalDenied, Pipeline
from agentpass.preview import Preview, Unavailable
from agentpass.push.channel import PushChannel
from agentpass.push.models import PushDevice
from agentpass.push.webpush import generate_vapid_key, public_key_b64, save_vapid_key
from tests.fakes import FakeChannel
from tests.push_helpers import Subscriber

ORIGIN = "https://gate.example.ts.net"
RP_ID = "gate.example.ts.net"
HOST = "gate.example.ts.net"
SUBJECT = "mailto:owner@example.com"
ALLOWED = {"type", "approval_id", "title", "body", "require", "one_tap", "token", "expires_at"}


class FakeTransport:
    """Records each push; per-endpoint status and delay."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], bytes, float]] = []
        self.status: dict[str, int] = {}
        self.delay: dict[str, float] = {}

    async def __call__(self, endpoint, headers, body, timeout) -> int:
        if endpoint in self.delay:
            await asyncio.sleep(self.delay[endpoint])
        self.calls.append((endpoint, headers, body, timeout))
        return self.status.get(endpoint, 201)

    def bodies(self, sub: Subscriber) -> list[dict]:
        return [sub.open(body) for ep, _, body, _ in self.calls if ep == sub.endpoint]


async def until(cond, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > deadline:
            raise AssertionError("condition never became true")
        await asyncio.sleep(0.01)


def _config(tmp_path, push=None) -> PasskeyConfig:
    push = {"enabled": True, "subject": SUBJECT} if push is None else push
    return PasskeyConfig.from_mapping(
        {"enabled": True, "rp_id": RP_ID, "origin": ORIGIN, "port": 0, "push": push},
        str(tmp_path / "agentpass.db"),
    )


class Env:
    def __init__(self, cfg, db, passkey, push, transport, coordinator, client):
        self.cfg, self.db, self.passkey, self.push = cfg, db, passkey, push
        self.transport, self.coordinator, self.client = transport, coordinator, client
        self.n = 0

    async def device(self, label="Pixel 8", one_tap=False) -> tuple[PushDevice, Subscriber]:
        self.n += 1
        sub = Subscriber(f"https://push.example.com/send/{self.n}")
        now = "2026-11-15T00:00:00Z"
        device = await self.db.upsert_push_device(
            PushDevice(
                f"dev{self.n}", label, sub.endpoint, sub.p256dh, sub.auth, False, "c", now, now
            )
        )
        if one_tap:
            await self.db.set_push_device(device.device_id, one_tap_approve=True)
        return device, sub

    async def pushed(self, sub: Subscriber, kind="approval", count=1) -> dict:
        await until(
            lambda: len([b for b in self.transport.bodies(sub) if b["type"] == kind]) >= count
        )
        return [b for b in self.transport.bodies(sub) if b["type"] == kind][count - 1]

    async def action(self, approval_id, action, token, *, origin=ORIGIN):
        return await self.client.post(
            "/api/push/action",
            json={"approval_id": approval_id, "action": action, "token": token},
            headers={"Origin": origin, "Host": HOST},
        )


@pytest.fixture
async def env(tmp_path):
    cfg = _config(tmp_path)
    save_vapid_key(generate_vapid_key(), cfg.push.vapid_key_path)
    db = Database(str(tmp_path / "agentpass.db"))
    await db.initialize()
    transport = FakeTransport()
    passkey = PasskeyChannel(cfg, db=db)
    push = PushChannel(cfg.push, page=passkey.page, db=db, transport=transport)
    telegram = FakeChannel("telegram")
    coordinator = ApprovalCoordinator(db, [passkey, push, telegram])
    await coordinator.start()
    client = TestClient(TestServer(passkey.page.build_app()))
    await client.start_server()
    e = Env(cfg, db, passkey, push, transport, coordinator, client)
    e.telegram = telegram
    yield e
    await client.close()
    await coordinator.stop()
    await db.close()


def _req(approval_id="P1", require="any_trusted", **kw) -> ApprovalRequest:
    base = dict(
        approval_id=approval_id,
        agent_id="hermes",
        agent_name="Hermes",
        tool="ha_fire_event",
        signature="ha_fire_event(event)",
        args={"event": "x"},
        expires_at=time.time() + 60,
        require=require,
    )
    base.update(kw)
    return ApprovalRequest(**base)


def _ask(env, req, **kw) -> asyncio.Task:
    return asyncio.create_task(env.coordinator.request(req, **kw))


# --- send ---


async def test_send_without_devices_raises(env):
    with pytest.raises(RuntimeError, match="no push devices"):
        await env.push.send(_req())
    assert env.transport.calls == []


async def test_unavailable_push_channel_is_skipped_with_one_info_line(env, caplog):
    assert issubclass(ChannelUnavailable, RuntimeError)
    with pytest.raises(ChannelUnavailable, match="no push devices"):
        await env.push.send(_req())
    with caplog.at_level(logging.INFO, logger="agentpass"):
        assert await env.coordinator._send(env.push, _req()) is None
    [record] = [r for r in caplog.records if "skipped" in r.getMessage()]
    assert record.levelno == logging.INFO and record.exc_info is None
    assert record.getMessage() == "Approval channel push skipped P1: no push devices"
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


async def test_payload_has_only_allowed_fields_and_no_args(env):
    _, sub = await env.device()
    secret = "sk-live-SECRET-9f8e7d"
    req = _req(args={"api_key": secret}, agent_note="note-do-not-leak", expires_at=time.time() + 90)
    handle = await env.push.send(req)
    assert handle.channel == "push" and handle.ref == {"approval_id": "P1"}
    payload = await env.pushed(sub)
    assert set(payload) == ALLOWED
    assert payload["title"] == "Hermes → ha_fire_event"
    assert payload["body"] == "ha_fire_event(event)"  # no Preview: the signature
    assert payload["require"] == "any_trusted" and payload["one_tap"] is False
    assert payload["approval_id"] == "P1" and int(payload["expires_at"]) == int(req.expires_at)
    _, headers, body, timeout = env.transport.calls[0]
    plain = sub.open(body)
    assert secret not in str(plain) and "note-do-not-leak" not in str(plain)
    assert secret.encode() not in body and b"Hermes" not in body  # encrypted on the wire
    assert headers["Content-Encoding"] == "aes128gcm" and headers["Urgency"] == "high"
    assert 85 <= int(headers["TTL"]) <= 90
    assert headers["Authorization"].startswith("vapid t=") and timeout == 10.0


async def test_payload_body_uses_preview_title_only_for_a_preview(env):
    _, sub = await env.device()
    long_name = "A" * 300
    preview = Preview(title="Lock Front door", summary="secret summary", built_at="now")
    await env.push.send(_req("P1", preview=preview, agent_name=long_name))
    await env.push.send(_req("P2", preview=Unavailable("lookup failed")))
    first = await env.pushed(sub)
    second = await env.pushed(sub, count=2)
    assert first["body"] == "Lock Front door" and "secret summary" not in str(first)
    assert len(first["title"]) == 120
    assert second["body"] == "ha_fire_event(event)"


# --- actions through the real coordinator ---


async def test_deny_from_notification_resolves_real_coordinator(env):
    device, sub = await env.device()
    task = _ask(env, _req())
    payload = await env.pushed(sub)
    r = await env.action("P1", "deny", payload["token"])
    assert r.status == 200, await r.text()
    outcome = await task
    assert not outcome.approved and outcome.reason is ApprovalReason.DENIED
    assert outcome.channel == "push" and outcome.approver_id == "push:Pixel 8:notification"
    assert (await env.db.get_push_device(device.device_id)).last_seen != "2026-11-15T00:00:00Z"


async def test_one_tap_off_approve_returns_open_link(env):
    _, sub = await env.device(one_tap=False)
    task = _ask(env, _req())
    payload = await env.pushed(sub)
    assert payload["one_tap"] is False
    r = await env.action("P1", "approve", payload["token"])
    assert r.status == 409 and await r.json() == {"open": "/a/P1"}
    assert not task.done()
    # the token was not consumed: the same tap can still deny
    r = await env.action("P1", "deny", payload["token"])
    assert r.status == 200
    assert not (await task).approved


async def test_one_tap_on_any_trusted_approves(env):
    device, sub = await env.device(one_tap=True)
    task = _ask(env, _req())
    payload = await env.pushed(sub)
    assert payload["one_tap"] is True
    r = await env.action("P1", "approve", payload["token"])
    assert r.status == 200, await r.text()
    outcome = await task
    assert outcome.approved and outcome.channel == "push"
    assert outcome.proof == {"kind": "push_action", "device_id": device.device_id}
    # single use
    r = await env.action("P1", "approve", payload["token"])
    assert r.status == 410


async def test_one_tap_read_from_db_at_action_time(env):
    device, sub = await env.device(one_tap=True)
    task = _ask(env, _req())
    payload = await env.pushed(sub)
    await env.db.set_push_device(device.device_id, one_tap_approve=False)
    r = await env.action("P1", "approve", payload["token"])
    assert r.status == 409 and not task.done()
    await env.action("P1", "deny", payload["token"])
    await task


async def test_one_tap_on_require_passkey_returns_open_link_and_coordinator_would_reject(env):
    _, sub = await env.device(one_tap=True)
    task = _ask(env, _req(require="passkey"))
    payload = await env.pushed(sub)
    assert payload["one_tap"] is False and payload["require"] == "passkey"
    r = await env.action("P1", "approve", payload["token"])
    assert r.status == 409 and await r.json() == {"open": "/a/P1"}
    # even an answer forged past the endpoint does not count
    forged = Answer(True, "push", "push:x:notification", proof={"kind": "push_action"})
    assert await env.coordinator.answer("P1", forged) is AnswerStatus.REJECTED
    assert satisfies(env.push, forged, "passkey") is False
    assert satisfies(env.push, forged, "telegram") is False
    assert "webauthn" not in env.push.proof_kinds
    assert "telegram_callback" not in env.push.proof_kinds
    assert not task.done()
    assert (await env.action("P1", "deny", payload["token"])).status == 200
    await task
    # require: telegram is refused on the notification too
    await env.push.send(_req("T1", require="telegram"))
    payload = await env.pushed(sub, count=2)
    assert payload["one_tap"] is False
    r = await env.action("T1", "approve", payload["token"])
    assert r.status == 409 and await r.json() == {"open": "/a/T1"}


async def test_second_device_token_refused_after_resolution(env):
    _, phone = await env.device("Pixel 8")
    _, laptop = await env.device("Laptop")
    task = _ask(env, _req())
    on_phone, on_laptop = await env.pushed(phone), await env.pushed(laptop)
    assert on_phone["token"] != on_laptop["token"]
    assert (await env.action("P1", "deny", on_phone["token"])).status == 200
    await task
    resolved = await env.pushed(laptop, "resolved")
    assert resolved == {
        "type": "resolved",
        "approval_id": "P1",
        "approved": False,
        "reason": "denied",
    }
    r = await env.action("P1", "deny", on_laptop["token"])
    assert r.status == 410 and await r.json() == {"error": "already resolved"}


async def test_two_devices_tapping_at_once_resolve_once(env):
    _, phone = await env.device("Pixel 8", one_tap=True)
    _, laptop = await env.device("Laptop")
    task = _ask(env, _req())
    on_phone, on_laptop = await env.pushed(phone), await env.pushed(laptop)
    responses = await asyncio.gather(
        env.action("P1", "approve", on_phone["token"]),
        env.action("P1", "deny", on_laptop["token"]),
    )
    statuses = [r.status for r in responses]
    assert sorted(statuses)[0] == 200 and sorted(statuses)[1] in (409, 410), statuses
    outcome = await task
    winner = responses[statuses.index(200)]
    assert outcome.approved is (await winner.json())["approved"]
    await until(lambda: env.telegram.finalized)
    await asyncio.sleep(0.05)
    assert [h.ref for h, _ in env.telegram.finalized] == [{"message_id": 1}]  # resolved once


async def test_finalize_pushes_resolved_and_action_after_is_410(env):
    _, sub = await env.device(one_tap=True)
    task = _ask(env, _req())
    payload = await env.pushed(sub)
    await until(lambda: env.telegram.sent)
    assert await env.telegram.approve("P1") is AnswerStatus.ACCEPTED
    assert (await task).channel == "telegram"
    resolved = await env.pushed(sub, "resolved")
    assert resolved["approved"] is True and resolved["reason"] == "approved"
    for action in ("approve", "deny"):
        r = await env.action("P1", action, payload["token"])
        assert r.status == 410 and await r.json() == {"error": "already resolved"}


async def test_bad_tokens_are_refused_without_an_answer(env):
    _, sub = await env.device(one_tap=True)
    task = _ask(env, _req())
    payload = await env.pushed(sub)
    for token in ("", "garbage", payload["token"][:-2] + "AA"):
        r = await env.action("P1", "approve", token)
        assert r.status == 401 and await r.json() == {"error": "invalid token"}
    await env.push.send(_req("P2"))
    other = await env.pushed(sub, count=2)
    assert (await env.action("P1", "approve", other["token"])).status == 401  # wrong approval
    assert (await env.action("nope", "deny", payload["token"])).status == 410
    assert (await env.action("P1", "maybe", payload["token"])).status == 400
    assert not task.done()
    await env.action("P1", "deny", payload["token"])
    await task


async def test_action_needs_origin_but_no_csrf(env):
    _, sub = await env.device()
    task = _ask(env, _req())
    payload = await env.pushed(sub)
    r = await env.action("P1", "deny", payload["token"], origin="https://evil.example")
    assert r.status == 403 and not task.done()
    # other writes still need CSRF
    r = await env.client.post("/api/approvals/P1/deny", headers={"Origin": ORIGIN, "Host": HOST})
    assert r.status == 403
    assert (await env.action("P1", "deny", payload["token"])).status == 200
    await task


# --- delivery ---


@pytest.mark.parametrize("status", [404, 410])
async def test_gone_endpoint_removes_device(env, status):
    gone, gone_sub = await env.device("Old")
    kept, kept_sub = await env.device("New")
    env.transport.status[gone_sub.endpoint] = status
    env.transport.status[kept_sub.endpoint] = 500
    await env.push.send(_req())
    await until(lambda: len(env.transport.calls) == 2)
    await until(lambda: not env.push._tasks)
    assert await env.db.get_push_device(gone.device_id) is None
    assert await env.db.get_push_device(kept.device_id) is not None  # 500 is not "gone"


async def test_slow_endpoint_does_not_block_send(env):
    _, slow = await env.device("Slow")
    _, fast = await env.device("Fast")
    env.transport.delay[slow.endpoint] = 30
    started = time.monotonic()
    await env.push.send(_req())
    assert time.monotonic() - started < 0.5
    await env.pushed(fast)
    assert env.transport.bodies(slow) == []
    await env.push.stop()  # cancels the hanging delivery
    assert not env.push._tasks


async def test_push_timeout_bounds_an_injected_transport(tmp_path, caplog):
    cfg = _config(tmp_path, {"enabled": True, "subject": SUBJECT, "timeout": 0.05})
    save_vapid_key(generate_vapid_key(), cfg.push.vapid_key_path)
    db = Database(str(tmp_path / "agentpass.db"))
    await db.initialize()
    transport = FakeTransport()
    page = PasskeyChannel(cfg, db=db).page
    push = PushChannel(cfg.push, page=page, db=db, transport=transport)
    await push.start(AsyncMock())
    sub = Subscriber("https://push.example.com/slow")
    now = "t"
    await db.upsert_push_device(
        PushDevice("d", "D", sub.endpoint, sub.p256dh, sub.auth, False, "", now, now)
    )
    transport.delay[sub.endpoint] = 30
    with caplog.at_level(logging.DEBUG):
        handle = await push.send(_req())
        await until(lambda: not push._tasks)
        await push.finalize(handle, MagicMock(approved=False, reason=ApprovalReason.TIMEOUT))
        await until(lambda: not push._tasks)
    messages = [r.getMessage() for r in caplog.records]
    assert any("timed out" in m.lower() or "timeout" in m.lower() for m in messages)
    assert not any(sub.p256dh in m or sub.endpoint in m or "BEGIN" in m for m in messages)
    await push.stop()
    await db.close()


async def test_missing_vapid_key_makes_send_raise(tmp_path, caplog):
    cfg = _config(tmp_path)
    db = Database(str(tmp_path / "agentpass.db"))
    await db.initialize()
    page = PasskeyChannel(cfg, db=db).page
    push = PushChannel(cfg.push, page=page, db=db, transport=FakeTransport())
    with caplog.at_level(logging.ERROR):
        await push.start(AsyncMock())
    assert any("vapid" in r.getMessage().lower() for r in caplog.records)
    assert await push.health_check() is False
    with pytest.raises(ChannelUnavailable, match="VAPID"):
        await push.send(_req())
    await push.stop()
    await db.close()


async def test_vapid_endpoint_requires_a_session(env):
    r = await env.client.get("/api/push/vapid", headers={"Host": HOST})
    assert r.status == 401
    token = env.passkey.page.sessions.create("cred-1")
    r = await env.client.get(
        "/api/push/vapid", headers={"Host": HOST, "Cookie": f"{SESSION_COOKIE}={token}"}
    )
    assert r.status == 200
    assert (await r.json())["public_key"] == public_key_b64(env.push._key)


# --- audit ---


async def test_audit_resolved_by_names_device_and_notification(env):
    _, sub = await env.device("Pixel 8")
    engine = MagicMock(spec=PermissionEngine)
    engine.evaluate.return_value = Evaluation(Decision.ASK)
    executor = AsyncMock(spec=Executor)
    pipeline = Pipeline(engine=engine, executor=executor, coordinator=env.coordinator, db=env.db)
    task = asyncio.create_task(pipeline.process("hermes", "ha_fire_event", {"event": "x"}))
    payload = await env.pushed(sub)
    r = await env.action(payload["approval_id"], "deny", payload["token"])
    assert r.status == 200, await r.text()
    with pytest.raises(ApprovalDenied):
        await task
    entry = (await env.db.get_audit_log())[0]
    assert entry.request_id == payload["approval_id"]
    assert entry.resolved_by == "push:Pixel 8:notification"
    executor.execute.assert_not_awaited()


# --- config and wiring ---


def test_config_requires_subject_and_passkey_page(tmp_path):
    db_path = str(tmp_path / "data" / "agentpass.db")
    off = PasskeyConfig.from_mapping({"enabled": True, "rp_id": RP_ID, "origin": ORIGIN}, db_path)
    assert off.push.enabled is False and off.push.timeout == 10
    assert off.push.vapid_key_path == str(tmp_path / "data" / "push-vapid.pem")
    for push in ({"enabled": True}, {"enabled": True, "subject": "owner@example.com"}):
        with pytest.raises(ConfigError, match="subject"):
            PasskeyConfig.from_mapping(
                {"enabled": True, "rp_id": RP_ID, "origin": ORIGIN, "push": push}, db_path
            )
    with pytest.raises(ConfigError, match="passkey page"):
        PasskeyConfig.from_mapping(
            {
                "enabled": False,
                "rp_id": RP_ID,
                "origin": ORIGIN,
                "push": {"enabled": True, "subject": SUBJECT},
            },
            db_path,
        )
    ok = PasskeyConfig.from_mapping(
        {
            "enabled": True,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "push": {"enabled": True, "subject": "https://example.com", "vapid_key_path": "/k.pem"},
        },
        db_path,
    )
    assert ok.push.enabled and ok.push.vapid_key_path == "/k.pem"


def test_build_channels_adds_push_after_passkey(tmp_path):
    class Cfg:
        def __init__(self, passkey):
            self.passkey = passkey
            self.channels = [ChannelConfig(name="page", type="passkey", passkey=passkey)]

    on = build_channels(Cfg(_config(tmp_path)))
    assert [c.name for c in on] == ["passkey", "push"]
    assert on[1].page is on[0].page and on[1].proof_kinds == {"push_action"}
    off = build_channels(Cfg(_config(tmp_path, {"enabled": False})))
    assert [c.name for c in off] == ["passkey"]


async def test_stop_lets_a_just_finalized_resolved_push_go_out(env):
    from agentpass.approval import ChannelHandle
    from agentpass.approval.channel import ApprovalOutcome

    _, sub = await env.device()
    env.transport.delay[sub.endpoint] = 0.2
    outcome = ApprovalOutcome("P1", True, ApprovalReason.APPROVED)
    await env.push.finalize(ChannelHandle("push", {"approval_id": "P1"}), outcome)
    await env.push.stop()  # right away: the in-flight push is waited for, not cancelled
    [resolved] = env.transport.bodies(sub)
    assert resolved["type"] == "resolved" and resolved["approved"] is True


async def test_stop_cancels_a_push_that_outlasts_the_grace(env, monkeypatch):
    from agentpass.approval import ChannelHandle
    from agentpass.approval.channel import ApprovalOutcome
    from agentpass.push import channel

    monkeypatch.setattr(channel, "STOP_GRACE", 0.05)
    _, sub = await env.device()
    env.transport.delay[sub.endpoint] = 5
    outcome = ApprovalOutcome("P1", True, ApprovalReason.APPROVED)
    await env.push.finalize(ChannelHandle("push", {"approval_id": "P1"}), outcome)
    started = time.monotonic()
    await env.push.stop()
    assert time.monotonic() - started < 1 and env.transport.calls == []


def test_clip_never_cuts_an_escape_and_stays_within_the_limit():
    from agentpass.push.channel import TEXT_LIMIT, _clip

    out = _clip("x" * 115 + "\u202e")  # the bidi mark escapes to 6 characters: 121 in all
    assert out == "x" * 115 + "…"  # the escape is dropped whole, never cut to "\\u20"
    assert _clip("x" * 118 + "\u202e" * 3) == "x" * 118 + "…"
    assert len(_clip("\u202e" * 100)) <= TEXT_LIMIT
    assert _clip("short \u202e") == "short \\u202e"
    assert _clip("y" * 300) == "y" * (TEXT_LIMIT - 1) + "…"
