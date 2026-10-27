"""Display-only notify channels: webhook / command transports, no way to approve."""

from __future__ import annotations

import asyncio
import stat
import sys
import time

import aiohttp
import pytest
from aiohttp import web

from agentpass.approval import (
    Answer,
    AnswerStatus,
    ApprovalCoordinator,
    ApprovalReason,
    ApprovalRequest,
    build_channels,
)
from agentpass.approval.notify_channel import NotifyChannel
from agentpass.config import ConfigError, NotifyConfig, _load_channels
from agentpass.db import Database
from agentpass.passkey.page import PasskeyConfig
from tests.fakes import FakeChannel


@pytest.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "n.db"))
    await database.initialize()
    yield database
    await database.close()


def _req(approval_id="r1", **kw) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=approval_id,
        agent_id="a1",
        agent_name="deploy-bot",
        tool="gh_merge_pr",
        signature="gh_merge_pr(repo=x/y)",
        args={"repo": "x/y", "branch": "main"},
        arg_display={"repo": "repository"},
        risk="high",
        expires_at=time.time() + 60,
        **kw,
    )


class Stub:
    """Local aiohttp server recording POSTs; ``statuses`` is consumed one per request."""

    def __init__(self, statuses=(200,)):
        self.statuses = list(statuses)
        self.bodies: list[dict] = []

    async def handler(self, request):
        self.bodies.append(await request.json())
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return web.Response(status=status)

    async def __aenter__(self):
        app = web.Application()
        app.router.add_post("/hook", self.handler)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/hook"
        return self

    async def __aexit__(self, *exc):
        await self.runner.cleanup()


def _webhook(url, origin=None, name="hermes") -> NotifyChannel:
    return NotifyChannel(
        NotifyConfig(transport="webhook", url=url, timeout=2), name=name, link_origin=origin
    )


def _script(tmp_path, body: str, name="notify.py") -> list[str]:
    path = tmp_path / name
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return [sys.executable, str(path)]


# --- message content ---


async def test_message_carries_agent_tool_args_risk_expiry_and_link():
    async with Stub() as stub:
        channel = _webhook(stub.url, origin="https://gate.example")
        await channel.send(_req())
        await channel.stop()
    text = stub.bodies[0]["text"]
    for needle in ("deploy-bot", "gh_merge_pr", "repository", "x/y", "main", "high", "Expires:"):
        assert needle in text
    assert "https://gate.example/" in text
    assert stub.bodies[0]["approval_id"] == "r1"


async def test_message_has_no_link_without_passkey_page():
    async with Stub() as stub:
        channel = _webhook(stub.url)
        await channel.send(_req())
        await channel.stop()
    assert "http" not in stub.bodies[0]["text"]


# --- webhook retry rules ---


async def test_webhook_4xx_is_not_retried():
    async with Stub(statuses=(400,)) as stub:
        channel = _webhook(stub.url)
        with pytest.raises(RuntimeError):
            await channel.send(_req())
        await channel.stop()
    assert len(stub.bodies) == 1


async def test_webhook_connection_error_retries_once():
    channel = _webhook("http://127.0.0.1:1/hook")
    calls = 0

    class Boom:
        def post(self, *a, **kw):
            nonlocal calls
            calls += 1
            raise aiohttp.ClientConnectionError("down")

    channel._transport._session = Boom()
    with pytest.raises(aiohttp.ClientConnectionError):
        await channel.send(_req())
    assert calls == 2


# --- command transport ---


async def test_command_gets_message_on_stdin_without_shell(tmp_path):
    out = tmp_path / "out.txt"
    argv = _script(
        tmp_path, f"import sys\nopen({str(out)!r}, 'a').write(sys.stdin.read() + '\\n--\\n')\n"
    )
    channel = NotifyChannel(NotifyConfig(transport="command", command=argv), name="paseo")
    await channel.send(_req())
    assert "gh_merge_pr" in out.read_text()


async def test_command_nonzero_exit_is_a_failed_delivery(tmp_path):
    argv = _script(tmp_path, "import sys\nsys.exit(3)\n")
    channel = NotifyChannel(NotifyConfig(transport="command", command=argv), name="paseo")
    with pytest.raises(RuntimeError, match="status 3"):
        await channel.send(_req())


async def test_command_timeout_kills_the_process(tmp_path):
    argv = _script(tmp_path, "import time\ntime.sleep(30)\n")
    channel = NotifyChannel(
        NotifyConfig(transport="command", command=argv, timeout=0.3), name="paseo"
    )
    with pytest.raises(TimeoutError):
        await channel.send(_req())


async def test_failed_command_does_not_break_the_request(db, tmp_path):
    argv = _script(tmp_path, "import sys\nsys.exit(1)\n")
    paseo = NotifyChannel(NotifyConfig(transport="command", command=argv), name="paseo")
    tg = FakeChannel()
    coordinator = ApprovalCoordinator(db, [tg, paseo])
    await coordinator.start()
    task = asyncio.create_task(coordinator.request(_req()))
    while not tg.sent:
        await asyncio.sleep(0.01)
    await tg.sink.answer("r1", Answer(True, "telegram", "owner", proof=True))
    outcome = await task
    assert outcome.approved and outcome.reason is ApprovalReason.APPROVED
    await coordinator.stop()


# --- cannot approve ---


async def test_notify_channel_cannot_resolve_an_approval(db):
    async with Stub() as stub:
        hermes = _webhook(stub.url)
        tg = FakeChannel()
        coordinator = ApprovalCoordinator(db, [tg, hermes])
        await coordinator.start()
        task = asyncio.create_task(coordinator.request(_req()))
        while not stub.bodies:
            await asyncio.sleep(0.01)
        for approved in (True, False):
            status = await coordinator.answer(
                "r1", Answer(approved, "hermes", "plugin", proof={"kind": "webauthn"})
            )
            assert status is AnswerStatus.REJECTED
        assert (await db.get_pending("r1"))["state"] == "pending"
        assert not task.done()
        # the trusted channel still resolves it, and the notify channel gets the follow-up
        assert await tg.sink.answer("r1", Answer(False, "telegram", "owner")) is (
            AnswerStatus.ACCEPTED
        )
        outcome = await task
        assert outcome.reason is ApprovalReason.DENIED
        for _ in range(100):
            if len(stub.bodies) >= 2:
                break
            await asyncio.sleep(0.01)
        await coordinator.stop()
    resolved = stub.bodies[1]
    assert resolved["event"] == "approval_resolved" and resolved["approved"] is False
    assert "Denied by owner" in resolved["text"]


def test_notify_channel_declares_no_authority():
    channel = _webhook("http://127.0.0.1:1/hook")
    assert channel.trust == "notify"
    assert channel.proof_kinds == set()


async def test_start_does_not_keep_the_sink():
    channel = _webhook("http://127.0.0.1:1/hook")
    await channel.start(object())
    assert not any(hasattr(channel, a) for a in ("sink", "_sink"))


async def test_finalize_posts_expiry_follow_up():
    async with Stub() as stub:
        channel = _webhook(stub.url)
        handle = await channel.send(_req())
        from agentpass.approval import ApprovalOutcome

        await channel.finalize(handle, ApprovalOutcome("r1", False, ApprovalReason.TIMEOUT))
        await channel.stop()
    assert "Expired" in stub.bodies[1]["text"]


async def test_finalize_failure_is_swallowed(tmp_path):
    argv = _script(tmp_path, "import sys\nsys.exit(1)\n")
    channel = NotifyChannel(NotifyConfig(transport="command", command=argv), name="paseo")
    from agentpass.approval import ApprovalOutcome, ChannelHandle

    await channel.finalize(
        ChannelHandle("paseo", {"approval_id": "r1"}),
        ApprovalOutcome("r1", True, ApprovalReason.APPROVED, approver_id="owner"),
    )


# --- config ---


def test_webhook_and_command_are_configured_alongside_telegram(tmp_path):
    raw = {
        "channels": [
            {"name": "tg", "type": "telegram", "token": "t", "chat_id": 1, "allowed_users": [1]},
            {"name": "hermes", "type": "webhook", "url": "http://127.0.0.1:9/h"},
            {"name": "paseo", "type": "command", "command": ["paseo-notify", "--stdin"]},
        ]
    }
    entries = _load_channels(raw)
    assert [e.trust for e in entries] == ["trusted", "notify", "notify"]
    passkey = PasskeyConfig(
        enabled=True, rp_id="g", origin="https://g", store_path=str(tmp_path / "p.json")
    )

    class Cfg:
        channels = entries
        passkey = None

    Cfg.passkey = passkey
    channels = build_channels(Cfg)
    assert [c.name for c in channels] == ["tg", "hermes", "paseo"]
    assert [c.trust for c in channels] == ["trusted", "notify", "notify"]
    assert "https://g/" in message_link(channels[1])


def message_link(channel):
    return channel._link


@pytest.mark.parametrize(
    "entry, match",
    [
        ({"type": "webhook"}, "url"),
        ({"type": "webhook", "url": "ftp://x"}, "http"),
        ({"type": "webhook", "url": "http://x", "command": ["a"]}, "unknown keys"),
        ({"type": "webhook", "url": "http://x", "trust": "trusted"}, "notify"),
        ({"type": "command"}, "command"),
        ({"type": "command", "command": []}, "non-empty"),
        ({"type": "command", "command": ["a"], "url": "http://x"}, "unknown keys"),
        ({"type": "command", "command": ["a"], "timeout": 0}, "timeout"),
    ],
)
def test_invalid_notify_entries_are_rejected(entry, match):
    with pytest.raises(ConfigError, match=match):
        _load_channels({"channels": [{"name": "n", **entry}]})


def test_command_string_is_split_into_argv_not_a_shell():
    (entry,) = _load_channels(
        {"channels": [{"name": "n", "type": "command", "command": "notify --flag 'a b'"}]}
    )
    assert entry.notify.command == ["notify", "--flag", "a b"]
