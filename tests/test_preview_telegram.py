"""Telegram rendering of previews, and preview.require_page through the pipeline."""

from __future__ import annotations

import asyncio
import contextlib
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from agentpass.approval import AnswerStatus, ApprovalRequest
from agentpass.approval.telegram_channel import TelegramChannel, message_text
from agentpass.config import (
    ArgDefinition,
    PermissionRule,
    Permissions,
    PreviewField,
    PreviewSpec,
    TelegramConfig,
    ToolDefinition,
)
from agentpass.engine import PermissionEngine
from agentpass.executor import Executor
from agentpass.pipeline import Pipeline
from agentpass.preview import Preview, Unavailable
from agentpass.registry import ToolRegistry
from tests.fakes import FakeChannel, started_coordinator, stateful_mock_db

APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174000"
CONFIG = TelegramConfig(token="123:fake", chat_id=-100, allowed_users=[42])
PAGE = "https://gate.example.ts.net"
NOTE = "SECRET-NOTE please approve, it is safe"


def _preview(**kw) -> Preview:
    base = {
        "title": "UNLOCK Front door",
        "summary": "UNLOCK Front door (lock.front_door), now: locked",
        "built_at": "2026-10-29T10:00:00Z",
        "warnings": ["w1", "w2"],
    }
    return Preview(**{**base, **kw}).seal()


def _req(**kw) -> ApprovalRequest:
    base = {
        "approval_id": APPROVAL_ID,
        "agent_id": "hermes",
        "agent_name": "Hermes",
        "tool": "ha_call_service",
        "signature": "lock.unlock, lock.front_door",
        "args": {"domain": "lock"},
        "expires_at": time.time() + 60,
        "agent_note": NOTE,
    }
    return ApprovalRequest(**{**base, **kw})


def _fake_app() -> MagicMock:
    app = MagicMock()
    app.bot.send_message = AsyncMock(return_value=SimpleNamespace(message_id=7))
    return app


def test_message_has_title_summary_and_warnings_but_never_the_agent_note():
    text = message_text(_req(preview=_preview()), PAGE)
    assert "📋 UNLOCK Front door" in text and "now: locked" in text
    assert "⚠ w1" in text and "⚠ w2" in text
    assert NOTE not in text and "SECRET" not in text


def test_only_the_top_three_warnings_are_shown():
    text = message_text(_req(preview=_preview(warnings=[f"w{i}" for i in range(1, 6)])), PAGE)
    assert "⚠ w3" in text and "⚠ w4" not in text and "2 more warnings on the page" in text


def test_summary_equal_to_title_is_not_repeated():
    text = message_text(_req(preview=_preview(summary="UNLOCK Front door")), PAGE)
    assert text.count("UNLOCK Front door") == 1


def test_unavailable_preview_says_so():
    text = message_text(_req(preview=Unavailable("timeout")), PAGE)
    assert "📋 Preview unavailable (timeout)" in text


def test_no_preview_leaves_the_message_as_before():
    assert "📋" not in message_text(_req(), PAGE)


async def test_page_link_button_with_the_usual_buttons():
    channel = TelegramChannel(CONFIG, application=_fake_app(), passkey_origin=PAGE)
    await channel.send(_req(preview=_preview()))
    markup = channel.application.bot.send_message.call_args.kwargs["reply_markup"]
    buttons = [b for row in markup.inline_keyboard for b in row]
    assert [b.text for b in buttons] == ["Allow once", "Deny once", "Review on the page"]
    assert buttons[-1].url == PAGE + "/"


async def test_no_link_button_without_a_preview_or_a_page():
    channel = TelegramChannel(CONFIG, application=_fake_app(), passkey_origin=PAGE)
    await channel.send(_req())
    markup = channel.application.bot.send_message.call_args.kwargs["reply_markup"]
    assert all(b.url is None for row in markup.inline_keyboard for b in row)
    channel = TelegramChannel(CONFIG, application=_fake_app())
    await channel.send(_req(preview=_preview()))
    markup = channel.application.bot.send_message.call_args.kwargs["reply_markup"]
    assert all(b.url is None for row in markup.inline_keyboard for b in row)


async def test_passkey_only_request_keeps_one_link_and_deny():
    channel = TelegramChannel(CONFIG, application=_fake_app(), passkey_origin=PAGE)
    await channel.send(_req(preview=_preview(), require="passkey"))
    (row,) = channel.application.bot.send_message.call_args.kwargs["reply_markup"].inline_keyboard
    assert [b.text for b in row] == ["Approve with passkey", "Deny"]


# --- preview.require_page ---


def _registry(require_page: bool) -> ToolRegistry:
    tool = ToolDefinition(
        name="tool_x",
        service_name="svc",
        args={"a": ArgDefinition()},
        preview=PreviewSpec(fields=[PreviewField("A", "{a}")], require_page=require_page),
    )
    return ToolRegistry({"tool_x": tool})


async def _pipeline(require_page: bool, *channels):
    executor = AsyncMock(spec=Executor)
    executor.execute.return_value = {"ok": True}
    db = stateful_mock_db()
    coordinator = await started_coordinator(db, *channels)
    rules = [PermissionRule(pattern="tool_x*", action="ask")]
    engine = PermissionEngine(Permissions(defaults=[], rules=rules))
    pipeline = Pipeline(
        engine=engine,
        executor=executor,
        coordinator=coordinator,
        db=db,
        registry=_registry(require_page),
    )
    return pipeline, executor


async def _first_sent(channel):
    for _ in range(200):
        if channel.sent:
            return channel.sent[-1].approval_id
        await asyncio.sleep(0.01)
    raise AssertionError("approval never sent")


async def test_require_page_refuses_a_telegram_approve_and_accepts_the_page():
    tg, page = FakeChannel(), FakeChannel("passkey", proof_kinds={"webauthn"})
    pipeline, executor = await _pipeline(True, tg, page)
    task = asyncio.create_task(pipeline.process("a", "tool_x", {"a": "1"}))
    approval_id = await _first_sent(tg)
    assert tg.last_request.require == page.last_request.require == "passkey"
    assert await tg.approve(approval_id) is AnswerStatus.REJECTED
    executor.execute.assert_not_awaited()
    assert await page.answer(approval_id, True, proof={"assertion": "ok"}) is AnswerStatus.ACCEPTED
    await task
    executor.execute.assert_awaited_once()


async def test_require_page_still_lets_telegram_deny():
    tg, page = FakeChannel(), FakeChannel("passkey", proof_kinds={"webauthn"})
    pipeline, executor = await _pipeline(True, tg, page)
    task = asyncio.create_task(pipeline.process("a", "tool_x", {"a": "1"}))
    approval_id = await _first_sent(tg)
    assert await tg.deny(approval_id) is AnswerStatus.ACCEPTED
    with contextlib.suppress(Exception):
        await task
    executor.execute.assert_not_awaited()


async def test_without_require_page_telegram_can_approve():
    tg = FakeChannel()
    pipeline, executor = await _pipeline(False, tg)
    task = asyncio.create_task(pipeline.process("a", "tool_x", {"a": "1"}))
    approval_id = await _first_sent(tg)
    assert tg.last_request.require == "any_trusted"
    assert await tg.approve(approval_id) is AnswerStatus.ACCEPTED
    await task
    executor.execute.assert_awaited_once()
