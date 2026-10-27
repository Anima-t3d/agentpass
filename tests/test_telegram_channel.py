"""Telegram approval channel: stateless callbacks, edits in finalize and scope step, no network."""

from __future__ import annotations

import re
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram.ext import Application

from agentpass.approval import (
    Answer,
    AnswerStatus,
    ApprovalOutcome,
    ApprovalReason,
    ApprovalRequest,
    ChannelHandle,
    RememberOffer,
    build_channels,
)
from agentpass.approval.telegram_channel import (
    CALLBACK_PATTERN,
    TelegramChannel,
    message_text,
    resolved_text,
)
from agentpass.config import ChannelConfig, TelegramConfig

APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174000"
CONFIG = TelegramConfig(token="123:fake", chat_id=-100, allowed_users=[42])


def _req(**kw) -> ApprovalRequest:
    base = {
        "approval_id": APPROVAL_ID,
        "agent_id": "hermes",
        "agent_name": "Hermes",
        "tool": "ha_call_service",
        "signature": "ha_call_service(light.turn_on, light.bedroom)",
        "args": {"domain": "light", "service": "turn_on", "brightness": 80},
        "expires_at": time.time() + 60,
    }
    return ApprovalRequest(**{**base, **kw})


def _fake_app() -> MagicMock:
    app = MagicMock()
    app.bot.send_message = AsyncMock(return_value=SimpleNamespace(message_id=7))
    app.bot.edit_message_text = AsyncMock()
    for name in ("initialize", "start", "stop", "shutdown"):
        setattr(app, name, AsyncMock())
    app.updater.start_polling = AsyncMock()
    app.updater.stop = AsyncMock()
    app.running = True
    return app


class _Sink:
    def __init__(self, status=AnswerStatus.ACCEPTED):
        self.status = status
        self.answers: list[tuple[str, Answer]] = []

    async def answer(self, approval_id, answer):
        self.answers.append((approval_id, answer))
        return self.status


def _query(data, user_id=42, chat_id=-100):
    query = MagicMock()
    query.data = data
    query.from_user.id = user_id
    query.message.chat.id = chat_id
    query.answer = AsyncMock()
    return SimpleNamespace(callback_query=query), query


@pytest.fixture
def channel():
    return TelegramChannel(CONFIG, application=_fake_app())


# --- send ---


async def test_send_posts_buttons_with_stateless_callback_data(channel):
    handle = await channel.send(_req())

    kwargs = channel.application.bot.send_message.call_args.kwargs
    assert kwargs["chat_id"] == -100
    buttons = kwargs["reply_markup"].inline_keyboard[0]
    assert [(b.text, b.callback_data) for b in buttons] == [
        ("Allow once", f"{APPROVAL_ID}:y"),
        ("Deny once", f"{APPROVAL_ID}:n"),
    ]
    assert all(len(b.callback_data.encode()) <= 64 for b in buttons)
    assert all(re.match(CALLBACK_PATTERN, b.callback_data) for b in buttons)
    assert handle.channel == "telegram" and handle.ref["message_id"] == 7
    assert handle.ref["text"] == kwargs["text"]


def test_message_text_keeps_the_existing_format():
    text = message_text(_req(risk="high"))
    assert text.split("\n") == [
        "\U0001f6a8 ha_call_service",
        "Agent: Hermes",
        "Risk: high",
        "ha_call_service(light.turn_on, light.bedroom)",
        "  brightness: 80",  # only args the signature does not already show
    ]
    assert "Agent: hermes" in message_text(_req(agent_name=""))


async def test_send_failure_propagates_to_the_coordinator(channel):
    channel.application.bot.send_message.side_effect = RuntimeError("down")
    with pytest.raises(RuntimeError):
        await channel.send(_req())


# --- finalize: the only place a message is edited ---


def _outcome(reason, approved=False):
    return ApprovalOutcome(APPROVAL_ID, approved, reason, approver_id="42")


def test_resolved_text_variants():
    original = message_text(_req())
    approved = resolved_text(original, _outcome(ApprovalReason.APPROVED, True)).split("\n")
    assert approved[0] == "✅ Approved" and approved[1:] == original.split("\n")[1:]
    assert resolved_text(original, _outcome(ApprovalReason.DENIED)).startswith("❌ Denied\n")
    assert resolved_text(original, _outcome(ApprovalReason.TIMEOUT)) == (
        "⏰ Expired\n\nApproval timed out"
    )
    assert "restarted" in resolved_text(original, _outcome(ApprovalReason.RESTART))
    assert "shutting down" in resolved_text(original, _outcome(ApprovalReason.GATEWAY_SHUTDOWN))


async def test_finalize_edits_the_message_from_the_handle_alone(channel):
    # a handle rebuilt from the database after a restart: no in-memory state needed
    handle = ChannelHandle("telegram", {"message_id": 7, "text": message_text(_req())})
    await channel.finalize(handle, _outcome(ApprovalReason.APPROVED, True))

    kwargs = channel.application.bot.edit_message_text.call_args.kwargs
    assert kwargs["chat_id"] == -100 and kwargs["message_id"] == 7
    assert kwargs["text"].startswith("✅ Approved")
    assert "reply_markup" not in kwargs  # editing without a keyboard removes the buttons


async def test_finalize_never_raises(channel):
    channel.application.bot.edit_message_text.side_effect = RuntimeError("message is gone")
    await channel.finalize(ChannelHandle("telegram", {"message_id": 7}), _outcome("timeout"))


# --- callbacks ---


async def test_tap_is_reported_to_the_sink_and_decides_nothing(channel):
    sink = _Sink()
    await channel.start(sink)
    update, query = _query(f"{APPROVAL_ID}:y")

    await channel._on_callback(update, None)

    [(approval_id, answer)] = sink.answers
    assert approval_id == APPROVAL_ID
    assert (answer.approved, answer.channel, answer.approver_id) == (True, "telegram", "42")
    assert answer.proof["kind"] == "telegram_callback"
    query.answer.assert_awaited_once_with()
    channel.application.bot.edit_message_text.assert_not_called()  # editing is finalize's job


async def test_deny_tap(channel):
    sink = _Sink()
    await channel.start(sink)
    update, _ = _query(f"{APPROVAL_ID}:n")
    await channel._on_callback(update, None)
    assert sink.answers[0][1].approved is False


async def test_tap_from_a_user_who_is_not_allowed_is_ignored(channel):
    sink = _Sink()
    await channel.start(sink)
    update, query = _query(f"{APPROVAL_ID}:y", user_id=666)
    await channel._on_callback(update, None)
    assert sink.answers == []
    query.answer.assert_not_called()


@pytest.mark.parametrize(
    ("status", "toast"),
    [
        (AnswerStatus.ALREADY_RESOLVED, "Already resolved"),
        (AnswerStatus.REJECTED, "This request needs a stronger approval"),
    ],
)
async def test_losing_or_rejected_taps_get_a_toast(channel, status, toast):
    await channel.start(_Sink(status))
    update, query = _query(f"{APPROVAL_ID}:y")
    await channel._on_callback(update, None)
    query.answer.assert_awaited_once_with(toast)


async def test_stale_button_is_acknowledged(channel):
    update, query = _query("some-old-pickled-key")
    await channel._on_stale(update, None)
    query.answer.assert_awaited_once_with("This button has expired")


@pytest.mark.parametrize(
    "data", [f"{APPROVAL_ID}:{c}" for c in ("y", "n", "a", "d", "ae", "at", "de", "dt", "b")]
)
def test_callback_pattern_accepts_ours(data):
    assert re.match(CALLBACK_PATTERN, data)


@pytest.mark.parametrize(
    "data",
    [
        APPROVAL_ID,
        f"{APPROVAL_ID}:x",
        f"{APPROVAL_ID}:y:z",
        ":y",
        f"{APPROVAL_ID}:aa",
        f"{APPROVAL_ID}:ex",
    ],
)
def test_callback_pattern_rejects_anything_else(data):
    assert not re.match(CALLBACK_PATTERN, data)


# --- lifecycle and construction ---


async def test_manual_ptb_lifecycle_never_run_polling(channel):
    app = channel.application
    await channel.start(_Sink())
    app.initialize.assert_awaited_once()
    app.start.assert_awaited_once()
    app.updater.start_polling.assert_awaited_once()
    app.run_polling.assert_not_called()

    await channel.stop()
    app.updater.stop.assert_awaited_once()
    app.stop.assert_awaited_once()
    app.shutdown.assert_awaited_once()


async def test_health_and_notify(channel):
    assert await channel.health_check() is True
    channel.application.running = False
    assert await channel.health_check() is False
    await channel.notify("consent needed")
    channel.application.bot.send_message.assert_awaited_with(chat_id=-100, text="consent needed")


def test_real_application_is_stateless():
    real = TelegramChannel(CONFIG).application
    assert isinstance(real, Application)
    assert real.persistence is None  # no callback_data.pickle
    assert real.bot.callback_data_cache is None  # no arbitrary callback data


def test_class_attributes():
    channel = TelegramChannel(CONFIG, application=_fake_app(), name="tg2", trust="notify")
    assert (channel.name, channel.trust, channel.proof_kinds) == (
        "tg2",
        "notify",
        {"telegram_callback"},
    )


def test_build_channels_from_config():
    cfg = SimpleNamespace(
        channels=[
            ChannelConfig("telegram", "telegram", "trusted", CONFIG),
            ChannelConfig("backup", "telegram", "notify", CONFIG),
        ]
    )
    channels = build_channels(cfg)
    assert [(c.name, c.trust) for c in channels] == [("telegram", "trusted"), ("backup", "notify")]
    with pytest.raises(ValueError, match="Unsupported"):
        build_channels(SimpleNamespace(channels=[ChannelConfig("x", "carrier-pigeon")]))


# --- Allow always / Deny always ---

OFFER = RememberOffer(allow_exact=True, allow_tool=True, args_hash="h", tool_fingerprint="f")


def _always_req(offer=OFFER):
    return _req(
        remember=offer, tool="gmail_list_messages", signature="gmail_list_messages(in:inbox)"
    )


def _rows(channel):
    markup = channel.application.bot.send_message.call_args.kwargs["reply_markup"]
    return [[(b.text, b.callback_data) for b in row] for row in markup.inline_keyboard]


async def test_always_buttons_are_offered_only_when_permitted(channel):
    await channel.send(_always_req())
    assert _rows(channel)[1] == [
        ("Allow always...", f"{APPROVAL_ID}:a"),
        ("Deny always...", f"{APPROVAL_ID}:d"),
    ]
    await channel.send(_always_req(RememberOffer(deny_exact=False, deny_tool=False)))
    assert len(_rows(channel)) == 1  # nothing to remember: just once/once
    await channel.send(_always_req(RememberOffer()))
    assert [t for t, _ in _rows(channel)[1]] == ["Deny always..."]
    await channel.send(_req())
    assert len(_rows(channel)) == 1


async def test_scope_step_shows_the_pattern_and_edits_only_the_message(channel):
    sink = _Sink()
    await channel.start(sink)
    await channel.send(_always_req())
    update, query = _query(f"{APPROVAL_ID}:a")
    query.edit_message_text = AsyncMock()

    await channel._on_callback(update, None)

    text = query.edit_message_text.call_args.args[0]
    assert "Allow always for agent Hermes" in text
    assert "gmail_list_messages(in:inbox)" in text and "gmail_list_messages(*)" in text
    assert "expires" in text and "⚠" in text
    markup = query.edit_message_text.call_args.kwargs["reply_markup"]
    assert [[b.callback_data for b in row] for row in markup.inline_keyboard] == [
        [f"{APPROVAL_ID}:ae", f"{APPROVAL_ID}:at"],  # exact first
        [f"{APPROVAL_ID}:b"],
    ]
    assert sink.answers == []  # opening the step decides nothing


async def test_back_restores_the_first_step(channel):
    await channel.start(_Sink())
    await channel.send(_always_req())
    update, query = _query(f"{APPROVAL_ID}:b")
    query.edit_message_text = AsyncMock()
    await channel._on_callback(update, None)
    assert query.edit_message_text.call_args.args[0] == message_text(_always_req())
    assert len(query.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard) == 2


async def test_deny_scope_step_has_no_expiry_and_no_warning(channel):
    await channel.start(_Sink())
    await channel.send(_always_req())
    update, query = _query(f"{APPROVAL_ID}:d")
    query.edit_message_text = AsyncMock()
    await channel._on_callback(update, None)
    text = query.edit_message_text.call_args.args[0]
    assert "no expiry" in text and "⚠" not in text


async def test_scope_step_for_an_unknown_or_unoffered_request_is_refused(channel):
    await channel.start(_Sink())
    update, query = _query(f"{APPROVAL_ID}:a")
    query.edit_message_text = AsyncMock()
    await channel._on_callback(update, None)  # never sent
    query.answer.assert_awaited_once_with("This button has expired")
    query.edit_message_text.assert_not_called()

    await channel.send(_always_req(RememberOffer()))  # deny only
    update, query = _query(f"{APPROVAL_ID}:a")
    query.edit_message_text = AsyncMock()
    await channel._on_callback(update, None)
    query.answer.assert_awaited_once_with("That choice is not available for this request")


@pytest.mark.parametrize(
    ("code", "approved", "remember"),
    [("ae", True, "exact"), ("at", True, "tool"), ("de", False, "exact"), ("dt", False, "tool")],
)
async def test_scope_tap_reports_the_scope_and_nothing_else(channel, code, approved, remember):
    sink = _Sink()
    await channel.start(sink)
    update, _ = _query(f"{APPROVAL_ID}:{code}")
    await channel._on_callback(update, None)
    [(approval_id, answer)] = sink.answers
    assert (approval_id, answer.approved, answer.remember) == (APPROVAL_ID, approved, remember)
    assert answer.approver_id == "42" and answer.proof["kind"] == "telegram_callback"


async def test_once_taps_carry_no_scope(channel):
    sink = _Sink()
    await channel.start(sink)
    update, _ = _query(f"{APPROVAL_ID}:y")
    await channel._on_callback(update, None)
    assert sink.answers[0][1].remember is None


async def test_refused_scope_gets_its_own_toast(channel):
    await channel.start(_Sink(AnswerStatus.REJECTED))
    update, query = _query(f"{APPROVAL_ID}:at")
    await channel._on_callback(update, None)
    query.answer.assert_awaited_once_with("That choice is not available for this request")


@pytest.mark.parametrize("code", ["y", "ae", "a", "b"])
async def test_taps_from_another_chat_or_user_are_ignored(channel, code):
    sink = _Sink()
    await channel.start(sink)
    await channel.send(_always_req())
    for kw in ({"chat_id": -999}, {"user_id": 666}):
        update, query = _query(f"{APPROVAL_ID}:{code}", **kw)
        query.edit_message_text = AsyncMock()
        await channel._on_callback(update, None)
        query.answer.assert_not_called()
        query.edit_message_text.assert_not_called()
    assert sink.answers == []


def test_resolved_text_names_the_rule():
    out = ApprovalOutcome(
        approval_id=APPROVAL_ID,
        approved=True,
        reason=ApprovalReason.APPROVED,
        rule_id=12,
        remembered="exact",
    )
    assert resolved_text("hdr\nline", out).startswith("✅ Approved (always: exact, rule #12)")


def test_all_callback_data_fits_telegram_limit():
    assert len(f"{APPROVAL_ID}:ae".encode()) <= 64
