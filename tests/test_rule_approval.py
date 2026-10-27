"""Per-rule approval requirements: YAML -> engine -> pipeline -> coordinator."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentpass.agents import AgentIdentity, load_agents
from agentpass.approval import AnswerStatus, ApprovalCoordinator
from agentpass.config import (
    ApprovalSpec,
    ChannelConfig,
    ConfigError,
    PermissionRule,
    Permissions,
    approval_warnings,
    load_permissions,
    validate_rule_channels,
)
from agentpass.engine import Evaluation, PermissionEngine
from agentpass.executor import Executor
from agentpass.models import Decision
from agentpass.pipeline import ApprovalTimeout, Pipeline
from tests.fakes import FakeChannel, started_coordinator, stateful_mock_db


def _rule(approval=None, pattern="t*", action="ask"):
    return PermissionRule(pattern=pattern, action=action, approval=approval)


async def _make(rules, *channels, identity=None, **kw):
    channels = channels or (FakeChannel(),)
    executor = AsyncMock(spec=Executor)
    executor.execute.return_value = {"ok": True}
    db = stateful_mock_db()
    coordinator = await started_coordinator(db, *channels)
    engine = PermissionEngine(Permissions(defaults=[], rules=rules))
    p = Pipeline(engine=engine, executor=executor, coordinator=coordinator, db=db, **kw)
    return p, executor, channels, db


def _webauthn_channel():
    return FakeChannel("passkey", proof_kinds={"webauthn"})


async def _first_sent(*channels):
    for _ in range(200):
        for ch in channels:
            if ch.sent:
                return ch.sent[-1].approval_id
        await asyncio.sleep(0.01)
    raise AssertionError("approval never sent")


# --- end to end ---


async def test_passkey_rule_refuses_telegram_and_accepts_webauthn():
    tg, pk = FakeChannel(), _webauthn_channel()
    p, executor, _, _ = await _make([_rule(ApprovalSpec(require="passkey"))], tg, pk)
    task = asyncio.create_task(p.process("a", "tool", {}))
    approval_id = await _first_sent(tg, pk)

    assert await tg.approve(approval_id) is AnswerStatus.REJECTED
    assert not task.done()
    executor.execute.assert_not_awaited()

    assert await pk.answer(approval_id, True, proof={"assertion": "ok"}) is AnswerStatus.ACCEPTED
    out = await task
    assert out.data == {"ok": True}
    executor.execute.assert_awaited_once()


async def test_rule_require_reaches_channels_on_the_request():
    tg, pk = FakeChannel(), _webauthn_channel()
    p, _, _, _ = await _make([_rule(ApprovalSpec(require="passkey"))], tg, pk)
    task = asyncio.create_task(p.process("a", "tool", {}))
    await _first_sent(tg, pk)
    assert tg.last_request.require == pk.last_request.require == "passkey"
    task.cancel()


# --- timeout precedence ---


async def test_rule_timeout_wins_over_global():
    p, _, [ch], _ = await _make([_rule(ApprovalSpec(timeout=1))], approval_timeout=900)
    task = asyncio.create_task(p.process("a", "tool", {}))
    await _first_sent(ch)
    assert ch.last_request.expires_at - time.time() == pytest.approx(1, abs=0.5)
    task.cancel()


async def test_rule_timeout_expires_the_request():
    p, _, _, _ = await _make([_rule(ApprovalSpec(timeout=1))], approval_timeout=900)
    started = time.monotonic()
    with pytest.raises(ApprovalTimeout):
        await p.process("a", "tool", {})
    assert time.monotonic() - started < 5


async def test_rule_without_timeout_uses_agent_then_global():
    p, _, [ch], _ = await _make([_rule(ApprovalSpec(require="telegram"))], approval_timeout=900)
    task = asyncio.create_task(p.process("a", "tool", {}))
    await _first_sent(ch)
    assert ch.last_request.expires_at - time.time() == pytest.approx(900, abs=5)
    task.cancel()

    p, _, [ch], _ = await _make([_rule()], approval_timeout=900)
    agent = AgentIdentity(id="a", approval_timeout=120)
    task = asyncio.create_task(p.process(agent, "tool", {}))
    await _first_sent(ch)
    assert ch.last_request.expires_at - time.time() == pytest.approx(120, abs=5)
    task.cancel()


async def test_rule_timeout_beats_agent_timeout():
    p, _, [ch], _ = await _make([_rule(ApprovalSpec(timeout=30))], approval_timeout=900)
    task = asyncio.create_task(p.process(AgentIdentity(id="a", approval_timeout=120), "tool", {}))
    await _first_sent(ch)
    assert ch.last_request.expires_at - time.time() == pytest.approx(30, abs=5)
    task.cancel()


# --- channel subset ---


async def test_channel_subset_limits_fan_out():
    a, b, c = FakeChannel("a"), FakeChannel("b"), FakeChannel("c")
    p, _, _, _ = await _make([_rule(ApprovalSpec(channels=("a", "c")))], a, b, c)
    task = asyncio.create_task(p.process("x", "tool", {}))
    await _first_sent(a, c)
    assert len(a.sent) == 1 and len(c.sent) == 1 and b.sent == []
    task.cancel()


async def test_no_approval_block_is_a_plain_coordinator_call():
    coordinator = AsyncMock(spec=ApprovalCoordinator)
    engine = MagicMock(spec=PermissionEngine)
    engine.evaluate.return_value = Evaluation(Decision.ASK)
    p = Pipeline(
        engine=engine,
        executor=AsyncMock(spec=Executor),
        coordinator=coordinator,
        db=stateful_mock_db(),
        approval_timeout=77,
    )
    coordinator.request.side_effect = RuntimeError("stop")
    with pytest.raises(RuntimeError):
        await p.process("a", "tool", {})
    [call] = coordinator.request.call_args_list
    assert set(call.kwargs) == {"on_pending"}
    assert call.args[0].require == "any_trusted"
    assert call.args[0].expires_at - time.time() == pytest.approx(77, abs=2)


async def test_engine_returns_matched_rules_approval():
    spec = ApprovalSpec(require="passkey", timeout=5)
    engine = PermissionEngine(
        Permissions(
            defaults=[_rule(ApprovalSpec(require="telegram"), "*", "ask")],
            rules=[_rule(spec, "gmail_send*", "ask"), _rule(None, "x*", "allow")],
        )
    )
    assert engine.evaluate("gmail_send", {}) == Evaluation(Decision.ASK, spec)
    assert engine.evaluate("x", {}).approval is None
    assert engine.evaluate("other", {}).approval.require == "telegram"
    assert engine.evaluate("zzz", {}).decision is Decision.ASK


# --- config validation ---


def _perm_file(tmp_path, approval):
    p = tmp_path / "permissions.yaml"
    p.write_text(
        f"rules:\n  - pattern: 'gmail_send(*)'\n    action: ask\n    approval: {approval}\n"
    )
    return str(p)


def test_valid_approval_block_is_parsed(tmp_path):
    perms = load_permissions(
        _perm_file(tmp_path, "{require: passkey, timeout: 900, channels: [pk], risk: high}")
    )
    assert perms.rules[0].approval == ApprovalSpec("passkey", 900, ("pk",), "high")


@pytest.mark.parametrize(
    ("approval", "message"),
    [
        ("{require: sms}", "require must be one of"),
        ("{timeout: 0}", "timeout must be a positive integer"),
        ("{timeout: 1.5}", "timeout must be a positive integer"),
        ("{timeout: true}", "timeout must be a positive integer"),
        ("{bogus: 1}", "unknown key bogus"),
        ("{channels: pk}", "channels must be a list"),
        ("{risk: huge}", "risk must be one of"),
        ("passkey", "must be a mapping"),
    ],
)
def test_bad_approval_block_names_file_and_key(tmp_path, approval, message):
    path = _perm_file(tmp_path, approval)
    with pytest.raises(ConfigError, match=message) as exc:
        load_permissions(path)
    assert path in str(exc.value)


def test_agent_file_approval_block_is_validated(tmp_path):
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "a.yaml").write_text(
        "id: a\n" + f"token_hash: 'sha256:{'0' * 64}'\n"
        "rules:\n  - {pattern: 'x*', action: ask, approval: {require: nope}}\n"
    )
    with pytest.raises(ConfigError, match=r"a\.yaml.*require must be one of"):
        load_agents(tmp_path / "agents")


def test_unknown_channel_name_is_a_config_error(tmp_path):
    perms = load_permissions(_perm_file(tmp_path, "{channels: [nope]}"))
    configured = [ChannelConfig(name="telegram", type="telegram")]
    with pytest.raises(ConfigError, match="unknown channel 'nope'"):
        validate_rule_channels(perms.rules, configured)
    ok = load_permissions(_perm_file(tmp_path, "{channels: [telegram]}"))
    validate_rule_channels(ok.rules, configured)


# --- check-config warnings ---


def test_require_of_unconfigured_channel_type_warns(tmp_path):
    perms = load_permissions(_perm_file(tmp_path, "{require: passkey}"))
    [warning] = approval_warnings(perms.rules, [ChannelConfig(name="tg", type="telegram")])
    assert "passkey" in warning and "gmail_send" in warning
    pk = ChannelConfig(name="pk", type="passkey")
    assert approval_warnings(perms.rules, [pk]) == []


def test_empty_channels_with_require_warns(tmp_path):
    perms = load_permissions(_perm_file(tmp_path, "{require: telegram, channels: []}"))
    [warning] = approval_warnings(perms.rules, [ChannelConfig(name="tg", type="telegram")])
    assert "channels is empty" in warning
