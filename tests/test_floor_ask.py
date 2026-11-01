"""Policy floor ask rules: they beat every allow, are never remembered, and stay listed."""

from __future__ import annotations

import asyncio

import pytest

from agentpass.agents import generate_token, load_agents
from agentpass.check import check
from agentpass.config import (
    ApprovalSpec,
    ArgDefinition,
    ConfigError,
    PermissionRule,
    Permissions,
    ToolDefinition,
)
from agentpass.db import Database
from agentpass.engine import PermissionEngine
from agentpass.models import Decision
from agentpass.registry import ToolRegistry
from agentpass.remembered import RememberedService, allow_blocker, build_offer, rule_state
from tests.test_check import LISTEN, TOOLS

FLOOR = (
    "rules:\n"
    '  - { pattern: "send_mail*", action: ask, approval: { require: passkey } }\n'
    '  - { pattern: "send_*", action: ask, approval: { require: telegram } }\n'
    '  - { pattern: "wipe*", action: deny }\n'
)


def _engine(tmp_path, agent_body="", sets=None, floor=FLOOR):
    policy = tmp_path / "policy"
    policy.mkdir(exist_ok=True)
    (policy / "_floor.yaml").write_text(floor)
    for name, text in (sets or {}).items():
        (policy / f"{name}.yaml").write_text(text)
    agents = tmp_path / "agents"
    agents.mkdir(exist_ok=True)
    _, digest = generate_token("bot")
    (agents / "bot.yaml").write_text(f"id: bot\ntoken_hash: '{digest}'\n{agent_body}")
    return PermissionEngine(load_agents(agents).get("bot").permissions)


def _eval(engine, signature):
    return engine.evaluate("x", {}, signature=signature)


def test_floor_ask_beats_agent_allow_and_set_allow(tmp_path):
    engine = _engine(
        tmp_path,
        'extends: [mail]\ndefaults:\n  - { pattern: "*", action: allow }\n'
        'rules:\n  - { pattern: "send_mail(a)", action: allow }\n',
        sets={"mail": 'rules:\n  - { pattern: "send_mail(*)", action: allow }\n'},
    )
    result = _eval(engine, "send_mail(a)")
    assert result.decision is Decision.ASK and result.floor
    assert result.approval == ApprovalSpec(require="passkey", source=result.approval.source)
    assert _eval(engine, "read_mail(a)").decision is Decision.ALLOW
    assert not _eval(engine, "read_mail(a)").floor


def test_first_floor_ask_wins_over_agent_ask_approval(tmp_path):
    engine = _engine(
        tmp_path,
        'rules:\n  - { pattern: "send_mail*", action: ask, approval: { require: telegram } }\n',
    )
    assert _eval(engine, "send_mail(a)").approval.require == "passkey"  # first floor rule
    assert _eval(engine, "send_other(a)").approval.require == "telegram"  # second floor rule


def test_deny_beats_floor_ask(tmp_path):
    floor = FLOOR + '  - { pattern: "send_secret*", action: ask }\n'
    engine = _engine(
        tmp_path, 'rules:\n  - { pattern: "send_mail(x)", action: deny }\n', floor=floor
    )
    assert _eval(engine, "send_mail(x)").decision is Decision.DENY  # agent deny
    floor_deny = (
        'rules:\n  - { pattern: "send*", action: ask }\n  - { pattern: "send*", action: deny }\n'
    )
    engine = _engine(tmp_path, floor=floor_deny)
    assert _eval(engine, "send_a").decision is Decision.DENY  # floor deny


def test_floor_allow_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="allow"):
        _engine(tmp_path, floor='rules:\n  - { pattern: "*", action: allow }\n')


def test_may_permit_keeps_tool_with_floor_ask(tmp_path):
    engine = _engine(tmp_path, 'defaults:\n  - { pattern: "*", action: deny }\n')
    assert engine.may_permit("send_mail")
    assert not engine.may_permit("read_mail")
    assert not engine.may_permit("wipe_all")


# --- remembered decisions ---


def _tool():
    return ToolDefinition(
        name="send_mail",
        service_name="svc",
        signature="{q}",
        args={"q": ArgDefinition(required=True)},
        risk="low",
    )


def test_allow_blocker_and_offer_for_floor():
    tool = _tool()
    assert allow_blocker(tool, None, "exact") is None
    assert allow_blocker(tool, None, "exact", floor=True)
    offer = build_offer(tool, None, "send_mail(a)", {"q": "a"}, floor=True)
    assert not offer.any_allow and offer.deny_exact and offer.deny_tool


@pytest.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "t.db"))
    await database.initialize()
    yield database
    await database.close()


async def _remember(db, action, scope="exact"):
    tool = _tool()
    from agentpass.remembered import iso, tool_fingerprint

    await db.upsert_remembered_rule(
        {
            "agent_id": "bot",
            "tool_name": "send_mail",
            "scope": scope,
            "signature": "send_mail(a)" if scope == "exact" else None,
            "args_hash": None,
            "action": action,
            "pattern": "send_mail(a)",
            "tool_fingerprint": tool_fingerprint(tool),
            "created_at": iso(),
            "expires_at": None,
            "created_by": "test",
            "source_request_id": "req-1",
        }
    )


async def test_remembered_allow_ignored_and_deny_applies_for_floor_ask(db):
    registry = ToolRegistry({"send_mail": _tool()})
    service = RememberedService(db, registry)
    await _remember(db, "allow")
    verdict = await service.resolve(
        "bot", "send_mail", "send_mail(a)", {"q": "a"}, Decision.ASK, None
    )
    assert verdict is not None and verdict.decision is Decision.ALLOW  # no floor: still works
    assert (
        await service.resolve(
            "bot", "send_mail", "send_mail(a)", {"q": "a"}, Decision.ASK, None, True
        )
        is None
    )
    await _remember(db, "deny")
    verdict = await service.resolve(
        "bot", "send_mail", "send_mail(a)", {"q": "a"}, Decision.ASK, None, True
    )
    assert verdict.decision is Decision.DENY


def test_rule_state_marks_allow_inactive_under_floor():
    from agentpass.remembered import tool_fingerprint

    tool = _tool()
    registry = ToolRegistry({"send_mail": tool})
    rule = {
        "agent_id": "bot",
        "tool_name": "send_mail",
        "scope": "exact",
        "signature": "send_mail(a)",
        "action": "allow",
        "revoked_at": None,
        "expires_at": None,
        "tool_fingerprint": tool_fingerprint(tool),
    }
    now = "2026-01-01T00:00:00Z"
    assert rule_state(rule, registry, now_iso=now)[0] == "active"
    state = rule_state(rule, registry, now_iso=now, floor_for=lambda *_: True)
    assert state[0] == "inactive" and "floor" in state[1]
    assert (
        rule_state(rule | {"action": "deny"}, registry, now_iso=now, floor_for=lambda *_: True)[0]
        == "active"
    )


# --- check-config ---


def _floor_setup(tmp_path, floor, channel=""):
    (tmp_path / "tools.yaml").write_text(TOOLS)
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy" / "_floor.yaml").write_text(floor)
    (tmp_path / "agents").mkdir()
    _, digest = generate_token("bot")
    (tmp_path / "agents" / "bot.yaml").write_text(
        f"id: bot\ntoken_hash: '{digest}'\ndefaults:\n  - {{ pattern: '*', action: ask }}\n"
    )
    messenger = "messenger: {type: telegram, telegram: {token: t, chat_id: 1, allowed_users: [1]}}"
    (tmp_path / "gateway.yaml").write_text(
        f"""\
gateway: {{health_port: 8210}}
{LISTEN}
agent: {{agents_dir: agents, policy_dir: policy}}
{channel or messenger}
services:
  svc: {{url: "http://localhost", auth: {{type: bearer, token: "t"}}, tools: tools.yaml}}
storage: {{type: sqlite, path: ./d.db}}
"""
    )
    (tmp_path / "permissions.yaml").write_text("defaults:\n  - {pattern: '*', action: ask}\n")
    return str(tmp_path / "gateway.yaml"), str(tmp_path / "permissions.yaml")


FLOOR_CHECK = 'rules:\n  - { pattern: "t_get*", action: ask, approval: { require: passkey } }\n'


def test_check_floor_ask_without_passkey_channel_is_an_error(tmp_path):
    report = check(*_floor_setup(tmp_path, FLOOR_CHECK), env={})
    assert [f.code for f in report.errors] == ["approval-passkey"]


def test_check_floor_ask_with_passkey_channel_is_clean_in_strict_mode(tmp_path):
    channel = (
        "passkey: {enabled: true, host: 127.0.0.1, port: 8206, rp_id: localhost, "
        "origin: 'https://localhost'}\n"
        "channels:\n"
        "  - {name: chat, type: telegram, token: t, chat_id: 1, allowed_users: [1]}\n"
        "  - {name: page, type: passkey, trust: trusted}"
    )
    report = check(*_floor_setup(tmp_path, FLOOR_CHECK, channel), env={})
    assert report.errors == [] and report.warnings == []
    assert report.exit_code(strict=True) == 0


def test_shipped_floor_example_loads(tmp_path):
    from pathlib import Path

    import agentpass

    example = Path(agentpass.__file__).resolve().parents[2] / "policy" / "_floor.example.yaml"
    engine = _engine(tmp_path, floor=example.read_text())
    assert _eval(engine, "gmail_delete_message(a)").decision is Decision.DENY
    sent = _eval(engine, "gmail_send_message(a)")
    assert sent.floor and sent.approval.require == "passkey"


async def test_pipeline_ignores_remembered_allow_and_offers_nothing(db, tmp_path):
    from tests.test_remembered import _stack

    registry_tools = {"send_mail": _tool()}
    pipeline, _remembered, channel, executor = await _stack(db, registry_tools, [])
    pipeline._engine = PermissionEngine(
        Permissions(defaults=[], rules=[], floor_ask=[_floor_rule()]), pipeline._registry
    )
    await _remember(db, "allow")
    task = asyncio.create_task(pipeline.process("bot", "send_mail", {"q": "a"}))
    for _ in range(300):
        if channel.sent:
            break
        await asyncio.sleep(0.01)
    assert channel.sent, "a floor ask must reach a human despite the remembered allow"
    offer = channel.sent[-1].remember
    assert not offer.any_allow and offer.any_deny
    executor.execute.assert_not_called()
    task.cancel()


def _floor_rule():
    return PermissionRule("send_mail*", "ask")
