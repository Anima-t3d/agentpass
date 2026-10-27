"""Remembered decisions: Allow always / Deny always."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from agentpass.approval import AnswerStatus, RememberOffer
from agentpass.config import (
    ApprovalSpec,
    ArgDefinition,
    PermissionRule,
    Permissions,
    ToolDefinition,
)
from agentpass.db import Database
from agentpass.engine import PermissionEngine
from agentpass.executor import Executor
from agentpass.models import Decision
from agentpass.pipeline import ApprovalDenied, Pipeline, PolicyDenied
from agentpass.registry import ToolRegistry
from agentpass.remembered import (
    RememberedService,
    allow_blocker,
    args_hash,
    build_offer,
    rule_state,
    tool_fingerprint,
)
from tests.fakes import FakeChannel, started_coordinator

NOW = "2026-10-27T00:00:00Z"


def _tool(name, risk, *, remember="args", signature="{q}", extra_arg=True):
    args = {"q": ArgDefinition(required=True)}
    if extra_arg:
        args["body"] = ArgDefinition(signature=False)
    return ToolDefinition(
        name=name,
        service_name="svc",
        signature=signature,
        args=args,
        risk=risk,
        remember=remember,
    )


def _registry(**tools):
    return ToolRegistry(tools)


@pytest.fixture
def tools():
    return {
        "lowt": _tool("lowt", "low"),
        "medt": _tool("medt", "medium"),
        "hight": _tool("hight", "high"),
        "unsett": _tool("unsett", None),
        "sigt": _tool("sigt", "low", remember="signature"),
    }


@pytest.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "t.db"))
    await database.initialize()
    yield database
    await database.close()


def _rules(*rules):
    return Permissions(defaults=[PermissionRule("*", "ask")], rules=list(rules))


async def _stack(db, tools, rules, channel=None):
    registry = _registry(**tools)
    engine = PermissionEngine(_rules(*rules), registry)
    remembered = RememberedService(db, registry)
    channel = channel or FakeChannel()
    executor = AsyncMock(spec=Executor)
    executor.execute.return_value = {"ok": True}
    coordinator = await started_coordinator(db, channel, remembered=remembered)
    pipeline = Pipeline(
        engine=engine,
        executor=executor,
        coordinator=coordinator,
        db=db,
        registry=registry,
        remembered=remembered,
    )
    return pipeline, remembered, channel, executor


async def _cancel(task):
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def _ask_and_answer(pipeline, channel, tool, args, **answer):
    task = asyncio.create_task(pipeline.process("bot", tool, args))
    for _ in range(300):
        if channel.sent and channel.sent[-1].approval_id != getattr(channel, "_seen", None):
            break
        await asyncio.sleep(0.01)
    req = channel.sent[-1]
    channel._seen = req.approval_id
    status = await channel.answer(req.approval_id, **answer)
    return req, status, task


# --- pure helpers ---


def test_args_hash_is_canonical():
    assert args_hash({"a": 1, "b": 2}) == args_hash({"b": 2, "a": 1})
    assert args_hash({"a": 1}) != args_hash({"a": 2})


def test_fingerprint_ignores_description_but_not_behaviour(tools):
    base = tools["lowt"]
    reworded = _tool("lowt", "low")
    reworded.description = "changed words"
    assert tool_fingerprint(base) == tool_fingerprint(reworded)
    assert tool_fingerprint(base) != tool_fingerprint(_tool("lowt", "medium"))
    assert tool_fingerprint(base) != tool_fingerprint(_tool("lowt", "low", remember="signature"))


@pytest.mark.parametrize(
    ("risk", "approval", "scope", "blocked"),
    [
        ("low", None, "exact", False),
        ("low", None, "tool", False),
        ("medium", None, "tool", False),
        ("high", None, "exact", True),
        ("high", None, "tool", True),
        (None, None, "exact", False),
        (None, None, "tool", True),  # unset risk never gets tool scope
        ("low", ApprovalSpec(require="passkey"), "exact", True),
        ("low", ApprovalSpec(require="telegram"), "exact", False),
        ("low", ApprovalSpec(risk="high"), "exact", True),  # the rule can raise the risk
        ("medium", ApprovalSpec(risk="low"), "exact", False),
    ],
)
def test_allow_blocker(risk, approval, scope, blocked):
    assert bool(allow_blocker(_tool("t", risk), approval, scope)) is blocked


def test_unknown_risk_counts_as_high():
    assert allow_blocker(_tool("t", "critical"), None, "exact")


def test_allow_blocker_without_tool():
    assert allow_blocker(None, None, "exact")


def test_offer_matches_policy(tools):
    offer = build_offer(tools["medt"], None, "medt(x)", {"q": "x"})
    assert (offer.allow_exact, offer.allow_tool, offer.deny_exact, offer.deny_tool) == (
        True,
        True,
        True,
        True,
    )
    assert offer.args_hash == args_hash({"q": "x"})

    high = build_offer(tools["hight"], None, "hight(x)", {"q": "x"})
    assert not high.any_allow and high.any_deny  # deny is always safe

    passkey = build_offer(tools["lowt"], ApprovalSpec(require="passkey"), "lowt(x)", {})
    assert not passkey.any_allow and passkey.any_deny

    unset = build_offer(tools["unsett"], None, "unsett(x)", {})
    assert unset.allow_exact and not unset.allow_tool


def test_offer_for_signature_mode_has_no_args_hash(tools):
    assert build_offer(tools["sigt"], None, "sigt(x)", {"q": "x"}).args_hash is None


def test_offer_hidden_for_a_signature_that_cannot_be_shown(tools):
    offer = build_offer(tools["lowt"], None, "lowt(" + "x" * 2000 + ")", {})
    assert not offer.any_allow and not offer.any_deny


def test_offer_permits():
    offer = RememberOffer(allow_exact=True, deny_exact=True, deny_tool=False)
    assert offer.permits(True, "exact")
    assert not offer.permits(True, "tool")
    assert not offer.permits(False, "tool")
    assert not offer.permits(True, "bogus")


# --- end to end: creating rules ---


async def test_allow_always_exact_then_identical_call_skips_the_prompt(db, tools):
    pipeline, _remembered, channel, _executor = await _stack(db, tools, [])
    args = {"q": "in:inbox", "body": "b"}
    req, status, task = await _ask_and_answer(
        pipeline, channel, "lowt", args, approved=True, remember="exact", approver="42"
    )
    assert status is AnswerStatus.ACCEPTED
    assert (await task).data == {"ok": True}

    [rule] = await db.list_remembered_rules()
    assert (rule["agent_id"], rule["scope"], rule["action"], rule["created_by"]) == (
        "bot",
        "exact",
        "allow",
        "42",
    )
    assert rule["pattern"] == "lowt(in:inbox)" == rule["signature"]
    assert rule["source_request_id"] == req.approval_id
    expires = datetime.strptime(rule["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert timedelta(days=89) < expires - datetime.now(UTC) <= timedelta(days=90)

    sent_before = len(channel.sent)
    out = await pipeline.process("bot", "lowt", args)  # no prompt
    assert out.data == {"ok": True} and len(channel.sent) == sent_before
    entries = await db.get_audit_log(limit=10)
    auto = next(e for e in entries if e.resolution == "remembered_allow")
    assert auto.remembered_rule_id == rule["id"]
    assert auto.resolved_by == f"rule:#{rule['id']}"
    assert (await db.get_remembered_rule(rule["id"]))["use_count"] == 1


async def test_creation_is_audited(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "lowt", {"q": "x"}, approved=True, remember="exact"
    )
    await task
    entries = await db.get_audit_log(limit=10)
    created = [e for e in entries if e.tool_name == "_remembered.create"]
    assert len(created) == 1 and created[0].resolution == "rule_created"
    approval = next(e for e in entries if e.tool_name == "lowt")
    assert approval.remembered_rule_id == created[0].remembered_rule_id


async def test_exact_scope_does_not_cover_other_signatures_or_agents(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "lowt", {"q": "a"}, approved=True, remember="exact"
    )
    await task
    for agent, args in (("bot", {"q": "b"}), ("other", {"q": "a"})):
        t = asyncio.create_task(pipeline.process(agent, "lowt", args))
        await asyncio.sleep(0.1)
        assert not t.done()  # still waiting for a human
        await _cancel(t)


async def test_exact_scope_covers_all_args_by_hash(db, tools):
    """A free-text arg outside the signature changes the hash, so it re-prompts."""
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "lowt", {"q": "a", "body": "one"}, approved=True, remember="exact"
    )
    await task
    t = asyncio.create_task(pipeline.process("bot", "lowt", {"q": "a", "body": "two"}))
    await asyncio.sleep(0.1)
    assert not t.done()
    await _cancel(t)


async def test_signature_mode_tool_ignores_non_signature_args(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "sigt", {"q": "a", "body": "one"}, approved=True, remember="exact"
    )
    await task
    out = await pipeline.process("bot", "sigt", {"q": "a", "body": "two"})
    assert out.data == {"ok": True}


async def test_tool_scope_covers_any_args_of_that_agent_only(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "medt", {"q": "a"}, approved=True, remember="tool"
    )
    await task
    [rule] = await db.list_remembered_rules()
    assert rule["pattern"] == "medt(*)" and rule["signature"] is None
    expires = datetime.strptime(rule["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert timedelta(days=29) < expires - datetime.now(UTC) <= timedelta(days=30)

    assert (await pipeline.process("bot", "medt", {"q": "anything"})).data == {"ok": True}
    t = asyncio.create_task(pipeline.process("other", "medt", {"q": "a"}))
    await asyncio.sleep(0.1)
    assert not t.done()
    await _cancel(t)


async def test_deny_always_blocks_without_prompt_and_never_expires(db, tools):
    pipeline, _, channel, executor = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "lowt", {"q": "a"}, approved=False, remember="exact"
    )
    with pytest.raises(ApprovalDenied):
        await task
    [rule] = await db.list_remembered_rules()
    assert rule["action"] == "deny" and rule["expires_at"] is None

    sent = len(channel.sent)
    with pytest.raises(PolicyDenied):
        await pipeline.process("bot", "lowt", {"q": "a"})
    assert len(channel.sent) == sent
    executor.execute.assert_not_awaited()
    entries = await db.get_audit_log(limit=10)
    assert any(e.resolution == "remembered_deny" and e.remembered_rule_id for e in entries)


async def test_duplicate_answer_renews_instead_of_duplicating(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "lowt", {"q": "a"}, approved=True, remember="exact"
    )
    await task
    [first] = await db.list_remembered_rules()
    rule_id, created = await db.upsert_remembered_rule({**first, "created_by": "43"})
    assert (rule_id, created) == (first["id"], False)
    assert len(await db.list_remembered_rules()) == 1


# --- precedence ---


async def test_static_deny_beats_remembered_allow(db, tools):
    """Floor / agent deny is step 1: even a stored allow never reaches it."""
    pipeline, _remembered, channel, executor = await _stack(
        db, tools, [PermissionRule("lowt(blocked)", "deny")]
    )
    await db.upsert_remembered_rule(_row("bot", "lowt", "exact", "lowt(blocked)", {"q": "blocked"}))
    await db.upsert_remembered_rule(_row("bot", "lowt", "tool", None, None))
    with pytest.raises(PolicyDenied):
        await pipeline.process("bot", "lowt", {"q": "blocked"})
    executor.execute.assert_not_awaited()
    assert channel.sent == []


async def test_remembered_deny_beats_static_allow(db, tools):
    pipeline, _, _channel, executor = await _stack(db, tools, [PermissionRule("lowt*", "allow")])
    await db.upsert_remembered_rule(
        _row("bot", "lowt", "exact", "lowt(x)", {"q": "x"}, action="deny", expires=None)
    )
    with pytest.raises(PolicyDenied):
        await pipeline.process("bot", "lowt", {"q": "x"})
    assert (await pipeline.process("bot", "lowt", {"q": "y"})).data == {"ok": True}
    executor.execute.assert_awaited_once()


async def test_remembered_deny_beats_remembered_allow(db, tools):
    pipeline, _, _, _ = await _stack(db, tools, [])
    await db.upsert_remembered_rule(_row("bot", "lowt", "tool", None, None))
    await db.upsert_remembered_rule(
        _row("bot", "lowt", "exact", "lowt(x)", {"q": "x"}, action="deny", expires=None)
    )
    with pytest.raises(PolicyDenied):
        await pipeline.process("bot", "lowt", {"q": "x"})
    assert (await pipeline.process("bot", "lowt", {"q": "z"})).data == {"ok": True}


async def test_remembered_allow_only_turns_ask_into_allow(db, tools):
    """The static verdict ALLOW stays ALLOW, ASK stays ASK without a rule."""
    _pipeline, remembered, _, _ = await _stack(db, tools, [])
    verdict = await remembered.resolve("bot", "lowt", "lowt(x)", {"q": "x"}, Decision.ALLOW, None)
    assert verdict is None
    await db.upsert_remembered_rule(_row("bot", "lowt", "tool", None, None))
    assert (
        await remembered.resolve("bot", "lowt", "lowt(x)", {"q": "x"}, Decision.ALLOW, None) is None
    )
    got = await remembered.resolve("bot", "lowt", "lowt(x)", {"q": "x"}, Decision.ASK, None)
    assert got.decision is Decision.ALLOW


# --- exclusions ---


async def test_passkey_rule_never_gets_allow_always(db, tools):
    approval = ApprovalSpec(require="passkey")
    rules = [PermissionRule("lowt*", "ask", approval=approval)]
    channel = FakeChannel("passkey", proof_kinds={"webauthn", "telegram_callback"})
    pipeline, _, channel, _ = await _stack(db, tools, rules, channel)
    task = asyncio.create_task(pipeline.process("bot", "lowt", {"q": "x"}))
    for _ in range(100):
        if channel.sent:
            break
        await asyncio.sleep(0.01)
    req = channel.sent[0]
    assert not req.remember.any_allow and req.remember.any_deny
    status = await channel.answer(req.approval_id, True, proof=1, remember="exact")
    assert status is AnswerStatus.REJECTED  # forged button: refused server-side
    assert await db.list_remembered_rules() == []
    await _cancel(task)


@pytest.mark.parametrize("name", ["hight", "unsett"])
async def test_high_or_unset_risk_never_gets_tool_scope(db, tools, name):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    task = asyncio.create_task(pipeline.process("bot", name, {"q": "x"}))
    for _ in range(100):
        if channel.sent:
            break
        await asyncio.sleep(0.01)
    req = channel.sent[0]
    assert not req.remember.allow_tool
    status = await channel.answer(req.approval_id, True, remember="tool")
    assert status is AnswerStatus.REJECTED
    assert await db.list_remembered_rules() == []
    assert not task.done()  # the forged answer did not resolve the request either
    await _cancel(task)


async def test_high_risk_not_even_exact(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    task = asyncio.create_task(pipeline.process("bot", "hight", {"q": "x"}))
    for _ in range(100):
        if channel.sent:
            break
        await asyncio.sleep(0.01)
    status = await channel.answer(channel.sent[0].approval_id, True, remember="exact")
    assert status is AnswerStatus.REJECTED
    await _cancel(task)


async def test_policy_change_after_creation_disables_the_allow(db, tools):
    """Eligibility is re-checked on every call, not frozen at creation."""
    _pipeline, remembered, _, _ = await _stack(db, tools, [])
    await db.upsert_remembered_rule(_row("bot", "lowt", "tool", None, None))
    ask = PermissionRule("lowt*", "ask", approval=ApprovalSpec(require="passkey"))
    assert (
        await remembered.resolve("bot", "lowt", "lowt(x)", {}, Decision.ASK, ask.approval) is None
    )
    ask = PermissionRule("lowt*", "ask", approval=ApprovalSpec(risk="high"))
    assert (
        await remembered.resolve("bot", "lowt", "lowt(x)", {}, Decision.ASK, ask.approval) is None
    )
    assert await remembered.resolve("bot", "lowt", "lowt(x)", {}, Decision.ASK, None) is not None


async def test_changed_tool_definition_ignores_allow_but_not_deny(db, tools):
    pipeline, _, _, _ = await _stack(db, tools, [])
    stale = tool_fingerprint(_tool("lowt", "medium"))
    await db.upsert_remembered_rule(_row("bot", "lowt", "tool", None, None, fingerprint=stale))
    deny = _row("bot", "medt", "tool", None, None, action="deny", expires=None, fingerprint=stale)
    await db.upsert_remembered_rule(deny)
    t = asyncio.create_task(pipeline.process("bot", "lowt", {"q": "x"}))
    await asyncio.sleep(0.1)
    assert not t.done()  # allow ignored, asks again
    await _cancel(t)
    with pytest.raises(PolicyDenied):  # deny stays in force
        await pipeline.process("bot", "medt", {"q": "x"})


# --- glob injection ---


async def test_stored_signature_is_compared_literally_never_as_a_glob(db, tools):
    _pipeline, remembered, _, _ = await _stack(db, tools, [])
    # a signature containing glob characters can never be created through the pipeline
    # (the engine rejects them), but even a hand-written row must not widen the match
    await db.upsert_remembered_rule(
        _row(
            "bot",
            "lowt",
            "exact",
            "lowt(*)",
            {"q": "*"},
            fingerprint=tool_fingerprint(tools["lowt"]),
        )
    )
    for sig in ("lowt(anything)", "lowt(a)", "lowt()"):
        assert await remembered.resolve("bot", "lowt", sig, {"q": "*"}, Decision.ASK, None) is None


async def test_glob_characters_in_signature_args_are_rejected_before_any_rule(db, tools):
    from agentpass.pipeline import InvalidParams

    pipeline, _, _, _ = await _stack(db, tools, [])
    for value in ("*", "a?b", "[x]", "a,b", "(x)"):
        with pytest.raises(InvalidParams):
            await pipeline.process("bot", "lowt", {"q": value})


# --- expiry and revoke ---


async def test_expired_rule_no_longer_applies(db, tools):
    _pipeline, remembered, _, _ = await _stack(db, tools, [])
    row = _row("bot", "lowt", "tool", None, None, expires="2020-01-01T00:00:00Z")
    rule_id, _ = await db.upsert_remembered_rule(row)
    assert await remembered.resolve("bot", "lowt", "lowt(x)", {}, Decision.ASK, None) is None
    assert remembered.state(await db.get_remembered_rule(rule_id)) == ("expired", "")


async def test_revoke_takes_effect_on_the_next_call_and_is_audited(db, tools):
    pipeline, remembered, _, _ = await _stack(db, tools, [])
    rule_id, _ = await db.upsert_remembered_rule(_row("bot", "lowt", "tool", None, None))
    assert (await pipeline.process("bot", "lowt", {"q": "x"})).data == {"ok": True}

    assert await remembered.revoke(rule_id, "cli") is True
    assert await remembered.revoke(rule_id, "cli") is False  # already revoked
    assert await remembered.revoke(9999, "cli") is False
    t = asyncio.create_task(pipeline.process("bot", "lowt", {"q": "x"}))
    await asyncio.sleep(0.1)
    assert not t.done()
    await _cancel(t)

    rule = await db.get_remembered_rule(rule_id)
    assert rule["revoked_by"] == "cli" and rule["revoked_at"]
    revoked = [e for e in await db.get_audit_log(limit=20) if e.tool_name == "_remembered.revoke"]
    assert len(revoked) == 1 and revoked[0].remembered_rule_id == rule_id


async def test_list_rules_and_counts(db, tools):
    _, remembered, _, _ = await _stack(db, tools, [])
    a, _ = await db.upsert_remembered_rule(_row("bot", "lowt", "tool", None, None))
    await db.upsert_remembered_rule(
        _row("bot", "medt", "tool", None, None, action="deny", expires=None)
    )
    await db.upsert_remembered_rule(
        _row("bot", "sigt", "tool", None, None, expires="2020-01-01T00:00:00Z")
    )
    await remembered.revoke(a, "cli")
    counts = await remembered.counts()
    assert counts == {"active": 1, "allow": 0, "deny": 1, "expired": 1, "inactive": 0}
    assert len(await remembered.list_rules()) == 3
    assert [r["state"] for r in await remembered.list_rules(include_history=False)] == ["active"]


def test_rule_state_reasons(tools):
    registry = _registry(**tools)
    base = _row("bot", "lowt", "tool", None, None, fingerprint=tool_fingerprint(tools["lowt"]))
    base.update(revoked_at=None)

    assert rule_state(base, registry, now_iso=NOW) == ("active", "")
    assert rule_state(base, registry, now_iso=NOW, agent_known=lambda _a: False) == (
        "inactive",
        "agent removed",
    )
    assert rule_state({**base, "tool_name": "gone"}, registry, now_iso=NOW)[1] == "tool removed"
    assert rule_state({**base, "tool_fingerprint": "x"}, registry, now_iso=NOW)[1] == "tool changed"
    exact = {**base, "scope": "exact", "signature": "lowt(x)"}
    state = rule_state(
        exact, registry, now_iso=NOW, approval_for=lambda *_: ApprovalSpec(require="passkey")
    )
    assert state == ("inactive", "policy: rule requires a passkey")


def _row(
    agent,
    tool,
    scope,
    signature,
    args,
    *,
    action="allow",
    expires="2099-01-01T00:00:00Z",
    fingerprint=None,
):
    from agentpass.remembered import iso

    fp = fingerprint
    if fp is None:
        fp = tool_fingerprint(
            _tool(
                tool,
                {"lowt": "low", "medt": "medium", "hight": "high", "sigt": "low"}[tool],
                remember="signature" if tool == "sigt" else "args",
            )
        )
    return {
        "agent_id": agent,
        "scope": scope,
        "tool_name": tool,
        "signature": signature,
        "args_hash": args_hash(args) if args is not None and scope == "exact" else None,
        "pattern": signature or f"{tool}(*)",
        "action": action,
        "created_by": "42",
        "created_at": iso(),
        "expires_at": expires,
        "source_request_id": "req-1",
        "tool_fingerprint": fp,
    }


async def test_only_the_answer_that_wins_the_race_stores_a_rule(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    req, status, task = await _ask_and_answer(
        pipeline, channel, "lowt", {"q": "x"}, approved=True, remember="tool"
    )
    assert status is AnswerStatus.ACCEPTED
    late = await channel.answer(req.approval_id, False, remember="exact")
    assert late is AnswerStatus.ALREADY_RESOLVED
    await task
    [rule] = await db.list_remembered_rules()
    assert (rule["action"], rule["scope"]) == ("allow", "tool")


async def test_a_notify_only_answer_without_offer_cannot_store_anything(db, tools):
    """No coordinator service wired (or no offer): a scoped answer is refused, not ignored."""
    channel = FakeChannel()
    registry = _registry(**tools)
    engine = PermissionEngine(_rules(), registry)
    executor = AsyncMock(spec=Executor)
    coordinator = await started_coordinator(db, channel)  # no RememberedService
    pipeline = Pipeline(
        engine=engine, executor=executor, coordinator=coordinator, db=db, registry=registry
    )
    task = asyncio.create_task(pipeline.process("bot", "lowt", {"q": "x"}))
    for _ in range(100):
        if channel.sent:
            break
        await asyncio.sleep(0.01)
    assert channel.sent[0].remember is None
    assert await channel.answer(channel.sent[0].approval_id, True, remember="exact") is (
        AnswerStatus.REJECTED
    )
    assert await db.list_remembered_rules() == []
    await _cancel(task)
