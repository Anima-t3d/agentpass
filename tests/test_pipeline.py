"""Unit tests for agentpass.pipeline — the transport-neutral request pipeline."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentpass.approval import ApprovalReason
from agentpass.engine import Evaluation, PermissionEngine
from agentpass.executor import ExecutionError, Executor
from agentpass.models import Decision
from agentpass.pipeline import (
    ApprovalDenied,
    ApprovalTimeout,
    ApprovalUnavailable,
    ExecutionFailed,
    InvalidParams,
    Outcome,
    Pipeline,
    PolicyDenied,
    RateLimited,
    ServiceUnauthorized,
    UnknownTool,
)
from agentpass.server import (
    APPROVAL_DENIED,
    APPROVAL_TIMEOUT,
    APPROVAL_UNAVAILABLE,
    ERROR_CODES,
    EXECUTION_FAILED,
    INVALID_PARAMS,
    POLICY_DENIED,
    RATE_LIMIT_EXCEEDED,
    SERVICE_UNAUTHORIZED,
    UNKNOWN_TOOL,
)
from tests.fakes import FakeChannel, started_coordinator, stateful_mock_db


async def _make(decision=Decision.ALLOW, registry=None, **kw):
    engine = MagicMock(spec=PermissionEngine)
    engine.evaluate.return_value = Evaluation(decision)
    executor = AsyncMock(spec=Executor)
    executor.execute.return_value = {"ok": True}
    channel = FakeChannel()
    db = stateful_mock_db()
    coordinator = await started_coordinator(db, channel)
    p = Pipeline(
        engine=engine, executor=executor, coordinator=coordinator, db=db, registry=registry, **kw
    )
    return p, engine, executor, channel, db


async def _request_id(channel) -> str:
    for _ in range(100):
        if channel.sent:
            return channel.sent[-1].approval_id
        await asyncio.sleep(0.01)
    raise AssertionError("approval never sent")


def test_error_code_table_covers_every_error_and_keeps_gate11_codes():
    assert {
        UnknownTool: UNKNOWN_TOOL,
        InvalidParams: INVALID_PARAMS,
        PolicyDenied: POLICY_DENIED,
        ApprovalDenied: APPROVAL_DENIED,
        ApprovalTimeout: APPROVAL_TIMEOUT,
        ApprovalUnavailable: APPROVAL_UNAVAILABLE,
        RateLimited: RATE_LIMIT_EXCEEDED,
        ExecutionFailed: EXECUTION_FAILED,
        ServiceUnauthorized: SERVICE_UNAUTHORIZED,
    } == ERROR_CODES
    assert (UNKNOWN_TOOL, APPROVAL_UNAVAILABLE, RATE_LIMIT_EXCEEDED) == (-32007, -32008, -32006)


def test_approval_reason_values():
    assert ApprovalReason.TIMEOUT == "timeout"
    assert ApprovalReason.GATEWAY_SHUTDOWN == "gateway_shutdown"
    assert {r.value for r in ApprovalReason} == {
        "approved",
        "denied",
        "timeout",
        "no_channel",
        "gateway_shutdown",
        "restart",
        "rejected_proof",
    }


async def test_allow_executes_and_audits_with_agent():
    p, _, executor, _, db = await _make()
    out = await p.process("agent-a", "t", {"a": 1})
    assert isinstance(out, Outcome) and out.data == {"ok": True}
    assert not out.awaiting_delivery
    executor.execute.assert_awaited_once_with("t", {"a": 1})
    entry = db.log_audit.call_args[0][0]
    assert entry.agent_id == "agent-a" and entry.decision == "allow"
    assert entry.request_id == out.request_id


async def test_deny_raises_policy_denied_without_executing():
    p, _, executor, _, _ = await _make(Decision.DENY)
    with pytest.raises(PolicyDenied):
        await p.process("a", "t", {})
    executor.execute.assert_not_awaited()


async def test_unknown_tool_rejected_before_engine():
    registry = MagicMock()
    registry.get_tool.return_value = None
    p, engine, _, _, db = await _make(registry=registry)
    with pytest.raises(UnknownTool, match="Unknown tool: nope"):
        await p.process("a", "nope", {})
    engine.evaluate.assert_not_called()
    db.log_audit.assert_not_awaited()


async def test_invalid_params_from_engine_value_error():
    p, engine, _, _, _ = await _make()
    engine.evaluate.side_effect = ValueError("bad arg")
    with pytest.raises(InvalidParams, match="bad arg"):
        await p.process("a", "t", {})


async def test_rate_limit_is_per_agent():
    p, *_ = await _make(max_requests_per_minute=1)
    await p.process("a", "t", {})
    with pytest.raises(RateLimited):
        await p.process("a", "t", {})
    await p.process("b", "t", {})  # other agent unaffected


@pytest.mark.parametrize(
    ("exc", "message"),
    [(ExecutionError("nope"), "nope"), (RuntimeError("secret"), "Internal execution error")],
)
async def test_execution_failures_are_typed(exc, message):
    p, _, executor, _, _ = await _make()
    executor.execute.side_effect = exc
    with pytest.raises(ExecutionFailed) as ei:
        await p.process("a", "t", {})
    assert ei.value.message == message


async def test_ask_approved_executes():
    p, _, executor, channel, db = await _make(Decision.ASK)
    task = asyncio.create_task(p.process("a", "t", {}))
    rid = await _request_id(channel)
    await channel.approve(rid)
    out = await task
    assert out.awaiting_delivery and out.request_id == rid
    executor.execute.assert_awaited_once()
    kw = db.update_audit_resolution.call_args.kwargs
    assert kw["resolution"] == "approved" and kw["execution_result"] == {"ok": True}
    assert not p._pending
    db.delete_pending.assert_not_awaited()  # transport confirms delivery via complete()
    await p.complete(rid)
    db.delete_pending.assert_awaited_once_with(rid)


async def test_ask_denied():
    p, _, executor, channel, db = await _make(Decision.ASK)
    task = asyncio.create_task(p.process("a", "t", {}))
    rid = await _request_id(channel)
    await channel.deny(rid)
    with pytest.raises(ApprovalDenied, match="Denied by user") as ei:
        await task
    assert ei.value.awaiting_delivery
    executor.execute.assert_not_awaited()
    assert db.update_audit_resolution.call_args.kwargs["resolution"] == "denied"


async def test_first_answer_wins():
    p, _, executor, channel, _ = await _make(Decision.ASK)
    task = asyncio.create_task(p.process("a", "t", {}))
    rid = await _request_id(channel)
    await channel.deny(rid)
    await channel.approve(rid)
    with pytest.raises(ApprovalDenied):
        await task
    executor.execute.assert_not_awaited()


async def test_timeout_is_owned_by_pipeline():
    p, _, executor, channel, db = await _make(Decision.ASK, approval_timeout=0.05)
    with pytest.raises(ApprovalTimeout, match="timed out"):
        await p.process("a", "t", {})
    executor.execute.assert_not_awaited()
    [(handle, outcome)] = channel.finalized
    assert handle.ref == {"message_id": 1} and outcome.reason is ApprovalReason.TIMEOUT
    kw = db.update_audit_resolution.call_args.kwargs
    assert kw["resolution"] == "timed_out" and kw["resolved_by"] == "gateway"
    assert not p._pending


async def test_late_answer_after_timeout_is_ignored():
    p, _, executor, channel, _ = await _make(Decision.ASK, approval_timeout=0.05)
    with pytest.raises(ApprovalTimeout):
        await p.process("a", "t", {})
    await channel.approve(channel.sent[-1].approval_id)
    executor.execute.assert_not_awaited()


async def test_shutdown_resolves_pending_with_reason():
    p, _, _, channel, db = await _make(Decision.ASK)
    task = asyncio.create_task(p.process("a", "t", {}))
    await _request_id(channel)
    await p.resolve_all_pending()
    with pytest.raises(ApprovalDenied, match="shutting down"):
        await task
    assert db.update_audit_resolution.call_args.kwargs["resolution"] == "denied"


async def test_send_failure_is_approval_unavailable():
    p, _, executor, channel, db = await _make(Decision.ASK)
    channel.send_error = RuntimeError("telegram down")
    with pytest.raises(ApprovalUnavailable):
        await p.process("a", "t", {})
    db.delete_pending.assert_awaited_once()
    assert db.update_audit_resolution.call_args.kwargs["resolution"] == "send_failed"
    executor.execute.assert_not_awaited()


async def test_pending_limit():
    p, _, _, channel, _ = await _make(Decision.ASK, max_pending=1)
    first = asyncio.create_task(p.process("a", "t", {}))
    rid = await _request_id(channel)
    with pytest.raises(RateLimited, match="pending"):
        await p.process("a", "t", {})
    await channel.deny(rid)
    with pytest.raises(ApprovalDenied):
        await first


async def test_approved_but_execution_fails_keeps_pending_for_delivery():
    p, _, executor, channel, db = await _make(Decision.ASK)
    executor.execute.side_effect = ExecutionError("boom")
    task = asyncio.create_task(p.process("a", "t", {}))
    rid = await _request_id(channel)
    await channel.approve(rid)
    with pytest.raises(ExecutionFailed) as ei:
        await task
    assert ei.value.awaiting_delivery
    assert db.update_audit_resolution.call_args.kwargs["resolution"] == "approved"


async def test_store_undelivered_outcome_and_denial():
    p, _, _, _, db = await _make()
    await p.store_undelivered("r1", Outcome(request_id="r1", data={"x": 1}))
    assert json.loads(db.update_pending_result.call_args[0][1]) == {
        "status": "executed",
        "request_id": "r1",
        "data": {"x": 1},
    }
    await p.store_undelivered("r2", ApprovalTimeout("Approval timed out"))
    assert json.loads(db.update_pending_result.call_args[0][1]) == {
        "status": "timeout",
        "code": "approval_timeout",
        "request_id": None,
        "data": "Approval timed out",
    }
    await p.store_undelivered("r3", ExecutionFailed("x"))
    assert json.loads(db.update_pending_result.call_args[0][1])["status"] == "error"
