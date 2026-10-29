"""Transport-neutral request pipeline (DESIGN section 11).

``Pipeline.process(agent, tool, args)`` runs rate limit, registry lookup,
validation, signature, policy, audit, approval and execution, and returns an
``Outcome`` or raises a typed ``PipelineError``. Transports (WebSocket, MCP)
only translate; they own no policy, timeout or approval-race logic.

Approval requirements come from the matched rule's ``approval`` block
(DESIGN 3.6, 5.3): ``require`` and ``channels`` go to the coordinator as given
(the coordinator owns the ``no_channel`` outcome), and the approval timeout is
the first of: the rule's ``approval.timeout``, the agent's ``approval_timeout``,
the global ``approval_timeout``. A rule without an ``approval`` block uses the
coordinator defaults.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentpass.agents import AgentIdentity
from agentpass.approval import (
    ApprovalCoordinator,
    ApprovalOutcome,
    ApprovalReason,
    ApprovalRequest,
    NoChannelError,
)
from agentpass.config import ApprovalSpec
from agentpass.db import Database
from agentpass.engine import PermissionEngine, build_signature, validate_args
from agentpass.executor import ExecutionError, Executor
from agentpass.models import AuditEntry, Decision, PendingApproval, ToolRequest
from agentpass.services.base import ServiceUnauthorizedError

if TYPE_CHECKING:
    from agentpass.registry import ToolRegistry
    from agentpass.remembered import RememberedService

logger = logging.getLogger(__name__)

GATEWAY_USER = "gateway"  # user_id on system-made approval results


def _epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class RateLimiter:
    """Sliding-window rate limiter."""

    def __init__(self, max_per_minute: int) -> None:
        self._max = max_per_minute
        self._timestamps: list[float] = []

    def check(self) -> bool:
        """Return True if request is allowed, False if rate limited."""
        now = time.monotonic()
        self._timestamps = [t for t in self._timestamps if now - t < 60]
        if len(self._timestamps) >= self._max:
            return False
        self._timestamps.append(now)
        return True


# --- Outcome and typed errors ---


@dataclass
class Outcome:
    """A successfully executed tool request."""

    request_id: str
    data: dict[str, Any]
    awaiting_delivery: bool = False  # a pending_requests row exists until complete()


class PipelineError(Exception):
    """Base class for pipeline failures. Subclasses map to transport error codes.

    ``code`` is the stable string code shared by every transport (DESIGN 7.5);
    each transport maps the class to its own wire code in one table.
    """

    code = "internal_error"

    def __init__(
        self,
        message: str,
        *,
        request_id: str | None = None,
        awaiting_delivery: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.request_id = request_id
        self.awaiting_delivery = awaiting_delivery


class UnknownTool(PipelineError):
    code = "unknown_tool"


class InvalidParams(PipelineError):
    code = "invalid_params"


class PolicyDenied(PipelineError):
    code = "policy_denied"


class ApprovalDenied(PipelineError):
    code = "approval_denied"


class ApprovalTimeout(PipelineError):
    code = "approval_timeout"


class ApprovalUnavailable(PipelineError):
    code = "no_channel"


class RateLimited(PipelineError):
    code = "rate_limited"


class ExecutionFailed(PipelineError):
    code = "execution_failed"


class ServiceUnauthorized(ExecutionFailed):
    """The service needs owner action (OAuth consent). Carries no upstream detail."""

    code = "service_unauthorized"


# Called once with (request_id, expires_at epoch) when a request starts waiting for a human
PendingCallback = Callable[[str, float], None]

IDEMPOTENCY_TTL = 24 * 3600  # seconds a finished keyed call stays replayable


class _KeyedCall:
    """One in-flight or finished call registered under an idempotency key."""

    def __init__(self, tool: str, args: Any, note: str | None = None) -> None:
        self.tool = tool
        self.args = args
        self.note = note  # first note wins; a replay with another note joins this call
        self.task: asyncio.Task[Outcome] | None = None
        self.pending: tuple[str, float] | None = None
        self.callbacks: list[PendingCallback] = []
        self.finished_at: float | None = None

    def subscribe(self, callback: PendingCallback) -> None:
        if self.pending is not None:
            callback(*self.pending)
        else:
            self.callbacks.append(callback)

    def notify(self, request_id: str, expires_at: float) -> None:
        self.pending = (request_id, expires_at)
        for callback in self.callbacks:
            callback(request_id, expires_at)
        self.callbacks.clear()


def _canonical(args: Any) -> str:
    return json.dumps(args, sort_keys=True, default=str)


def _payload(result: Outcome | PipelineError) -> dict[str, Any]:
    """The stored form of a final result (pending_requests.result, idempotency_keys.result)."""
    if isinstance(result, Outcome):
        return {"status": "executed", "request_id": result.request_id, "data": result.data}
    if isinstance(result, ApprovalTimeout):
        status = "timeout"
    elif isinstance(result, (ApprovalDenied, PolicyDenied)):
        status = "denied"
    else:
        status = "error"
    # Upstream detail is never stored: execution errors keep a fixed message
    message = "Execution failed" if isinstance(result, ExecutionFailed) else result.message
    return {"status": status, "code": result.code, "request_id": result.request_id, "data": message}


_ERRORS_BY_CODE: dict[str, type[PipelineError]] = {
    cls.code: cls
    for cls in (PolicyDenied, ApprovalDenied, ApprovalTimeout, ExecutionFailed, ServiceUnauthorized)
}


# --- Pipeline ---


class Pipeline:
    """Shared request pipeline used by every transport."""

    def __init__(
        self,
        *,
        engine: PermissionEngine,
        executor: Executor,
        coordinator: ApprovalCoordinator,
        db: Database,
        approval_timeout: int = 900,
        max_requests_per_minute: int = 60,
        max_pending: int = 10,
        registry: ToolRegistry | None = None,
        remembered: RememberedService | None = None,
    ) -> None:
        self._engine = engine
        self._remembered = remembered
        self._executor = executor
        self._coordinator = coordinator
        self._db = db
        self._approval_timeout = approval_timeout
        self._registry = registry
        self._max_per_minute = max_requests_per_minute
        self._max_pending = max_pending
        self._rate_limiters: dict[str, RateLimiter] = {}
        self._pending: dict[str, PendingApproval] = {}
        self._resolve_lock = asyncio.Lock()
        self._keyed: dict[tuple[str, str], _KeyedCall] = {}  # cache; the DB is the record
        self._bg: set[asyncio.Task] = set()

    async def process(
        self,
        agent: str | AgentIdentity,
        tool: str,
        args: Any,
        idempotency_key: str | None = None,
        on_pending: PendingCallback | None = None,
        agent_note: str | None = None,
    ) -> Outcome:
        """Run one tool request. Returns an Outcome or raises a PipelineError.

        ``agent_note`` is the already sanitized, unverified text the agent attached. The
        transport adapter pops it from the arguments first; it goes only to the approval
        display and the audit row, never into validation, signature, hashing or execution.

        A plain string is an identity with the gateway defaults and engine.
        A repeat of the same ``(agent, idempotency_key)`` joins the original call
        (its approval or result) instead of asking again; successes and human
        denials stay replayable for 24 h, other failures are retried afresh.
        ``on_pending`` is called with ``(request_id, expires_at)`` once the call
        is waiting for a human, so a transport can stop waiting and hand out the id.
        """
        identity = agent if isinstance(agent, AgentIdentity) else AgentIdentity(id=agent)
        if idempotency_key is None:
            return await self._run(identity, tool, args, on_pending, agent_note)

        key = (identity.id, idempotency_key)
        self._purge_keyed()
        call = self._keyed.get(key)
        if call is None:
            stored = await self._db.get_idempotency(*key)
            call = self._keyed.get(key)  # a concurrent call may have registered meanwhile
            if call is None and stored is not None:
                replay = self._replay(stored, tool, args)
                if replay is not None:
                    return replay
        if call is not None and (call.tool, call.args) != (tool, args):
            raise InvalidParams("idempotency_key was already used for a different request")
        if call is None:
            call = _KeyedCall(tool, args, agent_note)
            await self._db.put_idempotency(*key, tool, _canonical(args))
            call.task = asyncio.create_task(self._run_keyed(identity, key, call))
            call.task.add_done_callback(lambda t, k=key, c=call: self._keyed_done(k, c, t))
            self._keyed[key] = call
        if on_pending is not None:
            call.subscribe(on_pending)
        assert call.task is not None
        return await asyncio.shield(call.task)

    def _replay(self, stored: dict[str, Any], tool: str, args: Any) -> Outcome | None:
        """Return/raise the stored result of a finished keyed call; None if it has none."""
        if (stored["tool_name"], stored["args"]) != (tool, _canonical(args)):
            raise InvalidParams("idempotency_key was already used for a different request")
        if stored["result"] is None:
            return None
        payload = json.loads(stored["result"])
        request_id = payload.get("request_id") or stored["request_id"]
        if payload["status"] == "executed":
            return Outcome(request_id=request_id, data=payload["data"])
        cls = _ERRORS_BY_CODE.get(payload.get("code", ""), ExecutionFailed)
        raise cls(payload["data"], request_id=request_id)

    async def _run_keyed(
        self, identity: AgentIdentity, key: tuple[str, str], call: _KeyedCall
    ) -> Outcome:
        """Run a keyed call and persist its key state: request id, then a replayable result."""

        def on_pending(request_id: str, expires_at: float) -> None:
            call.notify(request_id, expires_at)
            task = asyncio.ensure_future(self._db.set_idempotency_request(*key, request_id))
            self._bg.add(task)
            task.add_done_callback(self._bg.discard)

        try:
            outcome = await self._run(identity, call.tool, call.args, on_pending, call.note)
        except (PolicyDenied, ApprovalDenied, ApprovalTimeout) as e:
            await self._db.set_idempotency_result(*key, json.dumps(_payload(e)))
            raise
        except BaseException:
            await asyncio.shield(self._db.delete_idempotency(*key))  # failures retry afresh
            raise
        await self._db.set_idempotency_result(*key, json.dumps(_payload(outcome)))
        return outcome

    def _keyed_done(self, key: tuple[str, str], call: _KeyedCall, task: asyncio.Task) -> None:
        call.finished_at = time.monotonic()
        error = None if task.cancelled() else task.exception()  # marks it retrieved
        replayable = not task.cancelled() and (
            error is None or isinstance(error, (PolicyDenied, ApprovalDenied, ApprovalTimeout))
        )
        if not replayable and self._keyed.get(key) is call:
            del self._keyed[key]

    def _purge_keyed(self) -> None:
        now = time.monotonic()
        for key, call in list(self._keyed.items()):
            if call.finished_at is not None and now - call.finished_at > IDEMPOTENCY_TTL:
                del self._keyed[key]

    def pending_for(self, agent_id: str) -> list[dict[str, Any]]:
        """Open approvals of one agent (request_id, tool, signature, expires_at)."""
        return [
            {
                "request_id": request_id,
                "tool": p.request.tool_name,
                "signature": p.request.signature,
                "expires_at": _epoch_to_iso(p.expires_at),
            }
            for request_id, p in self._pending.items()
            if p.agent_id == agent_id
        ]

    async def _run(
        self,
        identity: AgentIdentity,
        tool: str,
        args: Any,
        on_pending: PendingCallback | None,
        agent_note: str | None = None,
    ) -> Outcome:
        agent = identity.id
        engine = identity.engine or self._engine
        limiter = self._rate_limiters.get(agent)
        if limiter is None:
            rpm = identity.requests_per_minute or self._max_per_minute
            limiter = self._rate_limiters[agent] = RateLimiter(rpm)
        if not limiter.check():
            raise RateLimited("Rate limit exceeded")

        # Reject unknown tools before the engine (never reaches a human)
        if self._registry is not None and self._registry.get_tool(tool) is None:
            raise UnknownTool(f"Unknown tool: {tool}")

        # Validate args and build the signature once; policy, audit and the
        # approval message all use this same string.
        try:
            validate_args(tool, args, self._registry)
            signature = build_signature(tool, args, self._registry)
            evaluation = engine.evaluate(tool, args, signature=signature)
            decision = evaluation.decision
        except (ValueError, TypeError) as e:
            raise InvalidParams(str(e)) from e

        # Remembered decisions (docs/REMEMBERED-DECISIONS.md section 2). A static deny
        # (floor, agent file) is final and never reaches them.
        verdict = None
        if self._remembered is not None and decision is not Decision.DENY:
            verdict = await self._remembered.resolve(
                agent, tool, signature, args, decision, evaluation.approval
            )
            if verdict is not None:
                decision = verdict.decision

        # Generated id, decoupled from any transport message id
        request = ToolRequest(id=str(uuid.uuid4()), tool_name=tool, args=args, signature=signature)
        await self._db.log_audit(
            AuditEntry(
                request_id=request.id,
                tool_name=tool,
                args=self._audit_args(tool, args),
                signature=signature,
                decision=decision.value,
                agent_id=agent,
                agent_note=agent_note,
                **(
                    {
                        "resolution": f"remembered_{decision.value}",
                        "resolved_by": f"rule:#{verdict.rule['id']}",
                        "resolved_at": time.time(),
                        "remembered_rule_id": verdict.rule["id"],
                    }
                    if verdict is not None
                    else {}
                ),
            )
        )
        if verdict is not None:
            await self._remembered.touch(verdict.rule["id"])

        if decision == Decision.ALLOW:
            data = await self._execute(request)
            return Outcome(request_id=request.id, data=data)
        if decision == Decision.DENY:
            raise PolicyDenied("Denied by policy", request_id=request.id)
        cap = identity.max_pending or self._max_pending
        if sum(1 for p in self._pending.values() if p.agent_id == agent) >= cap:
            raise RateLimited("Too many pending approvals", request_id=request.id)
        return await self._ask(request, identity, on_pending, evaluation.approval, agent_note)

    def _audit_args(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        return self._registry.redact_args(tool, args) if self._registry else args

    def _audit_result(self, tool: str, data: dict[str, Any] | None) -> dict[str, Any] | None:
        return self._registry.audit_result(tool, data) if self._registry else data

    async def _execute(self, request: ToolRequest) -> dict[str, Any]:
        try:
            args = request.args
            if self._registry:
                args = self._registry.apply_defaults(request.tool_name, args)
            return await self._executor.execute(request.tool_name, args)
        except ServiceUnauthorizedError as e:
            # no upstream detail reaches the agent (DESIGN 7.5)
            raise ServiceUnauthorized("Service unauthorized", request_id=request.id) from e
        except ExecutionError as e:
            raise ExecutionFailed(str(e), request_id=request.id) from e
        except Exception as e:
            logger.exception("Unexpected error executing %s", request.tool_name)
            raise ExecutionFailed("Internal execution error", request_id=request.id) from e

    async def _ask(
        self,
        request: ToolRequest,
        identity: AgentIdentity,
        on_pending: PendingCallback | None = None,
        approval: ApprovalSpec | None = None,
        agent_note: str | None = None,
    ) -> Outcome:
        request_id = request.id
        timeout = (
            (approval and approval.timeout) or identity.approval_timeout or self._approval_timeout
        )
        expires_at_epoch = time.time() + timeout
        tool_def = self._registry.get_tool(request.tool_name) if self._registry else None
        approval_req = ApprovalRequest(
            approval_id=request_id,
            agent_id=identity.id,
            agent_name=identity.name,
            tool=request.tool_name,
            signature=request.signature,
            args=self._audit_args(request.tool_name, request.args),
            risk=getattr(tool_def, "risk", None),
            expires_at=expires_at_epoch,
            agent_note=agent_note,
            remember=(
                self._remembered.offer(request.tool_name, request.signature, request.args, approval)
                if self._remembered is not None
                else None
            ),
        )
        coordinator_args: dict[str, Any] = {}
        if getattr(getattr(tool_def, "preview", None), "require_page", False):
            # preview.require_page: only the page, where the preview is read in full, can approve
            approval_req.require = "passkey"
        if approval is not None:
            if approval.require is not None:
                approval_req.require = approval.require
            if approval.channels is not None:
                coordinator_args["channels"] = list(approval.channels)

        # Registered before the first await, so the per-agent cap sees it immediately
        self._pending[request_id] = PendingApproval(
            request=request, expires_at=expires_at_epoch, agent_id=identity.id
        )

        try:
            result = await self._coordinator.request(
                approval_req, on_pending=on_pending, preview_args=request.args, **coordinator_args
            )
        except NoChannelError as e:
            logger.error("No approval channel accepted request %s", request_id)
            await self._db.update_audit_resolution(
                request_id=request_id,
                resolution="send_failed",
                resolved_by=GATEWAY_USER,
                resolved_at=time.time(),
            )
            raise ApprovalUnavailable(
                "Could not deliver approval request", request_id=request_id
            ) from e
        finally:
            self._pending.pop(request_id, None)

        data: dict[str, Any] | None = None
        failure: ExecutionFailed | None = None
        if result.approved:
            try:
                data = await self._execute(request)
            except ExecutionFailed as e:
                failure = e

        await self._db.update_audit_resolution(
            request_id=request_id,
            resolution=self._resolution_label(result),
            resolved_by=result.approver_id,
            resolved_at=result.timestamp,
            execution_result=self._audit_result(request.tool_name, data),
            remembered_rule_id=result.rule_id,
        )

        if failure is not None:
            failure.awaiting_delivery = True
            raise failure
        if data is not None:
            return Outcome(request_id=request_id, data=data, awaiting_delivery=True)
        if result.reason == ApprovalReason.TIMEOUT:
            raise ApprovalTimeout(
                "Approval timed out", request_id=request_id, awaiting_delivery=True
            )
        msg = (
            "Gateway shutting down"
            if result.reason == ApprovalReason.GATEWAY_SHUTDOWN
            else "Denied by user"
        )
        raise ApprovalDenied(msg, request_id=request_id, awaiting_delivery=True)

    @staticmethod
    def _resolution_label(result: ApprovalOutcome) -> str:
        if result.reason == ApprovalReason.TIMEOUT:
            return "timed_out"
        return "approved" if result.approved else "denied"

    # --- Delivery bookkeeping (called by the transport adapter) ---

    async def complete(self, request_id: str) -> None:
        """The transport delivered the response; drop the pending row."""
        await self._db.delete_pending(request_id)

    async def store_undelivered(self, request_id: str, result: Outcome | PipelineError) -> None:
        """Keep a final result in the DB (get_pending_results, MCP gateway_result)."""
        if not isinstance(result, (Outcome, ApprovalDenied, ApprovalTimeout, ExecutionFailed)):
            await self._db.delete_pending(request_id)
            return
        await self._db.update_pending_result(request_id, json.dumps(_payload(result)))

    # --- Approval resolution ---

    async def resolve_all_pending(
        self, reason: ApprovalReason = ApprovalReason.GATEWAY_SHUTDOWN
    ) -> None:
        """Deny every pending approval (shutdown)."""
        await self._coordinator.resolve_all(reason)
