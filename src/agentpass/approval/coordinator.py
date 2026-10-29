"""Approval coordinator (DESIGN 4.2 and 4.3).

Owns everything a channel must not: the pending row, the fan-out, the one
timeout, the race between answers (arbitrated by the database, so it survives a
restart) and the final ``finalize`` on every channel.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentpass.approval.channel import (
    Answer,
    AnswerStatus,
    ApprovalChannel,
    ApprovalOutcome,
    ApprovalReason,
    ApprovalRequest,
    ChannelHandle,
    NoChannelError,
)
from agentpass.db import Database

if TYPE_CHECKING:
    from agentpass.preview import Preview, PreviewService, Unavailable
    from agentpass.remembered import RememberedService

logger = logging.getLogger(__name__)

FINALIZE_TIMEOUT = 10.0  # seconds a slow channel may hold up the agent's response


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def satisfies(channel: ApprovalChannel | None, answer: Answer, require: str) -> bool:
    """Does this answer count towards a rule's ``approval.require``?

    A denial from a trusted channel always counts (denying is safe, DESIGN 3.4);
    an approval needs the channel's trust and proof to meet the requirement.
    ``notify`` channels never resolve anything.
    """
    if channel is None or channel.trust != "trusted":
        return False
    if not answer.approved or require == "any_trusted":
        return True
    if require == "telegram":
        return "telegram_callback" in channel.proof_kinds
    if require == "passkey":
        return "webauthn" in channel.proof_kinds and answer.proof is not None
    return False


@dataclass
class _Waiter:
    req: ApprovalRequest
    future: asyncio.Future[ApprovalOutcome]
    handles: list[ChannelHandle] = field(default_factory=list)


class ApprovalCoordinator:
    """Gateway-owned approval flow over any number of channels. Also the channels' sink."""

    def __init__(
        self,
        db: Database,
        channels: list[ApprovalChannel],
        remembered: RememberedService | None = None,
        previews: PreviewService | None = None,
    ) -> None:
        names = [c.name for c in channels]
        if len(set(names)) != len(names):
            raise ValueError(f"Duplicate approval channel names: {names}")
        self._db = db
        self._remembered = remembered
        self._previews = previews
        self._channels = {c.name: c for c in channels}
        self._active: dict[str, ApprovalChannel] = {}
        self._waiters: dict[str, _Waiter] = {}

    @property
    def channels(self) -> list[ApprovalChannel]:
        return list(self._channels.values())

    # --- Lifecycle ---

    async def start(self) -> None:
        """Start the channels, then abandon approvals left over from a previous run."""
        for name, channel in self._channels.items():
            try:
                await channel.start(self)
            except Exception:
                logger.exception("Approval channel %s failed to start", name)
            else:
                self._active[name] = channel
        for row in await self._db.abandon_pending():
            outcome = ApprovalOutcome(
                approval_id=row["request_id"], approved=False, reason=ApprovalReason.RESTART
            )
            await self._finalize(self._load_handles(row.get("handles")), outcome)

    async def stop(self) -> None:
        for name, channel in list(self._active.items()):
            try:
                await channel.stop()
            except Exception:
                logger.warning("Approval channel %s failed to stop", name, exc_info=True)
        self._active.clear()

    async def resolve_all(self, reason: ApprovalReason = ApprovalReason.GATEWAY_SHUTDOWN) -> None:
        """Deny every open approval (shutdown)."""
        for approval_id, waiter in list(self._waiters.items()):
            await self._resolve(approval_id, waiter, self._system(approval_id, reason))

    async def health_check(self) -> dict[str, bool]:
        """Per-channel health; a channel that failed to start is unhealthy."""
        health: dict[str, bool] = {}
        for name, channel in self._channels.items():
            try:
                health[name] = name in self._active and await channel.health_check()
            except Exception:
                health[name] = False
        return health

    async def notify(self, text: str) -> None:
        """Plain owner notification on every channel that supports it."""
        for name, channel in self._active.items():
            try:
                await channel.notify(text)
            except Exception:
                logger.warning("Approval channel %s failed to notify", name, exc_info=True)

    # --- Requests ---

    async def request(
        self,
        req: ApprovalRequest,
        *,
        channels: list[str] | None = None,
        on_pending: Any = None,
        preview_args: dict[str, Any] | None = None,
    ) -> ApprovalOutcome:
        """Ask a human and wait for the resolution.

        ``channels`` limits the fan-out to the named channels (default: all).
        ``on_pending(approval_id, expires_at)`` is called once the request is out.
        ``preview_args`` are the unredacted args the preview is built from (``req.args``
        may be redacted for display); the default is ``req.args``.
        Raises ``NoChannelError`` (the row is deleted) when no channel that could
        satisfy ``req.require`` accepted it.
        """
        approval_id = req.approval_id
        await self._db.insert_pending(
            request_id=approval_id,
            tool_name=req.tool,
            args=req.args,
            signature=req.signature,
            expires_at=_iso(req.expires_at),
            agent_id=req.agent_id,
            agent_note=req.agent_note,
        )
        waiter = _Waiter(req, asyncio.get_running_loop().create_future())
        self._waiters[approval_id] = waiter  # before send: a fast tap must find it
        try:
            targets = [c for n, c in self._active.items() if channels is None or n in channels]
            preview = None
            if any(c.trust == "trusted" for c in targets):  # notify channels never get one
                preview = await self._build_preview(req, preview_args)
            sent = await asyncio.gather(*(self._send(c, req, preview) for c in targets))
            waiter.handles = [h for h in sent if h is not None]
            if not any(self._can_resolve(h.channel, req.require) for h in waiter.handles):
                await self._db.delete_pending(approval_id)
                self._waiters.pop(approval_id, None)
                await self._finalize(
                    waiter.handles, self._system(approval_id, ApprovalReason.NO_CHANNEL)
                )
                raise NoChannelError(f"No approval channel accepted request {approval_id}")
            await self._db.set_pending_handles(
                approval_id,
                json.dumps([{"channel": h.channel, "ref": h.ref} for h in waiter.handles]),
            )
            if on_pending is not None:
                on_pending(approval_id, req.expires_at)
            try:
                outcome = await asyncio.wait_for(
                    asyncio.shield(waiter.future), max(0.0, req.expires_at - time.time())
                )
            except TimeoutError:
                outcome = self._system(approval_id, ApprovalReason.TIMEOUT)
                if await self._db.transition_pending(approval_id, "resolved"):
                    waiter.future.set_result(outcome)
                else:
                    # An answer won the row at the last moment; it is about to land. If
                    # the row was resolved by something else, nobody can tell us how.
                    with contextlib.suppress(TimeoutError):
                        outcome = await asyncio.wait_for(asyncio.shield(waiter.future), 1.0)
        except NoChannelError:
            raise
        except BaseException:
            # cancelled or failed: nobody is waiting any more
            if self._waiters.pop(approval_id, None) is not None:
                await asyncio.shield(self._db.transition_pending(approval_id, "abandoned"))
                await asyncio.shield(
                    self._finalize(
                        waiter.handles, self._system(approval_id, ApprovalReason.GATEWAY_SHUTDOWN)
                    )
                )
            raise
        self._waiters.pop(approval_id, None)
        await self._finalize(waiter.handles, outcome)
        return outcome

    # --- Sink (called by channels) ---

    async def answer(self, approval_id: str, answer: Answer) -> AnswerStatus:
        """First valid answer wins; the database decides."""
        waiter = self._waiters.get(approval_id)
        if waiter is None:
            return AnswerStatus.ALREADY_RESOLVED
        channel = self._active.get(answer.channel)
        if not satisfies(channel, answer, waiter.req.require):
            logger.warning(
                "Rejected answer to %s from %s (require=%s)",
                approval_id,
                answer.channel,
                waiter.req.require,
            )
            return AnswerStatus.REJECTED
        if answer.remember is not None:
            # Offering the button is UX; this is the enforcement
            offer = waiter.req.remember
            if self._remembered is None or offer is None:
                return AnswerStatus.REJECTED
            if not offer.permits(answer.approved, answer.remember):
                logger.warning(
                    "Rejected %s-always (%s) for %s: not offered",
                    "allow" if answer.approved else "deny",
                    answer.remember,
                    approval_id,
                )
                return AnswerStatus.REJECTED
        outcome = ApprovalOutcome(
            approval_id=approval_id,
            approved=answer.approved,
            reason=ApprovalReason.APPROVED if answer.approved else ApprovalReason.DENIED,
            approver_id=answer.approver_id,
            channel=answer.channel,
            proof=answer.proof,
        )
        if not await self._resolve(approval_id, waiter, outcome, answer):
            return AnswerStatus.ALREADY_RESOLVED
        return AnswerStatus.ACCEPTED

    # --- Internals ---

    async def _resolve(
        self,
        approval_id: str,
        waiter: _Waiter,
        outcome: ApprovalOutcome,
        answer: Answer | None = None,
    ) -> bool:
        if not await self._db.transition_pending(approval_id, "resolved"):
            return False
        # Only the answer that won the race may store a rule; a failure here keeps
        # the decision for this one request but remembers nothing
        if answer is not None and answer.remember is not None and self._remembered is not None:
            try:
                outcome.rule_id = await self._remembered.create(
                    waiter.req, answer.remember, answer.approved, answer.approver_id
                )
                outcome.remembered = answer.remember if outcome.rule_id else None
            except Exception:
                logger.exception("Could not store the remembered rule for %s", approval_id)
        waiter.future.set_result(outcome)
        return True

    def _can_resolve(self, channel_name: str, require: str) -> bool:
        probe = Answer(approved=True, channel=channel_name, approver_id="", proof=True)
        return satisfies(self._active.get(channel_name), probe, require)

    async def _build_preview(
        self, req: ApprovalRequest, args: dict[str, Any] | None
    ) -> Preview | Unavailable | None:
        """Build, store and record the preview. Never raises: a failure is just no preview."""
        if self._previews is None:
            return None
        try:
            preview = await self._previews.build(req.tool, req.args if args is None else args)
            if preview is None:
                return None
            await self._db.set_pending_preview(req.approval_id, json.dumps(preview.to_dict()))
            await self._db.update_audit_preview(
                req.approval_id, preview.digest or None, preview.title or None, preview.status
            )
            return preview
        except Exception:
            logger.exception("Could not build or store the preview for %s", req.approval_id)
            return None

    async def _send(
        self,
        channel: ApprovalChannel,
        req: ApprovalRequest,
        preview: Preview | Unavailable | None = None,
    ) -> ChannelHandle | None:
        try:
            if channel.trust == "trusted":
                req = replace(req, preview=preview)
            else:  # notify channels: tool, signature and arg_display only
                req = replace(req, preview=None, agent_note=None)
            return await channel.send(req)
        except Exception:
            logger.exception("Approval channel %s failed to send %s", channel.name, req.approval_id)
            return None

    async def _finalize(self, handles: list[ChannelHandle], outcome: ApprovalOutcome) -> None:
        async def one(handle: ChannelHandle) -> None:
            channel = self._channels.get(handle.channel)
            if channel is None:
                return
            try:
                await asyncio.wait_for(channel.finalize(handle, outcome), FINALIZE_TIMEOUT)
            except Exception:
                logger.warning(
                    "Approval channel %s failed to finalize", handle.channel, exc_info=True
                )

        await asyncio.gather(*(one(h) for h in handles))

    @staticmethod
    def _load_handles(raw: str | None) -> list[ChannelHandle]:
        try:
            return [ChannelHandle(h["channel"], h.get("ref", {})) for h in json.loads(raw or "[]")]
        except (ValueError, KeyError, TypeError):
            return []

    @staticmethod
    def _system(approval_id: str, reason: ApprovalReason) -> ApprovalOutcome:
        return ApprovalOutcome(approval_id=approval_id, approved=False, reason=reason)
