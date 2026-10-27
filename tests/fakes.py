"""Shared fakes for approval tests: no Telegram, no network."""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import AsyncMock

from agentpass.approval import (
    Answer,
    AnswerStatus,
    ApprovalChannel,
    ApprovalCoordinator,
    ApprovalOutcome,
    ApprovalRequest,
    ApprovalSink,
    ChannelHandle,
)
from agentpass.db import Database


class FakeChannel(ApprovalChannel):
    """Records what the coordinator does; tests drive ``sink.answer`` through it."""

    proof_kinds: ClassVar[set[str]] = {"telegram_callback"}

    def __init__(self, name="telegram", trust="trusted", proof_kinds=None, healthy=True):
        self.name = name
        self.trust = trust
        if proof_kinds is not None:
            self.proof_kinds = proof_kinds
        self.sink: ApprovalSink | None = None
        self.sent: list[ApprovalRequest] = []
        self.finalized: list[tuple[ChannelHandle, ApprovalOutcome]] = []
        self.send_error: Exception | None = None
        self.started = self.stopped = False
        self.healthy = healthy

    async def start(self, sink):
        self.sink = sink
        self.started = True

    async def stop(self):
        self.stopped = True

    async def send(self, req):
        if self.send_error:
            raise self.send_error
        self.sent.append(req)
        return ChannelHandle(self.name, {"message_id": len(self.sent)})

    async def finalize(self, handle, outcome):
        self.finalized.append((handle, outcome))

    async def health_check(self):
        return self.healthy

    @property
    def last_request(self) -> ApprovalRequest | None:
        return self.sent[-1] if self.sent else None

    async def answer(
        self, approval_id, approved=True, approver="test-user", proof=None, remember=None
    ):
        return await self.sink.answer(
            approval_id,
            Answer(
                approved=approved,
                channel=self.name,
                approver_id=approver,
                proof=proof,
                remember=remember,
            ),
        )

    async def approve(self, approval_id, approver="test-user") -> AnswerStatus:
        return await self.answer(approval_id, True, approver)

    async def deny(self, approval_id, approver="test-user") -> AnswerStatus:
        return await self.answer(approval_id, False, approver)


def stateful_mock_db() -> AsyncMock:
    """AsyncMock(Database) whose ``transition_pending`` really arbitrates, once per id."""
    db = AsyncMock(spec=Database)
    resolved: set[str] = set()

    async def transition(request_id, state):
        if request_id in resolved:
            return False
        resolved.add(request_id)
        return True

    db.transition_pending.side_effect = transition
    db.abandon_pending.return_value = []
    return db


async def started_coordinator(db, *channels, remembered=None) -> ApprovalCoordinator:
    coordinator = ApprovalCoordinator(db, list(channels), remembered)
    await coordinator.start()
    return coordinator


def make_coordinator(db, *channels) -> ApprovalCoordinator:
    """A coordinator with its channels already active, for synchronous test setup.

    Equivalent to ``await coordinator.start()`` minus the leftover-row abandonment;
    pokes the coordinator's private state on purpose, so only tests use it.
    """
    coordinator = ApprovalCoordinator(db, list(channels))
    for channel in channels:
        channel.sink = coordinator
        coordinator._active[channel.name] = channel
    return coordinator
