"""Approval channel interface (DESIGN 4.1).

A channel shows an approval request to a human and reports answers to the
coordinator through a sink. It decides nothing: no race state, no timeout.
Importable without any passkey or Telegram code.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:
    from agentpass.preview.model import Preview, Unavailable

Trust = Literal["trusted", "notify"]

REQUIRE_LEVELS = ("any_trusted", "telegram", "passkey")


class ApprovalReason(StrEnum):
    """Why an approval was resolved (DESIGN 4.2)."""

    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    NO_CHANNEL = "no_channel"
    GATEWAY_SHUTDOWN = "gateway_shutdown"
    RESTART = "restart"
    REJECTED_PROOF = "rejected_proof"


class NoChannelError(Exception):
    """No channel accepted the approval request."""


@dataclass(frozen=True)
class RememberOffer:
    """Which "always" answers a request may get (docs/REMEMBERED-DECISIONS.md section 3).

    Computed by the gateway from current policy. A channel only renders it; the
    coordinator enforces it again when the answer arrives.
    """

    allow_exact: bool = False
    allow_tool: bool = False
    deny_exact: bool = True
    deny_tool: bool = True
    args_hash: str | None = None  # None: "exact" matches the signature only (remember: signature)
    tool_fingerprint: str = ""
    allow_exact_days: int = 90
    allow_tool_days: int = 30

    def permits(self, approved: bool, scope: str) -> bool:
        if scope not in ("exact", "tool"):
            return False
        return getattr(self, f"{'allow' if approved else 'deny'}_{scope}")

    @property
    def any_allow(self) -> bool:
        return self.allow_exact or self.allow_tool

    @property
    def any_deny(self) -> bool:
        return self.deny_exact or self.deny_tool


@dataclass
class ApprovalRequest:
    """A tool request awaiting human approval, as every channel sees it."""

    approval_id: str
    agent_id: str
    tool: str
    signature: str  # human-readable tool signature
    args: dict[str, Any]
    expires_at: float  # epoch seconds
    agent_name: str = ""  # shown in every approval message
    risk: str | None = None  # low | medium | high, display hint only
    require: str = "any_trusted"  # any_trusted | telegram | passkey
    arg_display: dict[str, str] = field(default_factory=dict)  # arg name -> display hint
    remember: RememberOffer | None = None  # None: no "always" buttons
    # Set by the coordinator for trusted channels only; None for notify channels and tools
    # without a preview block. Gateway-built, so it is the trusted part of what is shown.
    preview: Preview | Unavailable | None = None
    # Unverified agent text, shown in its own labelled box. Trusted channels only.
    agent_note: str | None = None


@dataclass
class ChannelHandle:
    """Where a channel put the request. JSON-serialisable so it survives a restart."""

    channel: str
    ref: dict[str, Any] = field(default_factory=dict)


@dataclass
class Answer:
    """A human answer, as reported by a channel."""

    approved: bool
    channel: str
    approver_id: str
    proof: Any = None  # channel-verified evidence (e.g. a WebAuthn assertion record)
    remember: str | None = None  # "exact" | "tool": store a remembered rule (Allow/Deny always)


@dataclass
class ApprovalOutcome:
    """The final resolution of one approval request."""

    approval_id: str
    approved: bool
    reason: ApprovalReason
    approver_id: str = "gateway"  # "gateway" for system resolutions
    channel: str | None = None
    proof: Any = None
    timestamp: float = field(default_factory=time.time)
    rule_id: int | None = None  # remembered rule created by this answer
    remembered: str | None = None  # its scope


class AnswerStatus(StrEnum):
    ACCEPTED = "accepted"
    ALREADY_RESOLVED = "already_resolved"  # lost the race, or the request is not pending
    REJECTED = "rejected"  # channel trust or proof does not satisfy the rule


class ApprovalSink(Protocol):
    """What a channel calls when a human answers."""

    async def answer(self, approval_id: str, answer: Answer) -> AnswerStatus: ...


class ApprovalChannel(ABC):
    """One way of asking a human. Subclasses set ``name``, ``trust`` and ``proof_kinds``."""

    name: str
    trust: Trust
    proof_kinds: set[str]  # {"telegram_callback", "webauthn"}

    @abstractmethod
    async def start(self, sink: ApprovalSink) -> None:
        """Start listening; report answers with ``sink.answer``."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop listening and release resources."""

    @abstractmethod
    async def send(self, req: ApprovalRequest) -> ChannelHandle:
        """Show the request. Raise if it could not be delivered."""

    @abstractmethod
    async def finalize(self, handle: ChannelHandle, outcome: ApprovalOutcome) -> None:
        """Edit or remove the message once resolved. Best effort; never decides."""

    async def notify(self, text: str) -> None:  # noqa: B027
        """Send a plain owner notification. Default: not supported."""

    async def health_check(self) -> bool:
        return True
