"""Display-only notification channels (docs/DESIGN.md, section 4.4): webhook or command.

A notify channel shows a pending approval and links to the out-of-band approval
page. It is ``trust = "notify"`` with no proof kinds and never calls
``sink.answer``, so it has no way to approve or deny anything. Delivery goes
through a small transport seam; the real target is configured per deployment:

* ``webhook``: POST a JSON body to a URL (short timeout, one retry on a
  connection error, never a retry on an HTTP error).
* ``command``: run a local command (argv, no shell) with the message on stdin.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, ClassVar

import aiohttp

from agentpass.approval.channel import (
    ApprovalChannel,
    ApprovalOutcome,
    ApprovalReason,
    ApprovalRequest,
    ApprovalSink,
    ChannelHandle,
)
from agentpass.config import NotifyConfig

logger = logging.getLogger(__name__)

MAX_VALUE_CHARS = 500

_RESOLUTION_HEADERS = {
    ApprovalReason.TIMEOUT: "⏰ Expired (timed out)",
    ApprovalReason.GATEWAY_SHUTDOWN: "⏰ Expired (gateway shutting down)",
    ApprovalReason.RESTART: "⏰ Expired (gateway restarted)",
    ApprovalReason.NO_CHANNEL: "⏰ Expired (no approval channel available)",
    ApprovalReason.REJECTED_PROOF: "❌ Rejected (proof rejected)",
}


def _clip(value: Any) -> str:
    text = str(value)
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "…"


def approval_link(origin: str | None) -> str | None:
    """The approval page, or None when the passkey page is not enabled."""
    return f"{origin.rstrip('/')}/" if origin else None


def message_text(req: ApprovalRequest, link: str | None) -> str:
    """Agent, tool, args (with display hints), risk, expiry and the approval link."""
    expires = datetime.fromtimestamp(req.expires_at, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"🚨 Approval needed: {req.tool}",
        f"Agent: {req.agent_name or req.agent_id}",
    ]
    if req.risk:
        lines.append(f"Risk: {req.risk}")
    lines.append(f"Expires: {expires}")
    for key, value in req.args.items():
        hint = req.arg_display.get(key)
        label = f"{key} ({hint})" if hint else key
        lines.append(f"  {label}: {_clip(value)}")
    if link:
        lines.append(f"Approve or deny on the approval page: {link}")
    else:
        lines.append("Answer it on a trusted channel (this one cannot approve).")
    return "\n".join(lines)


def resolution_text(outcome: ApprovalOutcome) -> str:
    if outcome.reason in _RESOLUTION_HEADERS:
        return _RESOLUTION_HEADERS[outcome.reason]
    if outcome.approved:
        return f"✅ Approved by {outcome.approver_id}"
    return f"❌ Denied by {outcome.approver_id}"


class Transport(ABC):
    """How a message leaves the gateway. Raises on delivery failure."""

    @abstractmethod
    async def deliver(self, event: dict[str, Any], text: str) -> None: ...

    async def close(self) -> None:
        return None


class WebhookTransport(Transport):
    def __init__(self, url: str, timeout: float) -> None:
        self._url = url
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: aiohttp.ClientSession | None = None

    async def deliver(self, event: dict[str, Any], text: str) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession(timeout=self._timeout)
        body = {**event, "text": text}
        for attempt in (1, 2):
            try:
                async with self._session.post(self._url, json=body) as resp:
                    if resp.status >= 400:
                        # An HTTP answer is final: never retried.
                        raise RuntimeError(f"webhook answered HTTP {resp.status}")
                    return
            except (aiohttp.ClientConnectionError, TimeoutError):
                if attempt == 2:
                    raise

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None


class CommandTransport(Transport):
    """Run an argv with the message on stdin. No shell, no interpolation of content."""

    def __init__(self, argv: list[str], timeout: float) -> None:
        self._argv = argv
        self._timeout = timeout

    async def deliver(self, event: dict[str, Any], text: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            *self._argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.communicate(text.encode()), self._timeout)
        except BaseException:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise
        if proc.returncode != 0:
            raise RuntimeError(f"command exited with status {proc.returncode}")


def build_transport(config: NotifyConfig) -> Transport:
    if config.transport == "webhook":
        return WebhookTransport(config.url, config.timeout)
    if config.transport == "command":
        return CommandTransport(config.command, config.timeout)
    raise ValueError(f"Unsupported notify transport: {config.transport!r}")


class NotifyChannel(ApprovalChannel):
    """Shows a pending approval and its resolution. Cannot answer anything."""

    trust = "notify"
    proof_kinds: ClassVar[set[str]] = set()

    def __init__(
        self,
        config: NotifyConfig,
        *,
        name: str,
        link_origin: str | None = None,
        transport: Transport | None = None,
    ) -> None:
        self.name = name
        self._link = approval_link(link_origin)
        self._transport = transport or build_transport(config)
        self._warned = False

    async def start(self, sink: ApprovalSink) -> None:
        # The sink is deliberately dropped: this channel must not be able to answer.
        return None

    async def stop(self) -> None:
        await self._transport.close()

    async def send(self, req: ApprovalRequest) -> ChannelHandle:
        event = {"event": "approval_pending", "approval_id": req.approval_id}
        await self._transport.deliver(event, message_text(req, self._link))
        return ChannelHandle(channel=self.name, ref={"approval_id": req.approval_id})

    async def finalize(self, handle: ChannelHandle, outcome: ApprovalOutcome) -> None:
        # A webhook or command cannot edit what it sent, so post a follow-up line.
        text = f"{resolution_text(outcome)}\nRequest {handle.ref.get('approval_id', '')}"
        event = {
            "event": "approval_resolved",
            "approval_id": handle.ref.get("approval_id"),
            "approved": outcome.approved,
            "reason": str(outcome.reason),
        }
        try:
            await self._transport.deliver(event, text)
        except Exception as exc:
            self._log_failure("finalize", exc)

    def _log_failure(self, what: str, exc: Exception) -> None:
        # Once per channel, and never the target (a URL may carry a secret).
        if not self._warned:
            self._warned = True
            logger.warning("Notify channel %s: %s failed (%s); not retrying", self.name, what, exc)

    async def health_check(self) -> bool:
        return True


__all__ = ["CommandTransport", "NotifyChannel", "Transport", "WebhookTransport"]
