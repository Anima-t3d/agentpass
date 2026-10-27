"""Passkey approval channel.

Implements the DESIGN 4.1 `ApprovalChannel` interface from ``agentpass.approval``.
The only way to resolve an approval through this channel is a verified passkey
assertion (Approve) or the Deny button.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar
from urllib.parse import quote

from aiohttp import web

from agentpass.approval.channel import ApprovalChannel, ChannelHandle
from agentpass.passkey.page import ApprovalPage, PasskeyConfig, PendingApproval
from agentpass.passkey.store import EnrolmentTokens, PasskeyStore
from agentpass.passkey.verify import parse_expiry

logger = logging.getLogger("agentpass.passkey")


class PasskeyChannel(ApprovalChannel):
    name = "passkey"
    trust = "trusted"
    proof_kinds: ClassVar[set[str]] = {"webauthn"}

    def __init__(self, config: PasskeyConfig, db: Any = None) -> None:
        self.config = config
        self.store = PasskeyStore(config.store_path)
        self.page = ApprovalPage(config, self.store, EnrolmentTokens(config.enroll_path), db=db)
        self._runner: web.AppRunner | None = None

    async def start(self, sink: Any) -> None:
        self.page.answer = sink.answer
        self._runner = web.AppRunner(self.page.build_app())
        await self._runner.setup()
        await web.TCPSite(self._runner, self.config.host, self.config.port).start()
        logger.info("Passkey approval page on http://%s:%d", self.config.host, self.config.port)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        self.page.pending.clear()

    async def send(self, req: Any) -> ChannelHandle:
        """Register the request for display. `req` carries the DESIGN 4.1 fields."""
        self.page.pending[req.approval_id] = PendingApproval(
            approval_id=req.approval_id,
            agent_id=req.agent_id,
            tool=req.tool,
            args=dict(req.args),
            risk=str(getattr(req, "risk", "") or "unknown"),
            expires_at=parse_expiry(req.expires_at),
            signature=getattr(req, "signature", "") or "",
            require=str(getattr(req, "require", "any_trusted")),
        )
        return ChannelHandle(channel=self.name, ref={"approval_id": req.approval_id})

    async def finalize(self, handle: ChannelHandle | str, outcome: Any = None) -> None:
        approval_id = handle.ref.get("approval_id") if isinstance(handle, ChannelHandle) else handle
        if approval_id:
            self.page.pending.pop(approval_id, None)


def issue_enrolment_url(config: PasskeyConfig) -> str:
    """Create a one-time enrolment token (10 minutes) and return the page URL."""
    token = EnrolmentTokens(config.enroll_path).issue()
    return f"{config.origin}/enroll?token={quote(token)}"
