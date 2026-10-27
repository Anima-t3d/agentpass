"""Telegram Guardian bot as an approval channel (DESIGN 4.4), on python-telegram-bot v21.

Callback data is ``<approval_id>:<code>`` and carries no rule: for "always" answers
the code only picks a scope, and the gateway rebuilds the pattern, tool, agent and
expiry from the pending request (docs/REMEMBERED-DECISIONS.md section 3). There is
no persistence file; the open requests are remembered in memory only to draw the
scope step. A message is edited in ``finalize`` and in the scope step. The manual PTB
lifecycle (never ``run_polling``) is behind ``start`` / ``stop``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler

from agentpass.approval.channel import (
    Answer,
    AnswerStatus,
    ApprovalChannel,
    ApprovalOutcome,
    ApprovalReason,
    ApprovalRequest,
    ApprovalSink,
    ChannelHandle,
    Trust,
)
from agentpass.config import TelegramConfig

logger = logging.getLogger(__name__)

# y/n: once. a/d: open the allow/deny-always scope step. ae/at/de/dt: allow/deny always,
# exact call / whole tool. b: back from the scope step.
CALLBACK_PATTERN = r"^[0-9a-f-]{36}:(y|n|a|d|ae|at|de|dt|b)$"

_ANSWERS = {
    "y": (True, None),
    "n": (False, None),
    "ae": (True, "exact"),
    "at": (True, "tool"),
    "de": (False, "exact"),
    "dt": (False, "tool"),
}

_CLOSED_HEADERS = {
    ApprovalReason.TIMEOUT: ("⏰ Expired", "Approval timed out"),
    ApprovalReason.GATEWAY_SHUTDOWN: ("⏰ Expired", "Gateway shutting down"),
    ApprovalReason.RESTART: ("⏰ Expired", "Gateway restarted"),
    ApprovalReason.NO_CHANNEL: ("⏰ Expired", "No approval channel available"),
    ApprovalReason.REJECTED_PROOF: ("❌ Rejected", "Approval proof rejected"),
}


def message_text(req: ApprovalRequest) -> str:
    """Signature plus any extra args the signature does not already show."""
    lines = [f"\U0001f6a8 {req.tool}", f"Agent: {req.agent_name or req.agent_id}"]
    if req.risk:
        lines.append(f"Risk: {req.risk}")
    if req.signature:
        lines.append(req.signature)
    sig_text = req.signature or ""
    for key, value in req.args.items():
        if str(value) not in sig_text:
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def resolved_text(original: str, outcome: ApprovalOutcome) -> str:
    """The message after resolution: a new header, the detail lines kept for answers."""
    if outcome.reason in _CLOSED_HEADERS:
        header, detail = _CLOSED_HEADERS[outcome.reason]
        return f"{header}\n\n{detail}"
    header = "✅ Approved" if outcome.approved else "❌ Denied"
    if outcome.rule_id is not None:
        header += f" (always: {outcome.remembered}, rule #{outcome.rule_id})"
    return "\n".join([header, *original.strip().split("\n")[1:]])


def _expiry(days: int | None) -> str:
    if days is None:
        return "no expiry"
    return "expires " + (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%d")


def scope_text(req: ApprovalRequest, approved: bool) -> str:
    """The scope step: exactly what each button will store."""
    offer = req.remember
    assert offer is not None
    who = req.agent_name or req.agent_id
    lines = [f"{'Allow' if approved else 'Deny'} always for agent {who}?", ""]
    exact_days = offer.allow_exact_days if approved else None
    tool_days = offer.allow_tool_days if approved else None
    if offer.permits(approved, "exact"):
        lines.append(f"This exact call ({_expiry(exact_days)}):\n{req.signature}")
    if offer.permits(approved, "tool"):
        lines.append(f"\nThis tool, any arguments ({_expiry(tool_days)}):\n{req.tool}(*)")
        if approved:
            lines.append("⚠ Every future call of this tool by this agent runs without asking.")
    return "\n".join(lines)


class TelegramChannel(ApprovalChannel):
    """Guardian bot: one message per request with Allow / Deny (once or always) buttons."""

    proof_kinds: ClassVar[set[str]] = {"telegram_callback"}

    def __init__(
        self,
        config: TelegramConfig,
        *,
        name: str = "telegram",
        trust: Trust = "trusted",
        application: Application | None = None,
    ) -> None:
        self.name = name
        self.trust = trust
        self._config = config
        self._sink: ApprovalSink | None = None
        self._open: dict[str, ApprovalRequest] = {}  # to draw the scope step; not persisted
        self._app = application or Application.builder().token(config.token).build()
        self._app.add_handler(CallbackQueryHandler(self._on_callback, pattern=CALLBACK_PATTERN))
        self._app.add_handler(CallbackQueryHandler(self._on_stale))

    @property
    def application(self) -> Application:
        return self._app

    # --- ApprovalChannel ---

    async def start(self, sink: ApprovalSink) -> None:
        self._sink = sink
        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling()

    async def stop(self) -> None:
        await self._app.updater.stop()
        await self._app.stop()
        await self._app.shutdown()
        self._sink = None

    @staticmethod
    def _main_markup(req: ApprovalRequest) -> InlineKeyboardMarkup:
        aid = req.approval_id
        rows = [
            [
                InlineKeyboardButton("Allow once", callback_data=f"{aid}:y"),
                InlineKeyboardButton("Deny once", callback_data=f"{aid}:n"),
            ]
        ]
        offer = req.remember
        always = []
        if offer is not None and offer.any_allow:
            always.append(InlineKeyboardButton("Allow always...", callback_data=f"{aid}:a"))
        if offer is not None and offer.any_deny:
            always.append(InlineKeyboardButton("Deny always...", callback_data=f"{aid}:d"))
        if always:
            rows.append(always)
        return InlineKeyboardMarkup(rows)

    @staticmethod
    def _scope_markup(req: ApprovalRequest, approved: bool) -> InlineKeyboardMarkup:
        offer = req.remember
        assert offer is not None
        aid, verb = req.approval_id, "a" if approved else "d"
        row = []
        if offer.permits(approved, "exact"):
            row.append(InlineKeyboardButton("This exact call", callback_data=f"{aid}:{verb}e"))
        if offer.permits(approved, "tool"):
            row.append(InlineKeyboardButton("This tool, any args", callback_data=f"{aid}:{verb}t"))
        return InlineKeyboardMarkup([row, [InlineKeyboardButton("Back", callback_data=f"{aid}:b")]])

    async def send(self, req: ApprovalRequest) -> ChannelHandle:
        text = message_text(req)
        msg = await self._app.bot.send_message(
            chat_id=self._config.chat_id, text=text, reply_markup=self._main_markup(req)
        )
        self._open[req.approval_id] = req
        return ChannelHandle(self.name, {"message_id": msg.message_id, "text": text})

    async def finalize(self, handle: ChannelHandle, outcome: ApprovalOutcome) -> None:
        """Edit the message (dropping the buttons). Best effort: never raises."""
        self._open.pop(outcome.approval_id, None)
        try:
            await self._app.bot.edit_message_text(
                chat_id=self._config.chat_id,
                message_id=int(handle.ref["message_id"]),
                text=resolved_text(handle.ref.get("text", ""), outcome),
            )
        except Exception:
            logger.warning("Failed to edit Telegram message %s", handle.ref, exc_info=True)

    async def notify(self, text: str) -> None:
        await self._app.bot.send_message(chat_id=self._config.chat_id, text=text)

    async def health_check(self) -> bool:
        try:
            return bool(self._app.running)
        except Exception:
            return False

    # --- PTB handlers ---

    async def _on_callback(self, update: Update, context: Any) -> None:
        query = update.callback_query
        if query.from_user.id not in self._config.allowed_users:
            return  # silently ignore
        message = query.message
        if message is None or message.chat.id != self._config.chat_id:
            return  # only the configured approval chat
        if self._sink is None:
            await query.answer("Gateway not ready")
            return
        approval_id, _, code = str(query.data).partition(":")
        if code in ("a", "d", "b"):
            await self._scope_step(query, approval_id, code)
            return
        approved, remember = _ANSWERS[code]
        status = await self._sink.answer(
            approval_id,
            Answer(
                approved=approved,
                channel=self.name,
                approver_id=str(query.from_user.id),
                proof={"kind": "telegram_callback", "user_id": query.from_user.id},
                remember=remember,
            ),
        )
        if status is AnswerStatus.ACCEPTED:
            await query.answer()
        elif status is AnswerStatus.REJECTED and remember is not None:
            await query.answer("That choice is not available for this request")
        elif status is AnswerStatus.REJECTED:
            await query.answer("This request needs a stronger approval")
        else:
            await query.answer("Already resolved")

    async def _scope_step(self, query: Any, approval_id: str, code: str) -> None:
        """Show (or leave) the scope picker. Decides nothing: the sink is not involved."""
        req = self._open.get(approval_id)
        if req is None or req.remember is None:
            await query.answer("This button has expired")
            return
        if code == "b":
            text, markup = message_text(req), self._main_markup(req)
        else:
            approved = code == "a"
            if not (
                req.remember.permits(approved, "exact") or req.remember.permits(approved, "tool")
            ):
                await query.answer("That choice is not available for this request")
                return
            text, markup = scope_text(req, approved), self._scope_markup(req, approved)
        try:
            await query.edit_message_text(text, reply_markup=markup)
        except Exception:
            logger.warning("Failed to edit Telegram message for %s", approval_id, exc_info=True)
        await query.answer()

    async def _on_stale(self, update: Update, context: Any) -> None:
        await update.callback_query.answer("This button has expired")
