"""Remembered decisions: "Allow always" / "Deny always" (docs/REMEMBERED-DECISIONS.md).

The pure rules (eligibility, matching keys, fingerprints, rule state) are plain
functions so ``check-config`` can use them offline; ``RememberedService`` adds the
database. Matching is string equality, never glob: nothing an agent sends is ever
interpreted as a pattern.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from agentpass.approval.channel import RememberOffer
from agentpass.config import ApprovalSpec, ToolDefinition
from agentpass.db import Database
from agentpass.models import AuditEntry, Decision

if TYPE_CHECKING:
    from agentpass.approval.channel import ApprovalRequest
    from agentpass.registry import ToolRegistry

logger = logging.getLogger(__name__)

ALLOW_EXACT_DAYS = 90
ALLOW_TOOL_DAYS = 30
MAX_SIGNATURE_LEN = 1500  # longer signatures cannot be shown in full in the scope step

_RISK_RANK = {"low": 0, "medium": 1, "high": 2}

CREATE_TOOL = "_remembered.create"
REVOKE_TOOL = "_remembered.revoke"


def iso(epoch: float | None = None) -> str:
    stamp = time.time() if epoch is None else epoch
    return datetime.fromtimestamp(stamp, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def args_hash(args: dict[str, Any]) -> str:
    """sha256 of the canonical JSON of the agent-supplied args (before defaults)."""
    return hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()


def tool_fingerprint(tool: ToolDefinition) -> str:
    """Hash of everything about a tool that changes what a call does (not its description)."""
    data = dataclasses.asdict(tool)
    data.pop("description", None)
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def effective_risk(tool: ToolDefinition | None, approval: ApprovalSpec | None) -> str | None:
    """The higher of the tool's risk and the matched rule's ``approval.risk``.

    None when neither is set. An unrecognised value counts as ``high``.
    """
    values = [v for v in (tool.risk if tool else None, approval.risk if approval else None) if v]
    if not values:
        return None
    return max((v if v in _RISK_RANK else "high" for v in values), key=_RISK_RANK.__getitem__)


def allow_blocker(
    tool: ToolDefinition | None, approval: ApprovalSpec | None, scope: str
) -> str | None:
    """Why a remembered *allow* of *scope* must not apply to this tool, or None if it may."""
    if tool is None:
        return "tool removed"
    if approval is not None and approval.require == "passkey":
        return "rule requires a passkey"
    risk = effective_risk(tool, approval)
    if risk == "high":
        return "high risk"
    if risk is None and scope == "tool":
        return "no risk level set"
    return None


def pattern_for(scope: str, tool_name: str, signature: str) -> str:
    """Display label of a rule. Never matched against."""
    return signature if scope == "exact" else f"{tool_name}(*)"


def build_offer(
    tool: ToolDefinition | None,
    approval: ApprovalSpec | None,
    signature: str,
    args: dict[str, Any],
) -> RememberOffer | None:
    """The "always" answers to show for one request; None when none is possible."""
    if tool is None:
        return None
    shown = len(signature) <= MAX_SIGNATURE_LEN
    return RememberOffer(
        allow_exact=shown and allow_blocker(tool, approval, "exact") is None,
        allow_tool=shown and allow_blocker(tool, approval, "tool") is None,
        deny_exact=shown,
        deny_tool=shown,
        args_hash=args_hash(args) if tool.remember == "args" else None,
        tool_fingerprint=tool_fingerprint(tool),
        allow_exact_days=ALLOW_EXACT_DAYS,
        allow_tool_days=ALLOW_TOOL_DAYS,
    )


def _matches(rule: dict[str, Any], signature: str, hash_: str) -> bool:
    if rule["scope"] == "tool":
        return True
    if rule["signature"] != signature:
        return False
    return rule["args_hash"] is None or rule["args_hash"] == hash_


def rule_state(
    rule: dict[str, Any],
    registry: ToolRegistry | None,
    *,
    now_iso: str,
    agent_known: Callable[[str], bool] = lambda _agent: True,
    approval_for: Callable[[str, str, str], ApprovalSpec | None] | None = None,
) -> tuple[str, str]:
    """(state, reason) of a stored rule: active | expired | revoked | inactive.

    *approval_for(agent, tool, signature)* gives the approval block of the rule that
    currently produces ``ask`` for an exact call, so a rule that now needs a passkey is
    reported. Tool-scope rules are judged on the tool alone.
    """
    if rule["revoked_at"]:
        return "revoked", ""
    if rule["expires_at"] and rule["expires_at"] <= now_iso:
        return "expired", ""
    if not agent_known(rule["agent_id"]):
        return "inactive", "agent removed"
    tool = registry.get_tool(rule["tool_name"]) if registry else None
    if tool is None:
        return "inactive", "tool removed"
    if rule["action"] == "deny":
        return "active", ""  # deny stays in force whatever changed
    if rule["tool_fingerprint"] != tool_fingerprint(tool):
        return "inactive", "tool changed"
    approval = None
    if approval_for is not None and rule["scope"] == "exact":
        approval = approval_for(rule["agent_id"], rule["tool_name"], rule["signature"] or "")
    blocker = allow_blocker(tool, approval, rule["scope"])
    if blocker:
        return "inactive", f"policy: {blocker}"
    return "active", ""


def summarize(states: Iterable[tuple[str, str]], rules: list[dict[str, Any]]) -> dict[str, int]:
    """Counts for check-config and the startup log (revoked rules are history, not counted)."""
    out = {"active": 0, "allow": 0, "deny": 0, "expired": 0, "inactive": 0}
    for (state, _reason), rule in zip(states, rules, strict=True):
        if state in out:
            out[state] += 1
        if state == "active":
            out[rule["action"]] += 1
    return out


def format_summary(counts: dict[str, int]) -> str:
    return (
        f"{counts['active']} active ({counts['allow']} allow, {counts['deny']} deny), "
        f"{counts['expired']} expired, {counts['inactive']} inactive"
    )


@dataclass
class RememberedVerdict:
    decision: Decision
    rule: dict[str, Any]


class RememberedService:
    """Database-backed remembered rules for the pipeline, coordinator and dashboard."""

    def __init__(
        self,
        db: Database,
        registry: ToolRegistry | None,
        *,
        agent_known: Callable[[str], bool] = lambda _agent: True,
        approval_for: Callable[[str, str, str], ApprovalSpec | None] | None = None,
    ) -> None:
        self._db = db
        self._registry = registry
        self._agent_known = agent_known
        self._approval_for = approval_for

    # --- Pipeline ---

    def offer(
        self,
        tool_name: str,
        signature: str,
        args: dict[str, Any],
        approval: ApprovalSpec | None,
    ) -> RememberOffer | None:
        tool = self._registry.get_tool(tool_name) if self._registry else None
        return build_offer(tool, approval, signature, args)

    async def resolve(
        self,
        agent_id: str,
        tool_name: str,
        signature: str,
        args: dict[str, Any],
        static: Decision,
        approval: ApprovalSpec | None,
    ) -> RememberedVerdict | None:
        """The remembered rule that settles this call, or None (docs section 2, steps 2-4).

        Step 1 (a static deny) is the caller's: it must not call this for a denied call.
        A deny rule wins over a static allow. An allow rule applies only when the static
        verdict is ``ask`` and the rule is still eligible under current policy and tool.
        """
        rules = await self._db.candidate_remembered_rules(agent_id, tool_name, iso())
        if not rules:
            return None
        hash_ = args_hash(args)
        hits = [r for r in rules if _matches(r, signature, hash_)]
        denies = [r for r in hits if r["action"] == "deny"]
        if denies:
            return RememberedVerdict(Decision.DENY, denies[0])
        if static is not Decision.ASK:
            return None
        tool = self._registry.get_tool(tool_name) if self._registry else None
        if tool is None:
            return None
        fingerprint = tool_fingerprint(tool)
        # an exact rule is reported in preference to a tool-wide one
        for rule in sorted(hits, key=lambda r: r["scope"] != "exact"):
            if rule["tool_fingerprint"] != fingerprint:
                continue
            if allow_blocker(tool, approval, rule["scope"]) is None:
                return RememberedVerdict(Decision.ALLOW, rule)
        return None

    async def touch(self, rule_id: int) -> None:
        await self._db.touch_remembered_rule(rule_id, iso())

    # --- Coordinator ---

    async def create(
        self, req: ApprovalRequest, scope: str, approved: bool, approver_id: str
    ) -> int | None:
        """Store the rule for a request a trusted human just answered; audited.

        The caller has validated *scope* against ``req.remember``. Returns the rule id.
        """
        offer = req.remember
        if offer is None or not offer.permits(approved, scope):
            return None
        now = time.time()
        expires_at = None
        if approved:
            days = offer.allow_exact_days if scope == "exact" else offer.allow_tool_days
            expires_at = iso(
                (datetime.fromtimestamp(now, tz=UTC) + timedelta(days=days)).timestamp()
            )
        action = "allow" if approved else "deny"
        pattern = pattern_for(scope, req.tool, req.signature)
        rule_id, _created = await self._db.upsert_remembered_rule(
            {
                "agent_id": req.agent_id,
                "scope": scope,
                "tool_name": req.tool,
                "signature": req.signature if scope == "exact" else None,
                "args_hash": offer.args_hash if scope == "exact" else None,
                "pattern": pattern,
                "action": action,
                "created_by": approver_id,
                "created_at": iso(now),
                "expires_at": expires_at,
                "source_request_id": req.approval_id,
                "tool_fingerprint": offer.tool_fingerprint,
            }
        )
        await self._db.log_audit(
            AuditEntry(
                # own id: update_audit_resolution keys on request_id and must not touch this row
                request_id=str(uuid.uuid4()),
                args={"source_request_id": req.approval_id},
                tool_name=CREATE_TOOL,
                signature=pattern,
                decision=action,
                resolution="rule_created",
                resolved_by=approver_id,
                resolved_at=now,
                agent_id=req.agent_id,
                remembered_rule_id=rule_id,
            )
        )
        logger.info(
            "Remembered rule #%d created: %s %s for %s", rule_id, action, pattern, req.agent_id
        )
        return rule_id

    # --- Dashboard, CLI ---

    async def revoke(self, rule_id: int, revoked_by: str) -> bool:
        """Revoke a rule (audited). False when it does not exist or is already revoked."""
        rule = await self._db.get_remembered_rule(rule_id)
        if rule is None or not await self._db.revoke_remembered_rule(rule_id, revoked_by, iso()):
            return False
        await self._db.log_audit(
            AuditEntry(
                request_id=str(uuid.uuid4()),
                tool_name=REVOKE_TOOL,
                signature=rule["pattern"],
                decision=rule["action"],
                resolution="rule_revoked",
                resolved_by=revoked_by,
                resolved_at=time.time(),
                agent_id=rule["agent_id"],
                remembered_rule_id=rule_id,
            )
        )
        logger.info("Remembered rule #%d revoked by %s", rule_id, revoked_by)
        return True

    def state(self, rule: dict[str, Any]) -> tuple[str, str]:
        return rule_state(
            rule,
            self._registry,
            now_iso=iso(),
            agent_known=self._agent_known,
            approval_for=self._approval_for,
        )

    async def list_rules(
        self, agent_id: str | None = None, include_history: bool = True
    ) -> list[dict[str, Any]]:
        """Rules with a computed ``state`` and ``state_reason``; newest first.

        Without *include_history* the expired and revoked ones are left out.
        """
        rules = await self._db.list_remembered_rules(agent_id)
        out = []
        for rule in rules:
            state, reason = self.state(rule)
            if not include_history and state in ("expired", "revoked"):
                continue
            out.append({**rule, "state": state, "state_reason": reason})
        return out

    async def counts(self) -> dict[str, int]:
        rules = await self._db.list_remembered_rules()
        return summarize([self.state(r) for r in rules], rules)
