"""Shared data models for agentpass."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass
class ToolRequest:
    """Incoming tool request from an agent."""

    id: str
    tool_name: str
    args: dict[str, Any]
    signature: str = ""


@dataclass
class PendingApproval:
    """A tool request awaiting human approval."""

    request: ToolRequest
    future: asyncio.Future | None = None
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0
    agent_id: str = "default"


@dataclass
class AuditEntry:
    """A record of a tool request and its outcome."""

    request_id: str
    timestamp: float = field(default_factory=time.time)
    tool_name: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    decision: str = ""
    resolution: str | None = None
    resolved_by: str | None = None
    resolved_at: float | None = None
    execution_result: dict[str, Any] | None = None
    agent_id: str = "default"
    remembered_rule_id: int | None = None
