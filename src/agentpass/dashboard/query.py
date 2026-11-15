"""Audit log query parsing shared by the admin dashboard and the PWA history view."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

MAX_PER_PAGE = 200
DEFAULT_PER_PAGE = 50


def parse_filters(params: Mapping[str, str]) -> dict[str, Any]:
    """Extract filter and paging params from a query string mapping."""
    filters: dict[str, Any] = {}

    if params.get("agent_id"):
        filters["agent_id"] = params["agent_id"]
    if params.get("tool_name"):
        filters["tool_name"] = params["tool_name"]
    if params.get("decision"):
        filters["decision"] = params["decision"]
    if params.get("resolution"):
        filters["resolution"] = params["resolution"]

    if params.get("from"):
        try:
            dt = datetime.fromisoformat(params["from"]).replace(tzinfo=UTC)
            filters["from_ts"] = dt.timestamp()
        except ValueError:
            pass
    if params.get("to"):
        try:
            dt = datetime.fromisoformat(params["to"]).replace(tzinfo=UTC)
            filters["to_ts"] = dt.timestamp()
        except ValueError:
            pass

    try:
        filters["per_page"] = max(
            1, min(MAX_PER_PAGE, int(params.get("per_page", DEFAULT_PER_PAGE)))
        )
    except ValueError:
        filters["per_page"] = DEFAULT_PER_PAGE

    try:
        filters["page"] = max(1, int(params.get("page", 1)))
    except ValueError:
        filters["page"] = 1

    return filters


def entry_to_dict(entry: Any) -> dict[str, Any]:
    """Convert an AuditEntry to a JSON-serializable dict."""
    return {
        "request_id": entry.request_id,
        "timestamp": entry.timestamp,
        "tool_name": entry.tool_name,
        "args": entry.args,
        "signature": entry.signature,
        "decision": entry.decision,
        "resolution": entry.resolution,
        "resolved_by": entry.resolved_by,
        "resolved_at": entry.resolved_at,
        "execution_result": entry.execution_result,
        "agent_id": entry.agent_id,
        "preview_digest": entry.preview_digest,
        "preview_title": entry.preview_title,
        "preview_status": entry.preview_status,
        "agent_note": entry.agent_note,  # unverified text from the agent
    }
