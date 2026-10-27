"""Audit dashboard HTTP routes — JSON API and HTML handler."""

from __future__ import annotations

import hmac
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import jinja2
from aiohttp import web

from agentpass.dashboard.remembered_routes import setup_remembered
from agentpass.db import Database
from agentpass.remembered import RememberedService

logger = logging.getLogger("agentpass.dashboard")

_db_key = web.AppKey("db", Database)
_jinja2_key = web.AppKey("jinja2_env", jinja2.Environment)

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _parse_filters(request: web.Request) -> dict[str, Any]:
    """Extract filter params from query string."""
    params = request.query
    filters: dict[str, Any] = {}

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
        filters["per_page"] = max(1, min(200, int(params.get("per_page", 50))))
    except ValueError:
        filters["per_page"] = 50

    try:
        filters["page"] = max(1, int(params.get("page", 1)))
    except ValueError:
        filters["page"] = 1

    return filters


def _entry_to_dict(entry: Any) -> dict[str, Any]:
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
    }


async def handle_api_log(request: web.Request) -> web.Response:
    """GET /audit/api/log — JSON audit log with filtering and pagination."""
    db: Database = request.app[_db_key]
    filters = _parse_filters(request)
    per_page = filters.pop("per_page")
    page = filters.pop("page")
    offset = (page - 1) * per_page

    entries, total = await db.get_audit_log_filtered(limit=per_page, offset=offset, **filters)
    pages = max(1, (total + per_page - 1) // per_page)

    return web.json_response(
        {
            "entries": [_entry_to_dict(e) for e in entries],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }
    )


async def handle_api_stats(request: web.Request) -> web.Response:
    """GET /audit/api/stats — summary statistics."""
    db: Database = request.app[_db_key]
    stats = await db.get_audit_stats()
    return web.json_response(stats)


async def handle_audit_page(request: web.Request) -> web.Response:
    """GET /audit/ — HTML dashboard page."""
    db: Database = request.app[_db_key]
    env: jinja2.Environment = request.app[_jinja2_key]
    filters = _parse_filters(request)
    per_page = filters.pop("per_page")
    page = filters.pop("page")
    offset = (page - 1) * per_page

    entries, total = await db.get_audit_log_filtered(limit=per_page, offset=offset, **filters)
    pages = max(1, (total + per_page - 1) // per_page)
    stats = await db.get_audit_stats()

    tool_names = await db.get_distinct_tool_names()

    # Build query string helper for pagination links
    raw_params = dict(request.query)

    def query_string(**overrides: Any) -> str:
        params = {k: v for k, v in {**raw_params, **overrides}.items() if v}
        return urlencode(params)

    template = env.get_template("audit.html")
    html = template.render(
        entries=entries,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
        stats=stats,
        tool_names=tool_names,
        filters=filters,
        query_string=query_string,
    )
    return web.Response(text=html, content_type="text/html")


def _format_ts(epoch: float) -> str:
    """Format an epoch timestamp as a human-readable string."""
    try:
        return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return str(epoch)


def admin_token_middleware(admin_token: str):
    """Require ``Authorization: Bearer <admin token>`` (constant-time compare) on every route.

    Only the admin token passes: an agent token, even a valid one, gets 401.
    """
    expected = admin_token.encode()

    @web.middleware
    async def _auth(request: web.Request, handler):
        header = request.headers.get("Authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            presented.strip().encode(), expected
        ):
            return web.json_response(
                {"error": "unauthorized"}, status=401, headers={"WWW-Authenticate": "Bearer"}
            )
        return await handler(request)

    return _auth


def build_dashboard_app(
    db: Database, admin_token: str | None = None, remembered: RememberedService | None = None
) -> web.Application:
    """An app that serves only the audit dashboard; with a token, every route requires it."""
    if admin_token is not None and not admin_token:
        raise ValueError("admin_token must not be empty")
    middlewares = [admin_token_middleware(admin_token)] if admin_token else []
    app = web.Application(middlewares=middlewares)
    setup_dashboard(app, db, remembered)
    return app


def setup_dashboard(
    app: web.Application, db: Database, remembered: RememberedService | None = None
) -> None:
    """Register dashboard routes on an aiohttp Application."""
    app[_db_key] = db

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    env.filters["format_ts"] = _format_ts
    app[_jinja2_key] = env

    app.router.add_get("/audit/", handle_audit_page)
    app.router.add_get("/audit/api/log", handle_api_log)
    app.router.add_get("/audit/api/stats", handle_api_stats)
    if remembered is not None:
        setup_remembered(app, remembered, env)
