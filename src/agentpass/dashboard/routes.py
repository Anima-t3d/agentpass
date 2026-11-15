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

from agentpass.dashboard.query import entry_to_dict, parse_filters
from agentpass.dashboard.remembered_routes import setup_remembered
from agentpass.db import Database
from agentpass.remembered import RememberedService

logger = logging.getLogger("agentpass.dashboard")

_db_key = web.AppKey("db", Database)
_jinja2_key = web.AppKey("jinja2_env", jinja2.Environment)

_TEMPLATE_DIR = Path(__file__).parent / "templates"


async def handle_api_log(request: web.Request) -> web.Response:
    """GET /audit/api/log — JSON audit log with filtering and pagination."""
    db: Database = request.app[_db_key]
    filters = parse_filters(request.query)
    per_page = filters.pop("per_page")
    page = filters.pop("page")
    offset = (page - 1) * per_page

    entries, total = await db.get_audit_log_filtered(limit=per_page, offset=offset, **filters)
    pages = max(1, (total + per_page - 1) // per_page)

    return web.json_response(
        {
            "entries": [entry_to_dict(e) for e in entries],
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
    filters = parse_filters(request.query)
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
