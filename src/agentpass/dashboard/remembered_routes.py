"""Remembered-decisions routes: list and revoke only. There is deliberately no create route."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import jinja2
from aiohttp import web

from agentpass.remembered import RememberedService

_service_key = web.AppKey("remembered", RememberedService)
_env_key = web.AppKey("remembered_env", jinja2.Environment)

CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "agentpass"


def _public(rule: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in rule.items() if k != "tool_fingerprint"}


async def handle_api_rules(request: web.Request) -> web.Response:
    """GET /remembered/api/rules?agent=&all=1 — rules with their computed state."""
    service: RememberedService = request.app[_service_key]
    rules = await service.list_rules(
        agent_id=request.query.get("agent") or None,
        include_history=request.query.get("all") == "1",
    )
    return web.json_response({"rules": [_public(r) for r in rules]})


def _csrf_ok(request: web.Request) -> bool:
    """A custom header (not sendable cross-origin without a preflight) and a same-origin Origin."""
    if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        return False
    origin = request.headers.get("Origin")
    return origin is None or urlsplit(origin).netloc == request.host


async def handle_api_revoke(request: web.Request) -> web.Response:
    """POST /remembered/api/rules/{id}/revoke"""
    if not _csrf_ok(request):
        return web.json_response({"error": "forbidden"}, status=403)
    try:
        rule_id = int(request.match_info["rule_id"])
    except ValueError:
        return web.json_response({"error": "invalid rule id"}, status=400)
    service: RememberedService = request.app[_service_key]
    by = "cli" if request.query.get("by") == "cli" else "dashboard"
    if not await service.revoke(rule_id, by):
        return web.json_response({"error": "no such active rule"}, status=404)
    return web.json_response({"revoked": rule_id})


async def handle_page(request: web.Request) -> web.Response:
    """GET /remembered/ — HTML list with a Revoke button per rule."""
    service: RememberedService = request.app[_service_key]
    show_all = request.query.get("all") == "1"
    rules = await service.list_rules(include_history=show_all)
    html = (
        request.app[_env_key]
        .get_template("remembered.html")
        .render(rules=rules, show_all=show_all, csrf_header=CSRF_HEADER, csrf_value=CSRF_VALUE)
    )
    return web.Response(text=html, content_type="text/html")


def setup_remembered(
    app: web.Application, service: RememberedService, env: jinja2.Environment
) -> None:
    app[_service_key] = service
    app[_env_key] = env
    app.router.add_get("/remembered/", handle_page)
    app.router.add_get("/remembered/api/rules", handle_api_rules)
    app.router.add_post("/remembered/api/rules/{rule_id}/revoke", handle_api_revoke)
