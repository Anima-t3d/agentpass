"""MCP frontend: streamable HTTP JSON-RPC on ``POST /mcp`` (DESIGN 7).

A second adapter on the transport-neutral ``Pipeline``. ``tools/call`` calls
``Pipeline.process`` and nothing else; this module owns no policy, rate-limit,
timeout or approval logic, only translation, the inline-wait / pending-result
bookkeeping a request/response transport needs, and agent-scoped read tools.
It runs on its own aiohttp app and must never be mounted on the dashboard app.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

from aiohttp import web

from agentpass.agents import AgentIdentity, AgentRegistry
from agentpass.db import Database
from agentpass.pipeline import Outcome, Pipeline, PipelineError
from agentpass.preview import sanitize_note
from agentpass.registry import ToolRegistry
from agentpass.schema import input_schema, tool_annotations, with_gateway_properties

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-03-26"
RESULT_TTL = 24 * 3600  # seconds a finished approval result stays fetchable
MAX_WAIT_SECONDS = 60  # cap for gateway_result long-polling
AUDIT_DEFAULT_LIMIT = 20
AUDIT_MAX_LIMIT = 100

# JSON-RPC protocol errors
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602

_HIGH_RISK = {"high", "critical"}
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}

_TIMEOUT_PAYLOAD = {"status": "timeout", "code": "approval_timeout", "data": "Approval timed out"}

GATEWAY_TOOLS: list[dict[str, Any]] = [
    {
        "name": "gateway_result",
        "description": (
            "Fetch the result of an earlier call that returned pending_approval. "
            "Waits up to wait_seconds for the human decision."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "wait_seconds": {"type": "integer", "minimum": 0, "maximum": MAX_WAIT_SECONDS},
            },
            "required": ["request_id"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "gateway_pending",
        "description": "List this agent's open approvals.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "gateway_audit",
        "description": "This agent's recent calls (own rows only).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": AUDIT_MAX_LIMIT},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
]
_GATEWAY_TOOL_NAMES = {t["name"] for t in GATEWAY_TOOLS}


class ToolError(Exception):
    """A tool-level failure reported as an isError result."""

    def __init__(self, code: str, message: str, request_id: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def error_payload(error: PipelineError) -> dict[str, Any]:
    """Stable string code for a pipeline error (class attribute, see pipeline.py)."""
    payload: dict[str, Any] = {"code": error.code, "message": error.message}
    if error.request_id:
        payload["request_id"] = error.request_id
    return payload


def _text_result(payload: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "structuredContent": payload,
    }
    if is_error:
        result["isError"] = True
    return result


class McpServer:
    """The MCP adapter. ``build_app()`` returns the aiohttp app serving ``POST /mcp``."""

    def __init__(
        self,
        *,
        pipeline: Pipeline,
        agents: AgentRegistry,
        registry: ToolRegistry,
        db: Database,
        inline_wait: float = 50,
    ) -> None:
        self._pipeline = pipeline
        self._agents = agents
        self._registry = registry
        self._db = db
        self._inline_wait = inline_wait
        self._tasks: set[asyncio.Task] = set()
        # Cache only, for long-polling a call that is live in this process. The
        # source of truth for gateway_result is pending_requests in the database.
        self._open: dict[tuple[str, str], asyncio.Task] = {}

    def build_app(self) -> web.Application:
        app = web.Application()
        app.router.add_post("/mcp", self._handle_post)
        app.on_shutdown.append(self._on_shutdown)
        return app

    async def _on_shutdown(self, _app: web.Application) -> None:
        # Let calls settle (the pipeline resolves pending approvals on shutdown) so
        # their results reach the database; cancel only what is still stuck.
        if self._tasks:
            await asyncio.wait(self._tasks, timeout=5)
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    # --- HTTP / JSON-RPC ---

    async def _handle_post(self, request: web.Request) -> web.Response:
        identity = self._authenticate(request)
        if identity is None:
            return web.json_response(
                {"error": "unauthorized"},
                status=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            msg = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._rpc_error(None, PARSE_ERROR, "Parse error")
        if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
            return self._rpc_error(None, INVALID_REQUEST, "Invalid request")
        msg_id = msg.get("id")
        method = msg["method"]
        params = msg.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return self._rpc_error(msg_id, INVALID_PARAMS, "Params must be an object")

        if "id" not in msg:  # notification
            return web.Response(status=202)
        if method == "initialize":
            result: dict[str, Any] = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "agentpass", "version": "0.1"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self._list_tools(identity)}
        elif method == "tools/call":
            name, arguments = params.get("name"), params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return self._rpc_error(msg_id, INVALID_PARAMS, "Invalid tools/call params")
            result = await self._call(identity, name, arguments)
        else:
            return self._rpc_error(msg_id, METHOD_NOT_FOUND, f"Unknown method: {method}")
        return web.json_response({"jsonrpc": "2.0", "id": msg_id, "result": result})

    def _authenticate(self, request: web.Request) -> AgentIdentity | None:
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        return self._agents.authenticate(token.strip())

    @staticmethod
    def _rpc_error(msg_id: Any, code: int, message: str) -> web.Response:
        body = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
        return web.json_response(body)

    # --- tools/list ---

    def _list_tools(self, identity: AgentIdentity) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        for tool in self._registry.all_tools():
            if identity.engine is not None and not identity.engine.may_permit(tool.name):
                continue
            entry: dict[str, Any] = {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": input_schema(tool.args),
            }
            annotations = tool_annotations(tool)
            if annotations:
                entry["annotations"] = annotations
            tools.append(entry)
        # Optional on every tool call; kept out of the arg schema the pipeline validates
        for entry in tools:
            with_gateway_properties(entry["inputSchema"], idempotency_key=True)
        return [*tools, *GATEWAY_TOOLS]

    # --- tools/call ---

    async def _call(self, identity: AgentIdentity, name: str, arguments: dict) -> dict[str, Any]:
        try:
            if name in _GATEWAY_TOOL_NAMES:
                return _text_result(await self._gateway_tool(identity, name, arguments))
            return _text_result(await self._tool_call(identity, name, arguments))
        except ToolError as e:
            payload = {"code": e.code, "message": e.message}
            if e.request_id:
                payload["request_id"] = e.request_id
            return _text_result({"error": payload}, is_error=True)
        except PipelineError as e:
            return _text_result({"error": error_payload(e)}, is_error=True)

    async def _tool_call(self, identity: AgentIdentity, name: str, arguments: dict) -> dict:
        args = dict(arguments)
        key = args.pop("idempotency_key", None)
        if key is not None and (not isinstance(key, str) or not key):
            raise ToolError("invalid_params", "idempotency_key must be a non-empty string")
        try:
            note = sanitize_note(args.pop("agent_note", None))
        except ValueError as e:
            raise ToolError("invalid_params", str(e)) from None

        pending = asyncio.Event()
        info: dict[str, Any] = {}

        def on_pending(request_id: str, expires_at: float) -> None:
            info["request_id"], info["expires_at"] = request_id, expires_at
            pending.set()

        task = asyncio.create_task(self._run_call(identity, name, args, key, on_pending, note))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        task.add_done_callback(self._reap)
        waiter = asyncio.create_task(pending.wait())
        try:
            await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            waiter.cancel()
        if not task.done():  # waiting for a human: bounded inline wait
            cache_key = (identity.id, info["request_id"])
            self._open[cache_key] = task
            task.add_done_callback(lambda _t, k=cache_key: self._open.pop(k, None))
            await asyncio.wait({task}, timeout=self._inline_wait)
            if not task.done():
                return {
                    "status": "pending_approval",
                    "request_id": info["request_id"],
                    "expires_at": _iso(info["expires_at"]),
                    "retry": "call gateway_result",
                }
        return self._render(self._outcome(task))

    async def _run_call(
        self,
        identity: AgentIdentity,
        name: str,
        args: dict,
        key: str | None,
        on_pending: Any,
        note: str | None = None,
    ) -> Outcome | PipelineError:
        """Pipeline.process, plus: keep the final result of an approval in the database.

        This runs in its own task, so the result is stored whether or not the HTTP
        request that started it is still waiting. A pipeline error is the task's
        *result*, never an exception: the request may have returned `pending_approval`
        and left, and nobody would retrieve it.
        """
        try:
            outcome = await self._pipeline.process(
                identity, name, args, key, on_pending=on_pending, agent_note=note
            )
        except PipelineError as e:
            if e.awaiting_delivery and e.request_id:
                await self._pipeline.store_undelivered(e.request_id, e)
            return e
        if outcome.awaiting_delivery:
            await self._pipeline.store_undelivered(outcome.request_id, outcome)
        return outcome

    @staticmethod
    def _reap(task: asyncio.Task) -> None:
        """Retrieve the outcome of a finished call so an unexpected failure is logged once."""
        if not task.cancelled() and task.exception() is not None:
            logger.error("MCP tool call failed", exc_info=task.exception())

    @staticmethod
    def _outcome(task: asyncio.Task) -> Outcome | PipelineError:
        return task.result()

    @staticmethod
    def _render(result: Outcome | PipelineError) -> dict[str, Any]:
        if isinstance(result, Outcome):
            return {"status": "executed", "request_id": result.request_id, "data": result.data}
        raise result

    # --- gateway_* tools ---

    async def _gateway_tool(
        self, identity: AgentIdentity, name: str, arguments: dict
    ) -> dict[str, Any]:
        if name == "gateway_pending":
            return {"pending": self._pipeline.pending_for(identity.id)}
        if name == "gateway_audit":
            limit = arguments.get("limit", AUDIT_DEFAULT_LIMIT)
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
                raise ToolError("invalid_params", "limit must be a positive integer")
            entries, _ = await self._db.get_audit_log_filtered(
                agent_id=identity.id, limit=min(limit, AUDIT_MAX_LIMIT)
            )
            return {
                "entries": [
                    {
                        "request_id": e.request_id,
                        "timestamp": _iso(e.timestamp),
                        "tool": e.tool_name,
                        "signature": e.signature,
                        "decision": e.decision,
                        "resolution": e.resolution,
                    }
                    for e in entries
                ]
            }
        return await self._gateway_result(identity, arguments)

    async def _gateway_result(self, identity: AgentIdentity, arguments: dict) -> dict[str, Any]:
        request_id = arguments.get("request_id")
        wait = arguments.get("wait_seconds", 0)
        if not isinstance(request_id, str) or not request_id:
            raise ToolError("invalid_params", "request_id is required")
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or wait < 0:
            raise ToolError("invalid_params", "wait_seconds must be a non-negative number")
        await self._db.purge_finished(RESULT_TTL)

        row = await self._lookup(identity.id, request_id)
        if row["result"] is None and wait > 0:
            task = self._open.get((identity.id, request_id))  # live here: wake on completion
            if task is not None and not task.done():
                await asyncio.wait({task}, timeout=min(wait, MAX_WAIT_SECONDS))
                row = await self._lookup(identity.id, request_id)
        if row["result"] is None:
            if row["expires_at"] <= _iso(time.time()):
                return self._stored(request_id, _TIMEOUT_PAYLOAD)
            return {
                "status": "pending_approval",
                "request_id": request_id,
                "expires_at": row["expires_at"],
                "retry": "call gateway_result",
            }
        return self._stored(request_id, json.loads(row["result"]))

    async def _lookup(self, agent_id: str, request_id: str) -> dict[str, Any]:
        """The caller's own pending_requests row; other agents' ids never resolve."""
        row = await self._db.get_pending(request_id)
        if row is None or row["agent_id"] != agent_id:
            raise ToolError("unknown_request", "No such request for this agent", request_id)
        return row

    @staticmethod
    def _stored(request_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if payload["status"] == "executed":
            return {"status": "executed", "request_id": request_id, "data": payload["data"]}
        code = payload.get("code") or (
            "approval_timeout" if payload["status"] == "timeout" else "execution_failed"
        )
        return {
            "status": payload["status"],
            "request_id": request_id,
            "error": {"code": code, "message": payload["data"], "request_id": request_id},
        }
