"""WebSocket server — JSON-RPC 2.0 gateway for agent communication."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from websockets.exceptions import ConnectionClosed

if TYPE_CHECKING:
    from agentpass.registry import ToolRegistry

from agentpass.agents import AgentIdentity, AgentRegistry
from agentpass.approval import ApprovalCoordinator, ApprovalReason
from agentpass.db import Database
from agentpass.engine import PermissionEngine
from agentpass.executor import Executor
from agentpass.models import PendingApproval
from agentpass.pipeline import (
    ApprovalDenied,
    ApprovalTimeout,
    ApprovalUnavailable,
    ExecutionFailed,
    InvalidParams,
    Outcome,
    Pipeline,
    PipelineError,
    PolicyDenied,
    RateLimited,
    RateLimiter,
    ServiceUnauthorized,
    UnknownTool,
)
from agentpass.schema import args_to_json_schema, tool_annotations

__all__ = ["GatewayServer", "RateLimiter"]

logger = logging.getLogger(__name__)

# JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
APPROVAL_DENIED = -32001
APPROVAL_TIMEOUT = -32002
POLICY_DENIED = -32003
EXECUTION_FAILED = -32004
NOT_AUTHENTICATED = -32005
RATE_LIMIT_EXCEEDED = -32006
UNKNOWN_TOOL = -32007
APPROVAL_UNAVAILABLE = -32008
SERVICE_UNAUTHORIZED = -32009
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

LEGACY_AGENT_ID = "default"  # identity of the single configured agent.token
AUTH_TIMEOUT = 10  # seconds

# The one place pipeline errors become JSON-RPC codes.
ERROR_CODES: dict[type[PipelineError], int] = {
    UnknownTool: UNKNOWN_TOOL,
    InvalidParams: INVALID_PARAMS,
    PolicyDenied: POLICY_DENIED,
    ApprovalDenied: APPROVAL_DENIED,
    ApprovalTimeout: APPROVAL_TIMEOUT,
    ApprovalUnavailable: APPROVAL_UNAVAILABLE,
    RateLimited: RATE_LIMIT_EXCEEDED,
    ExecutionFailed: EXECUTION_FAILED,
    ServiceUnauthorized: SERVICE_UNAUTHORIZED,
}


@dataclass
class ConnectionContext:
    """Per-connection state: who is connected and over which socket."""

    identity: AgentIdentity
    websocket: Any


class GatewayServer:
    """WebSocket gateway server managing agent connections and tool request dispatch."""

    def __init__(
        self,
        *,
        agent_token: str | None = None,
        agents: AgentRegistry | None = None,
        engine: PermissionEngine,
        executor: Executor,
        coordinator: ApprovalCoordinator,
        db: Database,
        approval_timeout: int = 900,
        rate_limit_config: Any = None,
        registry: ToolRegistry | None = None,
        services: dict[str, Any] | None = None,
        remembered: Any = None,
    ) -> None:
        if agent_token is None and agents is None:
            raise ValueError("Either agent_token or agents is required")
        if agent_token is not None and agents is not None:
            raise ValueError("agent_token and agents are mutually exclusive")
        self._agents = agents
        # One shared token = one identity, one session at a time (unchanged behaviour)
        self._legacy_token = agent_token
        self._legacy_identity = AgentIdentity(id=LEGACY_AGENT_ID, max_sessions=1)
        self._sessions: dict[str, int] = {}
        self._coordinator = coordinator
        self._db = db
        self._registry = registry
        self._services = services or {}
        self._pipeline = Pipeline(
            engine=engine,
            executor=executor,
            coordinator=coordinator,
            db=db,
            approval_timeout=approval_timeout,
            max_requests_per_minute=(
                rate_limit_config.max_requests_per_minute if rate_limit_config else 60
            ),
            max_pending=rate_limit_config.max_pending_approvals if rate_limit_config else 10,
            registry=registry,
            remembered=remembered,
        )

    @property
    def pipeline(self) -> Pipeline:
        return self._pipeline

    @property
    def _engine(self) -> PermissionEngine:
        return self._pipeline._engine

    @_engine.setter
    def _engine(self, engine: PermissionEngine) -> None:
        self._pipeline._engine = engine

    @property
    def _pending(self) -> dict[str, PendingApproval]:
        return self._pipeline._pending

    async def health_status(self) -> dict[str, Any]:
        """Return health status of all components."""
        db_ok = await self._db.health_check()
        channels = await self._coordinator.health_check()
        telegram_ok = all(channels.values())
        services_status = {}
        for name, svc in self._services.items():
            services_status[name] = await svc.health_check()

        all_critical_ok = db_ok and telegram_ok
        return {
            "status": "healthy" if all_critical_ok else "unhealthy",
            "checks": {
                "database": db_ok,
                "telegram": telegram_ok,
                "channels": channels,
                "services": services_status,
            },
        }

    async def handle_connection(self, websocket: Any) -> None:
        """Handle a single agent WebSocket connection."""
        ctx: ConnectionContext | None = None
        try:
            # Phase 1: Authentication with deadline (no session counted, so an
            # unauthenticated connection cannot lock out a real agent)
            identity = await self._authenticate(websocket)
            if identity is None:
                return

            # Count the session only after auth (no await between check and set)
            held = self._sessions.get(identity.id, 0)
            if identity.max_sessions is not None and held >= identity.max_sessions:
                await websocket.close(4000, "Another agent is already connected")
                return
            self._sessions[identity.id] = held + 1
            ctx = ConnectionContext(identity=identity, websocket=websocket)
            logger.info("Agent %s connected", identity.id)

            # Phase 2: Message loop — each message gets its own task
            tasks: set[asyncio.Task] = set()
            async for raw_message in websocket:
                task = asyncio.create_task(self._handle_message(ctx, raw_message))
                tasks.add(task)
                task.add_done_callback(tasks.discard)

            # Wait for in-flight message tasks to finish
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        except ConnectionClosed:
            logger.info("Agent disconnected")
        finally:
            if ctx is not None:
                remaining = self._sessions.get(ctx.identity.id, 1) - 1
                if remaining > 0:
                    self._sessions[ctx.identity.id] = remaining
                else:
                    self._sessions.pop(ctx.identity.id, None)
                logger.info("Agent %s session ended", ctx.identity.id)

    def _resolve_identity(self, token: Any) -> AgentIdentity | None:
        if self._agents is not None:
            return self._agents.authenticate(token)
        if (
            self._legacy_token is not None
            and isinstance(token, str)
            and hmac.compare_digest(token.encode(), self._legacy_token.encode())
        ):
            return self._legacy_identity
        return None

    async def _authenticate(self, websocket: Any) -> AgentIdentity | None:
        """Handle auth flow. Returns the agent identity, or None on failure."""
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=AUTH_TIMEOUT)
        except TimeoutError:
            await self._send_error(websocket, NOT_AUTHENTICATED, "Authentication timeout", None)
            await websocket.close()
            return None

        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            await self._send_error(websocket, PARSE_ERROR, "Parse error", None)
            await websocket.close()
            return None

        if not isinstance(msg, dict) or msg.get("method") != "auth":
            await self._send_error(
                websocket,
                NOT_AUTHENTICATED,
                "Not authenticated",
                msg.get("id") if isinstance(msg, dict) else None,
            )
            await websocket.close()
            return None

        params = msg.get("params")
        token = params.get("token", "") if isinstance(params, dict) else ""
        identity = self._resolve_identity(token)
        if identity is None:
            await self._send_error(websocket, NOT_AUTHENTICATED, "Invalid token", msg.get("id"))
            await websocket.close()
            return None

        # Auth success
        await self._send_result(websocket, {"status": "authenticated"}, msg.get("id"))
        logger.info("Agent %s authenticated", identity.id)
        return identity

    async def _handle_message(self, ctx: ConnectionContext, raw_message: str) -> None:
        """Process a single JSON-RPC message."""
        websocket = ctx.websocket
        # Parse
        try:
            msg = json.loads(raw_message)
        except json.JSONDecodeError:
            await self._send_error(websocket, PARSE_ERROR, "Parse error", None)
            return

        if not isinstance(msg, dict):
            await self._send_error(websocket, INVALID_REQUEST, "Invalid request", None)
            return

        msg_id = msg.get("id")
        method = msg.get("method")

        if not method:
            await self._send_error(websocket, INVALID_REQUEST, "Missing method", msg_id)
            return

        try:
            if method == "tool_request":
                await self._handle_tool_request(ctx, msg, msg_id)
            elif method == "get_pending_results":
                await self._handle_get_pending_results(ctx, msg_id)
            elif method == "list_tools":
                await self._handle_list_tools(websocket, msg_id)
            else:
                await self._send_error(
                    websocket, METHOD_NOT_FOUND, f"Unknown method: {method}", msg_id
                )
        except ConnectionClosed:
            raise
        except Exception:
            # Never leave a request unanswered
            logger.exception("Unhandled error processing %s", method)
            await self._send_error(websocket, INTERNAL_ERROR, "Internal error", msg_id)

    async def _handle_tool_request(self, ctx: ConnectionContext, msg: dict, msg_id: Any) -> None:
        """Process a tool_request."""
        websocket = ctx.websocket
        # Validate msg_id is present (Major 1: prevents None collisions)
        if msg_id is None:
            await self._send_error(websocket, INVALID_REQUEST, "Missing request id", None)
            return

        params = msg.get("params", {})
        if not isinstance(params, dict):
            await self._send_error(websocket, INVALID_PARAMS, "Params must be an object", msg_id)
            return
        tool_name = params.get("tool")
        args = params.get("args", {})

        if not tool_name or not isinstance(tool_name, str):
            await self._send_error(websocket, INVALID_REQUEST, "Missing tool name", msg_id)
            return

        result: Outcome | PipelineError
        try:
            result = await self._pipeline.process(ctx.identity, tool_name, args)
        except PipelineError as e:
            result = e

        try:
            if isinstance(result, Outcome):
                await self._send_result(
                    websocket, {"status": "executed", "data": result.data}, msg_id
                )
            else:
                code = next(ERROR_CODES[c] for c in type(result).__mro__ if c in ERROR_CODES)
                await self._send_error(websocket, code, result.message, msg_id)
        except ConnectionClosed:
            # Agent gone: keep the result for get_pending_results
            if result.awaiting_delivery:
                await self._pipeline.store_undelivered(result.request_id, result)
            raise
        if result.awaiting_delivery:
            await self._pipeline.complete(result.request_id)

    async def resolve_all_pending(
        self, reason: ApprovalReason = ApprovalReason.GATEWAY_SHUTDOWN
    ) -> None:
        """Resolve all pending approvals (called during shutdown)."""
        await self._pipeline.resolve_all_pending(reason)

    async def _handle_get_pending_results(self, ctx: ConnectionContext, msg_id: Any) -> None:
        """Return this agent's stored results from approvals resolved while it was away."""
        agent_id = ctx.identity.id
        results = await self._db.get_completed_results(agent_id)
        await self._send_result(ctx.websocket, {"results": results}, msg_id)

        # Clean up retrieved results from DB
        if results:
            request_ids = [r["request_id"] for r in results]
            await self._db.delete_completed_results(request_ids, agent_id)

    async def _handle_list_tools(self, websocket: Any, msg_id: Any) -> None:
        """Return available tool definitions."""
        if self._registry is None:
            await self._send_result(websocket, {"tools": []}, msg_id)
            return

        tools = []
        for tool_def in self._registry.all_tools():
            args_schema: dict[str, dict[str, Any]] = {}
            for arg_name, arg_def in tool_def.args.items():
                arg_info: dict[str, Any] = {"required": arg_def.required}
                if arg_def.validate:
                    arg_info["validate"] = arg_def.validate
                args_schema[arg_name] = arg_info

            tools.append(
                {
                    "name": tool_def.name,
                    "description": tool_def.description,
                    "service": tool_def.service_name,
                    "args": args_schema,
                    "inputSchema": args_to_json_schema(tool_def.args),
                    "annotations": tool_annotations(tool_def),
                    "risk": tool_def.risk,
                }
            )

        await self._send_result(websocket, {"tools": tools}, msg_id)

    # --- JSON-RPC helpers ---

    async def _send_result(self, websocket: Any, result: Any, msg_id: Any) -> None:
        """Send a JSON-RPC success response."""
        response = {"jsonrpc": "2.0", "result": result, "id": msg_id}
        await websocket.send(json.dumps(response))

    async def _send_error(self, websocket: Any, code: int, message: str, msg_id: Any) -> None:
        """Send a JSON-RPC error response."""
        response = {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": msg_id,
        }
        await websocket.send(json.dumps(response))
