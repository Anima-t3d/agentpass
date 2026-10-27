"""Tests for agentpass.server — WebSocket server, auth, dispatch, rate limiting."""

from __future__ import annotations

import asyncio
import contextlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentpass.approval import ApprovalChannel, ApprovalCoordinator, ApprovalReason
from agentpass.config import RateLimitConfig
from agentpass.db import Database
from agentpass.engine import Evaluation, PermissionEngine
from agentpass.executor import ExecutionError, Executor
from agentpass.models import Decision
from agentpass.pipeline import ApprovalDenied
from agentpass.server import (
    APPROVAL_DENIED,
    APPROVAL_TIMEOUT,
    EXECUTION_FAILED,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    NOT_AUTHENTICATED,
    PARSE_ERROR,
    POLICY_DENIED,
    RATE_LIMIT_EXCEEDED,
    GatewayServer,
    RateLimiter,
)
from tests.fakes import FakeChannel, make_coordinator

# ---------------------------------------------------------------------------
# MockWebSocket
# ---------------------------------------------------------------------------


class MockWebSocket:
    """Simulates a websockets connection for unit tests."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.to_recv: asyncio.Queue[str] = asyncio.Queue()
        self.closed = False
        self.close_code: int | None = None
        self.close_reason: str | None = None
        self._iter_timeout: float = 0.1

    async def send(self, data: str) -> None:
        self.sent.append(data)

    async def recv(self) -> str:
        return await self.to_recv.get()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = True
        self.close_code = code
        self.close_reason = reason

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        if self.closed:
            raise StopAsyncIteration
        try:
            data = await asyncio.wait_for(self.to_recv.get(), timeout=self._iter_timeout)
        except TimeoutError:
            raise StopAsyncIteration from None
        return data

    # Helper methods for tests

    def enqueue(self, msg: dict | str) -> None:
        """Enqueue a message (dict will be JSON-encoded)."""
        if isinstance(msg, dict):
            msg = json.dumps(msg)
        self.to_recv.put_nowait(msg)

    def get_responses(self) -> list[dict]:
        """Return all sent messages parsed as JSON dicts."""
        return [json.loads(s) for s in self.sent]

    def last_response(self) -> dict:
        """Return the last sent message parsed as JSON."""
        return json.loads(self.sent[-1])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TOKEN = "test-secret-token"


def _make_server(**overrides) -> GatewayServer:
    """Create a GatewayServer with mocked dependencies."""
    registry = overrides.pop("registry", None)
    engine = overrides.pop("engine", MagicMock(spec=PermissionEngine))
    executor = overrides.pop("executor", AsyncMock(spec=Executor))
    channel = overrides.pop("channel", None) or FakeChannel()
    db = overrides.pop("db", AsyncMock(spec=Database))
    services = overrides.pop("services", None)
    rate_limit_config = overrides.pop(
        "rate_limit_config",
        RateLimitConfig(max_pending_approvals=10, max_requests_per_minute=60),
    )

    return GatewayServer(
        agent_token=overrides.pop("agent_token", TOKEN),
        engine=engine,
        executor=executor,
        coordinator=make_coordinator(db, channel),
        db=db,
        approval_timeout=overrides.pop("approval_timeout", 900),
        rate_limit_config=rate_limit_config,
        registry=registry,
        services=services,
    )


def _auth_msg(token: str = TOKEN, msg_id: str = "auth-1") -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "auth",
        "params": {"token": token},
        "id": msg_id,
    }


def _tool_request_msg(
    tool: str = "ha_get_state",
    args: dict | None = None,
    msg_id: str = "req-1",
) -> dict:
    if args is None:
        args = {"entity_id": "sensor.temp"}
    return {
        "jsonrpc": "2.0",
        "method": "tool_request",
        "params": {"tool": tool, "args": args},
        "id": msg_id,
    }


async def _cancel_task(task: asyncio.Task) -> None:
    """Cancel a task and suppress CancelledError."""
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


# ---------------------------------------------------------------------------
# RateLimiter unit tests
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_allows_under_limit(self):
        rl = RateLimiter(max_per_minute=5)
        for _ in range(5):
            assert rl.check() is True

    def test_blocks_over_limit(self):
        rl = RateLimiter(max_per_minute=3)
        for _ in range(3):
            assert rl.check() is True
        assert rl.check() is False

    def test_window_slides(self):
        rl = RateLimiter(max_per_minute=2)
        assert rl.check() is True
        assert rl.check() is True
        assert rl.check() is False
        # Manually expire the first timestamp
        rl._timestamps[0] -= 61
        assert rl.check() is True


# ---------------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------------


class TestAuthentication:
    async def test_auth_correct_token_succeeds(self):
        """Auth with correct token returns authenticated."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())

        await server.handle_connection(ws)

        resp = ws.last_response()
        assert resp["result"]["status"] == "authenticated"
        assert resp["id"] == "auth-1"

    async def test_auth_wrong_token_closes(self):
        """Auth with wrong token returns -32005 and closes."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue(_auth_msg(token="wrong-token"))

        await server.handle_connection(ws)

        resp = ws.last_response()
        assert resp["error"]["code"] == NOT_AUTHENTICATED
        assert ws.closed is True

    async def test_non_auth_before_auth_closes(self):
        """Non-auth message before auth returns -32005 and closes."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue(_tool_request_msg())

        await server.handle_connection(ws)

        resp = ws.last_response()
        assert resp["error"]["code"] == NOT_AUTHENTICATED
        assert ws.closed is True

    async def test_auth_timeout_closes(self):
        """Auth must complete within AUTH_TIMEOUT seconds."""
        server = _make_server()
        ws = MockWebSocket()
        # Don't enqueue anything — recv() will hang

        with patch("agentpass.server.AUTH_TIMEOUT", 0.05):
            await server.handle_connection(ws)

        resp = ws.last_response()
        assert resp["error"]["code"] == NOT_AUTHENTICATED
        assert "timeout" in resp["error"]["message"].lower()
        assert ws.closed is True

    async def test_auth_malformed_json_closes(self):
        """Malformed JSON during auth phase returns -32700 and closes."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue("not valid json {{{")

        await server.handle_connection(ws)

        resp = ws.last_response()
        assert resp["error"]["code"] == PARSE_ERROR
        assert ws.closed is True


# ---------------------------------------------------------------------------
# Tool request tests
# ---------------------------------------------------------------------------


class TestToolRequests:
    async def test_allow_executes_immediately(self):
        """allow -> execute immediately and return result."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        executor = AsyncMock(spec=Executor)
        executor.execute.return_value = {"state": "on"}
        server = _make_server(engine=engine, executor=executor)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg())

        await server.handle_connection(ws)

        responses = ws.get_responses()
        # First response is auth, second is tool result
        assert len(responses) == 2
        tool_resp = responses[1]
        assert tool_resp["result"]["status"] == "executed"
        assert tool_resp["result"]["data"] == {"state": "on"}
        assert tool_resp["id"] == "req-1"

    async def test_deny_returns_policy_denied(self):
        """deny -> -32003."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.DENY)
        server = _make_server(engine=engine)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg())

        await server.handle_connection(ws)

        responses = ws.get_responses()
        tool_resp = responses[1]
        assert tool_resp["error"]["code"] == POLICY_DENIED

    async def test_ask_triggers_approval_flow(self):
        """ask -> triggers approval flow, deferred until resolved."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ASK)
        channel = FakeChannel()
        executor = AsyncMock(spec=Executor)
        executor.execute.return_value = {"state": "on"}
        db = AsyncMock(spec=Database)
        server = _make_server(engine=engine, channel=channel, executor=executor, db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="ask-1"))

        # Start connection handling in background
        task = asyncio.create_task(server.handle_connection(ws))

        # Wait for the approval to be pending
        await asyncio.sleep(0.2)

        # Verify approval was sent to messenger
        assert len(channel.sent) == 1
        request_id = channel.last_request.approval_id

        # Verify request is pending
        assert request_id in server._pending

        # Resolve the approval
        await channel.approve(request_id, "12345")

        # Wait for task to complete
        await asyncio.sleep(0.2)
        ws.closed = True  # Allow iteration to stop
        await asyncio.sleep(0.1)
        await _cancel_task(task)

        responses = ws.get_responses()
        # Auth response + tool result
        assert len(responses) >= 2
        # Find the tool result (not auth)
        tool_responses = [r for r in responses if r.get("id") == "ask-1"]
        assert len(tool_responses) == 1
        assert tool_responses[0]["result"]["status"] == "executed"

    async def test_ask_denied_by_user(self):
        """ask -> denied by user returns -32001."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ASK)
        channel = FakeChannel()
        db = AsyncMock(spec=Database)
        server = _make_server(engine=engine, channel=channel, db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="deny-1"))

        task = asyncio.create_task(server.handle_connection(ws))
        await asyncio.sleep(0.2)

        # Get the server-generated request_id
        request_id = channel.last_request.approval_id

        # Deny the approval
        await channel.deny(request_id, "12345")

        await asyncio.sleep(0.2)
        ws.closed = True
        await asyncio.sleep(0.1)
        await _cancel_task(task)

        tool_responses = [r for r in ws.get_responses() if r.get("id") == "deny-1"]
        assert len(tool_responses) == 1
        assert tool_responses[0]["error"]["code"] == APPROVAL_DENIED

    async def test_ask_timeout(self):
        """ask -> timeout returns -32002."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ASK)
        channel = FakeChannel()
        db = AsyncMock(spec=Database)
        server = _make_server(engine=engine, channel=channel, db=db, approval_timeout=0.1)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="timeout-1"))

        task = asyncio.create_task(server.handle_connection(ws))
        # The gateway owns the timeout: nobody answers, the future times out
        await asyncio.sleep(0.4)
        ws.closed = True
        await asyncio.sleep(0.1)
        await _cancel_task(task)

        tool_responses = [r for r in ws.get_responses() if r.get("id") == "timeout-1"]
        assert len(tool_responses) == 1
        assert tool_responses[0]["error"]["code"] == APPROVAL_TIMEOUT
        assert [o.reason for _, o in channel.finalized] == [ApprovalReason.TIMEOUT]

    async def test_multiple_concurrent_requests(self):
        """Multiple concurrent tool_requests each get own task."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        executor = AsyncMock(spec=Executor)
        executor.execute.return_value = {"result": "ok"}
        server = _make_server(engine=engine, executor=executor)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="r1"))
        ws.enqueue(_tool_request_msg(msg_id="r2"))
        ws.enqueue(_tool_request_msg(msg_id="r3"))

        await server.handle_connection(ws)

        responses = ws.get_responses()
        # auth + 3 tool results
        assert len(responses) == 4
        ids = {r["id"] for r in responses}
        assert ids == {"auth-1", "r1", "r2", "r3"}

    async def test_malformed_json_returns_parse_error(self):
        """Malformed JSON returns -32700."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue("not json!!!")

        await server.handle_connection(ws)

        responses = ws.get_responses()
        error_resp = responses[1]
        assert error_resp["error"]["code"] == PARSE_ERROR

    async def test_missing_method_returns_invalid_request(self):
        """Missing method field returns -32600."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue({"jsonrpc": "2.0", "params": {}, "id": "bad-1"})

        await server.handle_connection(ws)

        responses = ws.get_responses()
        error_resp = responses[1]
        assert error_resp["error"]["code"] == INVALID_REQUEST

    async def test_unknown_method_returns_method_not_found(self):
        """Unknown method returns -32601."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(
            {
                "jsonrpc": "2.0",
                "method": "nonexistent",
                "params": {},
                "id": "u-1",
            }
        )

        await server.handle_connection(ws)

        responses = ws.get_responses()
        error_resp = responses[1]
        assert error_resp["error"]["code"] == METHOD_NOT_FOUND

    async def test_missing_tool_name_returns_invalid_request(self):
        """Missing tool name in tool_request returns -32600."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(
            {
                "jsonrpc": "2.0",
                "method": "tool_request",
                "params": {"args": {}},
                "id": "m-1",
            }
        )

        await server.handle_connection(ws)

        responses = ws.get_responses()
        error_resp = responses[1]
        assert error_resp["error"]["code"] == INVALID_REQUEST

    async def test_execution_error_returns_execution_failed(self):
        """Execution error returns -32004."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        executor = AsyncMock(spec=Executor)
        executor.execute.side_effect = ExecutionError("Service unavailable")
        server = _make_server(engine=engine, executor=executor)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg())

        await server.handle_connection(ws)

        responses = ws.get_responses()
        error_resp = responses[1]
        assert error_resp["error"]["code"] == EXECUTION_FAILED
        assert "Service unavailable" in error_resp["error"]["message"]


# ---------------------------------------------------------------------------
# Rate limiting tests
# ---------------------------------------------------------------------------


class TestRateLimiting:
    async def test_request_rate_limit_exceeded(self):
        """Exceeding max_requests_per_minute returns -32006."""
        rate_config = RateLimitConfig(max_requests_per_minute=2, max_pending_approvals=10)
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        executor = AsyncMock(spec=Executor)
        executor.execute.return_value = {"ok": True}
        server = _make_server(engine=engine, executor=executor, rate_limit_config=rate_config)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="r1"))
        ws.enqueue(_tool_request_msg(msg_id="r2"))
        ws.enqueue(_tool_request_msg(msg_id="r3"))  # Should be rate-limited

        await server.handle_connection(ws)

        responses = ws.get_responses()
        # auth + 2 ok + 1 rate-limited
        assert len(responses) == 4
        rate_limited = [
            r for r in responses if r.get("error", {}).get("code") == RATE_LIMIT_EXCEEDED
        ]
        assert len(rate_limited) == 1
        assert rate_limited[0]["id"] == "r3"

    async def test_pending_approval_limit_exceeded(self):
        """Exceeding max_pending_approvals returns -32006."""
        rate_config = RateLimitConfig(max_requests_per_minute=60, max_pending_approvals=1)
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ASK)
        channel = FakeChannel()
        db = AsyncMock(spec=Database)
        server = _make_server(
            engine=engine,
            channel=channel,
            db=db,
            rate_limit_config=rate_config,
        )

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="p1"))
        ws.enqueue(_tool_request_msg(msg_id="p2"))  # Should hit pending limit

        task = asyncio.create_task(server.handle_connection(ws))
        await asyncio.sleep(0.3)

        # p2 should have been rejected with rate limit error
        responses = ws.get_responses()
        rate_limited = [
            r for r in responses if r.get("error", {}).get("code") == RATE_LIMIT_EXCEEDED
        ]
        assert len(rate_limited) >= 1

        # Clean up pending futures
        await server.resolve_all_pending()
        ws.closed = True
        await asyncio.sleep(0.1)
        await _cancel_task(task)


# ---------------------------------------------------------------------------
# Connection management tests
# ---------------------------------------------------------------------------


class TestConnectionManagement:
    async def test_second_connection_rejected(self):
        """Server rejects second concurrent connection."""
        server = _make_server()

        ws1 = MockWebSocket()
        ws1.enqueue(_auth_msg())
        # Keep ws1 alive in message loop long enough for ws2 to attempt
        ws1._iter_timeout = 5.0

        ws2 = MockWebSocket()
        ws2.enqueue(_auth_msg())

        # Start first connection (will wait in message loop)
        task1 = asyncio.create_task(server.handle_connection(ws1))
        await asyncio.sleep(0.15)

        # Try second connection — rejected once authenticated
        await server.handle_connection(ws2)

        assert ws2.closed is True
        assert ws2.close_code == 4000

        # Clean up
        ws1.closed = True
        await _cancel_task(task1)


# ---------------------------------------------------------------------------
# Audit logging tests
# ---------------------------------------------------------------------------


class TestAuditLogging:
    async def test_tool_request_logged(self):
        """Every tool request is logged with decision."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        executor = AsyncMock(spec=Executor)
        executor.execute.return_value = {"ok": True}
        db = AsyncMock(spec=Database)
        server = _make_server(engine=engine, executor=executor, db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg())

        await server.handle_connection(ws)

        db.log_audit.assert_called_once()
        audit_entry = db.log_audit.call_args[0][0]
        assert audit_entry.tool_name == "ha_get_state"
        assert audit_entry.decision == "allow"
        assert audit_entry.request_id  # UUID, not msg_id

    async def test_deny_logged(self):
        """Deny decision is logged."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.DENY)
        db = AsyncMock(spec=Database)
        server = _make_server(engine=engine, db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg())

        await server.handle_connection(ws)

        db.log_audit.assert_called_once()
        audit_entry = db.log_audit.call_args[0][0]
        assert audit_entry.decision == "deny"


# ---------------------------------------------------------------------------
# Persistence tests
# ---------------------------------------------------------------------------


class TestPersistence:
    async def test_get_pending_results(self):
        """Agent retrieves stored results via get_pending_results."""
        db = AsyncMock(spec=Database)
        db.get_completed_results = AsyncMock(return_value=[])
        db.delete_completed_results = AsyncMock()
        server = _make_server(db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(
            {
                "jsonrpc": "2.0",
                "method": "get_pending_results",
                "params": {},
                "id": "gpr-1",
            }
        )

        await server.handle_connection(ws)

        responses = ws.get_responses()
        result_resp = [r for r in responses if r.get("id") == "gpr-1"]
        assert len(result_resp) == 1
        assert "results" in result_resp[0]["result"]


# ---------------------------------------------------------------------------
# resolve_all_pending tests
# ---------------------------------------------------------------------------


class TestResolveAllPending:
    async def test_resolve_all_pending(self):
        """All open approvals are denied on shutdown and their messages finalized."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ASK)
        channel = FakeChannel()
        server = _make_server(engine=engine, channel=channel)
        tasks = [
            asyncio.create_task(server.pipeline.process(f"agent-{i}", "ha_get_state", {}))
            for i in range(3)
        ]
        while len(channel.sent) < 3:
            await asyncio.sleep(0.01)

        await server.resolve_all_pending(ApprovalReason.GATEWAY_SHUTDOWN)

        for task in tasks:
            with pytest.raises(ApprovalDenied, match="shutting down"):
                await task
        assert [o.reason for _, o in channel.finalized] == [ApprovalReason.GATEWAY_SHUTDOWN] * 3
        assert not server._pending


# ---------------------------------------------------------------------------
# Integration tests (real WebSocket)
# ---------------------------------------------------------------------------


class TestRealWebSocket:
    """Integration tests using actual WebSocket connections."""

    async def test_full_auth_handshake(self):
        """Full auth handshake over real WebSocket."""
        from websockets.asyncio.client import connect as ws_connect
        from websockets.asyncio.server import serve as ws_serve

        server = GatewayServer(
            agent_token=TOKEN,
            engine=MagicMock(spec=PermissionEngine),
            executor=AsyncMock(spec=Executor),
            coordinator=ApprovalCoordinator(AsyncMock(spec=Database), []),
            db=AsyncMock(spec=Database),
        )

        async with ws_serve(server.handle_connection, "127.0.0.1", 0) as ws_server:
            port = ws_server.sockets[0].getsockname()[1]
            async with ws_connect(f"ws://127.0.0.1:{port}") as client:
                await client.send(json.dumps(_auth_msg()))
                raw = await asyncio.wait_for(client.recv(), timeout=2)
                resp = json.loads(raw)
                assert resp["result"]["status"] == "authenticated"

    async def test_tool_request_allow_real_ws(self):
        """tool_request -> allow -> result over real WebSocket."""
        from websockets.asyncio.client import connect as ws_connect
        from websockets.asyncio.server import serve as ws_serve

        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        executor = AsyncMock(spec=Executor)
        executor.execute.return_value = {"brightness": 100}
        server = GatewayServer(
            agent_token=TOKEN,
            engine=engine,
            executor=executor,
            coordinator=ApprovalCoordinator(AsyncMock(spec=Database), []),
            db=AsyncMock(spec=Database),
        )

        async with ws_serve(server.handle_connection, "127.0.0.1", 0) as ws_server:
            port = ws_server.sockets[0].getsockname()[1]
            async with ws_connect(f"ws://127.0.0.1:{port}") as client:
                # Authenticate
                await client.send(json.dumps(_auth_msg()))
                await asyncio.wait_for(client.recv(), timeout=2)

                # Send tool request
                await client.send(json.dumps(_tool_request_msg()))
                raw = await asyncio.wait_for(client.recv(), timeout=2)
                resp = json.loads(raw)
                assert resp["result"]["status"] == "executed"
                assert resp["result"]["data"] == {"brightness": 100}

    async def test_tool_request_deny_real_ws(self):
        """tool_request -> deny -> error over real WebSocket."""
        from websockets.asyncio.client import connect as ws_connect
        from websockets.asyncio.server import serve as ws_serve

        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.DENY)
        server = GatewayServer(
            agent_token=TOKEN,
            engine=engine,
            executor=AsyncMock(spec=Executor),
            coordinator=ApprovalCoordinator(AsyncMock(spec=Database), []),
            db=AsyncMock(spec=Database),
        )

        async with ws_serve(server.handle_connection, "127.0.0.1", 0) as ws_server:
            port = ws_server.sockets[0].getsockname()[1]
            async with ws_connect(f"ws://127.0.0.1:{port}") as client:
                # Authenticate
                await client.send(json.dumps(_auth_msg()))
                await asyncio.wait_for(client.recv(), timeout=2)

                # Send tool request
                await client.send(json.dumps(_tool_request_msg()))
                raw = await asyncio.wait_for(client.recv(), timeout=2)
                resp = json.loads(raw)
                assert resp["error"]["code"] == POLICY_DENIED

    async def test_malformed_json_real_ws(self):
        """Malformed JSON over real WebSocket returns -32700."""
        from websockets.asyncio.client import connect as ws_connect
        from websockets.asyncio.server import serve as ws_serve

        server = GatewayServer(
            agent_token=TOKEN,
            engine=MagicMock(spec=PermissionEngine),
            executor=AsyncMock(spec=Executor),
            coordinator=ApprovalCoordinator(AsyncMock(spec=Database), []),
            db=AsyncMock(spec=Database),
        )

        async with ws_serve(server.handle_connection, "127.0.0.1", 0) as ws_server:
            port = ws_server.sockets[0].getsockname()[1]
            async with ws_connect(f"ws://127.0.0.1:{port}") as client:
                # Authenticate first
                await client.send(json.dumps(_auth_msg()))
                await asyncio.wait_for(client.recv(), timeout=2)

                # Send malformed JSON
                await client.send("not json {{{")
                raw = await asyncio.wait_for(client.recv(), timeout=2)
                resp = json.loads(raw)
                assert resp["error"]["code"] == PARSE_ERROR


# ---------------------------------------------------------------------------
# Major 1: msg_id=None validation
# ---------------------------------------------------------------------------


class TestMsgIdValidation:
    async def test_missing_id_returns_invalid_request(self):
        """Major 1: tool_request without 'id' field returns -32600."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        server = _make_server(engine=engine)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        # Message with no "id" field
        ws.enqueue(
            {
                "jsonrpc": "2.0",
                "method": "tool_request",
                "params": {"tool": "ha_get_state", "args": {"entity_id": "sensor.temp"}},
            }
        )

        await server.handle_connection(ws)

        responses = ws.get_responses()
        # Auth response + error response
        assert len(responses) == 2
        error_resp = responses[1]
        assert error_resp["error"]["code"] == INVALID_REQUEST
        assert error_resp["id"] is None


# ---------------------------------------------------------------------------
# Major 3: _execute_and_respond catches all exceptions
# ---------------------------------------------------------------------------


class TestExecuteAndRespondExceptions:
    async def test_non_execution_error_returns_error_response(self):
        """Major 3: Non-ExecutionError exception returns -32004 with generic message."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        executor = AsyncMock(spec=Executor)
        executor.execute.side_effect = RuntimeError("Unexpected HA error")
        server = _make_server(engine=engine, executor=executor)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg())

        await server.handle_connection(ws)

        responses = ws.get_responses()
        error_resp = responses[1]
        assert error_resp["error"]["code"] == EXECUTION_FAILED
        assert "Internal execution error" in error_resp["error"]["message"]

    async def test_value_error_returns_error_response(self):
        """Major 3: ValueError (non-ExecutionError) also returns -32004."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ALLOW)
        executor = AsyncMock(spec=Executor)
        executor.execute.side_effect = ValueError("Bad value")
        server = _make_server(engine=engine, executor=executor)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg())

        await server.handle_connection(ws)

        responses = ws.get_responses()
        error_resp = responses[1]
        assert error_resp["error"]["code"] == EXECUTION_FAILED
        assert "Internal execution error" in error_resp["error"]["message"]


# ---------------------------------------------------------------------------
# Critical 2: Timeout scheduling
# ---------------------------------------------------------------------------


class TestTimeoutOwnership:
    async def test_gateway_does_not_use_channel_scheduled_timeouts(self):
        """The coordinator owns the approval timeout; channels have no timeout hooks."""
        assert not hasattr(ApprovalChannel, "schedule_timeout")


# ---------------------------------------------------------------------------
# Critical 1: FR8 persistence - offline approval flow
# ---------------------------------------------------------------------------


class TestOfflineApprovalFlow:
    async def test_get_pending_results_calls_db_properly(self):
        """FR8: get_pending_results queries db.get_completed_results and returns data."""
        db = AsyncMock(spec=Database)
        db.get_completed_results = AsyncMock(
            return_value=[
                {
                    "request_id": "old-1",
                    "result": '{"status": "executed", "data": {"state": "on"}}',
                }
            ]
        )
        db.delete_completed_results = AsyncMock()
        server = _make_server(db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(
            {
                "jsonrpc": "2.0",
                "method": "get_pending_results",
                "params": {},
                "id": "gpr-1",
            }
        )

        await server.handle_connection(ws)

        responses = ws.get_responses()
        result_resp = [r for r in responses if r.get("id") == "gpr-1"]
        assert len(result_resp) == 1
        assert len(result_resp[0]["result"]["results"]) == 1
        assert result_resp[0]["result"]["results"][0]["request_id"] == "old-1"

        # Verify cleanup was called
        db.delete_completed_results.assert_called_once_with(["old-1"], "default")

    async def test_get_pending_results_empty(self):
        """FR8: get_pending_results returns empty when no completed results."""
        db = AsyncMock(spec=Database)
        db.get_completed_results = AsyncMock(return_value=[])
        db.delete_completed_results = AsyncMock()
        server = _make_server(db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(
            {
                "jsonrpc": "2.0",
                "method": "get_pending_results",
                "params": {},
                "id": "gpr-2",
            }
        )

        await server.handle_connection(ws)

        responses = ws.get_responses()
        result_resp = [r for r in responses if r.get("id") == "gpr-2"]
        assert result_resp[0]["result"]["results"] == []
        # No cleanup called when no results
        db.delete_completed_results.assert_not_called()


# ---------------------------------------------------------------------------
# Major 5: Audit log updated on resolution
# ---------------------------------------------------------------------------


class TestAuditResolution:
    async def test_audit_updated_on_approval_allow(self):
        """audit entry updated with resolution after approval resolves."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ASK)
        channel = FakeChannel()
        executor = AsyncMock(spec=Executor)
        executor.execute.return_value = {"state": "on"}
        db = AsyncMock(spec=Database)
        db.update_audit_resolution = AsyncMock()
        server = _make_server(engine=engine, channel=channel, executor=executor, db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="audit-1"))

        task = asyncio.create_task(server.handle_connection(ws))
        await asyncio.sleep(0.2)

        # Get server-generated request_id
        request_id = channel.last_request.approval_id

        # Resolve with allow
        await channel.approve(request_id, "12345")

        await asyncio.sleep(0.2)
        ws.closed = True
        await asyncio.sleep(0.1)
        await _cancel_task(task)

        # Verify audit resolution was called
        db.update_audit_resolution.assert_called_once()
        call_kwargs = db.update_audit_resolution.call_args.kwargs
        assert call_kwargs["request_id"] == request_id
        assert call_kwargs["resolution"] == "approved"
        assert call_kwargs["resolved_by"] == "12345"

    async def test_audit_updated_on_approval_deny(self):
        """audit entry updated on denial."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ASK)
        channel = FakeChannel()
        db = AsyncMock(spec=Database)
        db.update_audit_resolution = AsyncMock()
        server = _make_server(engine=engine, channel=channel, db=db)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="audit-2"))

        task = asyncio.create_task(server.handle_connection(ws))
        await asyncio.sleep(0.2)

        # Get server-generated request_id
        request_id = channel.last_request.approval_id

        await channel.deny(request_id, "67890")

        await asyncio.sleep(0.2)
        ws.closed = True
        await asyncio.sleep(0.1)
        await _cancel_task(task)

        db.update_audit_resolution.assert_called_once()
        call_kwargs = db.update_audit_resolution.call_args.kwargs
        assert call_kwargs["request_id"] == request_id
        assert call_kwargs["resolution"] == "denied"
        assert call_kwargs["resolved_by"] == "67890"

    async def test_audit_updated_on_timeout(self):
        """audit entry updated on timeout."""
        engine = MagicMock(spec=PermissionEngine)
        engine.evaluate.return_value = Evaluation(Decision.ASK)
        channel = FakeChannel()
        db = AsyncMock(spec=Database)
        db.update_audit_resolution = AsyncMock()
        server = _make_server(engine=engine, channel=channel, db=db, approval_timeout=0.1)

        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg(msg_id="audit-3"))

        task = asyncio.create_task(server.handle_connection(ws))
        await asyncio.sleep(0.4)
        request_id = channel.last_request.approval_id
        ws.closed = True
        await asyncio.sleep(0.1)
        await _cancel_task(task)

        db.update_audit_resolution.assert_called_once()
        call_kwargs = db.update_audit_resolution.call_args.kwargs
        assert call_kwargs["request_id"] == request_id
        assert call_kwargs["resolution"] == "timed_out"
        assert call_kwargs["resolved_by"] == "gateway"


# ---------------------------------------------------------------------------
# list_tools tests
# ---------------------------------------------------------------------------


class TestListTools:
    async def test_list_tools_returns_tool_definitions(self):
        """list_tools method returns tool definitions from registry."""
        from agentpass.config import AuthConfig, ServiceConfig, load_tools_file
        from agentpass.registry import build_registry

        tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
        svc = ServiceConfig(
            name="homeassistant",
            url="http://ha",
            auth=AuthConfig(type="bearer", token="x"),
            tools=tools,
        )
        registry = build_registry({"homeassistant": svc})

        server = _make_server(registry=registry)
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue({"jsonrpc": "2.0", "method": "list_tools", "params": {}, "id": "lt-1"})

        await server.handle_connection(ws)

        responses = ws.get_responses()
        lt_resp = [r for r in responses if r.get("id") == "lt-1"]
        assert len(lt_resp) == 1
        result = lt_resp[0]["result"]
        assert "tools" in result
        tool_names = [t["name"] for t in result["tools"]]
        assert "ha_get_state" in tool_names
        assert "ha_call_service" in tool_names
        # Verify arg schema
        ha_get_state = next(t for t in result["tools"] if t["name"] == "ha_get_state")
        assert ha_get_state["args"]["entity_id"]["required"] is True

    async def test_list_tools_no_registry(self):
        """list_tools returns empty when no registry."""
        server = _make_server()
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue({"jsonrpc": "2.0", "method": "list_tools", "params": {}, "id": "lt-2"})

        await server.handle_connection(ws)

        responses = ws.get_responses()
        lt_resp = [r for r in responses if r.get("id") == "lt-2"]
        assert lt_resp[0]["result"]["tools"] == []

    async def test_list_tools_includes_service_name(self):
        """list_tools response includes the service name for each tool."""
        from agentpass.config import AuthConfig, ServiceConfig, load_tools_file
        from agentpass.registry import build_registry

        tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
        svc = ServiceConfig(
            name="homeassistant",
            url="http://ha",
            auth=AuthConfig(type="bearer", token="x"),
            tools=tools,
        )
        registry = build_registry({"homeassistant": svc})

        server = _make_server(registry=registry)
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue({"jsonrpc": "2.0", "method": "list_tools", "params": {}, "id": "lt-3"})

        await server.handle_connection(ws)

        responses = ws.get_responses()
        lt_resp = [r for r in responses if r.get("id") == "lt-3"]
        for tool in lt_resp[0]["result"]["tools"]:
            assert tool["service"] == "homeassistant"


class TestHealthStatus:
    """Tests for GatewayServer.health_status()."""

    async def test_healthy_when_all_ok(self):
        """Returns healthy when db, messenger, and services are all up."""
        db = AsyncMock(spec=Database)
        db.health_check = AsyncMock(return_value=True)
        channel = FakeChannel(healthy=True)
        svc = AsyncMock()
        svc.health_check = AsyncMock(return_value=True)

        server = _make_server(db=db, channel=channel, services={"ha": svc})
        status = await server.health_status()

        assert status["status"] == "healthy"
        assert status["checks"]["database"] is True
        assert status["checks"]["telegram"] is True
        assert status["checks"]["services"]["ha"] is True

    async def test_unhealthy_when_db_down(self):
        """Returns unhealthy when database is down."""
        db = AsyncMock(spec=Database)
        db.health_check = AsyncMock(return_value=False)
        channel = FakeChannel(healthy=True)

        server = _make_server(db=db, channel=channel)
        status = await server.health_status()

        assert status["status"] == "unhealthy"
        assert status["checks"]["database"] is False

    async def test_unhealthy_when_telegram_down(self):
        """Returns unhealthy when Telegram bot is down."""
        db = AsyncMock(spec=Database)
        db.health_check = AsyncMock(return_value=True)
        channel = FakeChannel(healthy=False)

        server = _make_server(db=db, channel=channel)
        status = await server.health_status()

        assert status["status"] == "unhealthy"
        assert status["checks"]["telegram"] is False

    async def test_healthy_with_service_down(self):
        """Stays healthy when a service is down (services are non-critical)."""
        db = AsyncMock(spec=Database)
        db.health_check = AsyncMock(return_value=True)
        channel = FakeChannel(healthy=True)
        svc = AsyncMock()
        svc.health_check = AsyncMock(return_value=False)

        server = _make_server(db=db, channel=channel, services={"ha": svc})
        status = await server.health_status()

        assert status["status"] == "healthy"
        assert status["checks"]["services"]["ha"] is False
