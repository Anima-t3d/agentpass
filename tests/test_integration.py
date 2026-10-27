"""End-to-end integration tests — real WebSocket server with mocked services (T4).

Uses real GatewayServer, PermissionEngine, Executor, Database, and AgentPassClient.
Only the approval channel and HA service handler are mocked.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import tempfile
from collections.abc import AsyncIterator
from typing import Any

import pytest
import websockets.asyncio.server

from agentpass.client import AgentPassClient, AgentPassDenied
from agentpass.config import (
    AuthConfig,
    PermissionRule,
    Permissions,
    ServiceConfig,
    load_tools_file,
)
from agentpass.db import Database
from agentpass.engine import PermissionEngine
from agentpass.executor import ExecutionError, Executor
from agentpass.registry import build_registry
from agentpass.server import GatewayServer
from agentpass.services.base import ServiceHandler
from tests.fakes import FakeChannel, make_coordinator

# ---------------------------------------------------------------------------
# Mock services
# ---------------------------------------------------------------------------


class MockHAService(ServiceHandler):
    """Mock HA service that returns canned responses."""

    async def execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "ha_get_state":
            return {"entity_id": args["entity_id"], "state": "21.3"}
        if tool_name == "ha_call_service":
            return {"result": []}
        raise ExecutionError(f"Unknown tool: {tool_name}")

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TOKEN = "test-token"


@pytest.fixture
async def gateway_env() -> AsyncIterator[tuple[str, FakeChannel, GatewayServer, Database]]:
    """Start a full gateway with real WS server, return (url, channel, gateway, db)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"
        db = Database(db_path)
        await db.initialize()

        # Build registry from HA tools YAML
        tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
        svc_config = ServiceConfig(
            name="homeassistant",
            url="http://ha",
            auth=AuthConfig(type="bearer", token="x"),
            tools=tools,
        )
        registry = build_registry({"homeassistant": svc_config})

        # Mock services
        ha = MockHAService()
        executor = Executor({"homeassistant": ha}, registry)
        channel = FakeChannel()

        # Permission rules:
        #   ha_get_* -> allow (default)
        #   ha_call_service(lock.*) -> deny (rule)
        #   everything else -> ask (default fallback)
        permissions = Permissions(
            defaults=[
                PermissionRule(pattern="ha_get_state(*)", action="allow"),
                PermissionRule(pattern="*", action="ask"),
            ],
            rules=[
                PermissionRule(pattern="ha_call_service(lock.*)", action="deny"),
            ],
        )
        engine = PermissionEngine(permissions, registry=registry)

        gateway = GatewayServer(
            agent_token=TOKEN,
            engine=engine,
            executor=executor,
            coordinator=make_coordinator(db, channel),
            db=db,
            approval_timeout=60,
            registry=registry,
        )

        # Start real WS server
        server = await websockets.asyncio.server.serve(
            gateway.handle_connection,
            "127.0.0.1",
            0,  # Random port
        )

        # Get the assigned port
        port = server.sockets[0].getsockname()[1]
        url = f"ws://127.0.0.1:{port}"

        yield url, channel, gateway, db

        server.close()
        await server.wait_closed()
        await db.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAutoAllowedRequest:
    """An auto-allowed request flows through the real stack end-to-end."""

    async def test_auto_allowed_request(self, gateway_env):
        url, _channel, _gateway, _db = gateway_env

        async with AgentPassClient(url, TOKEN) as client:
            result = await client.tool_request("ha_get_state", entity_id="sensor.temp")

        assert result == {"entity_id": "sensor.temp", "state": "21.3"}


class TestPolicyDeniedRequest:
    """A policy-denied request raises AgentPassDenied with -32003."""

    async def test_policy_denied_request(self, gateway_env):
        url, _channel, _gateway, _db = gateway_env

        async with AgentPassClient(url, TOKEN) as client:
            with pytest.raises(AgentPassDenied) as exc_info:
                await client.tool_request(
                    "ha_call_service",
                    domain="lock",
                    service="lock",
                    entity_id="lock.front",
                )

        assert exc_info.value.code == -32003


class TestAskApprovedRequest:
    """An ask-flow request approved by the human returns the result."""

    async def test_ask_approved_request(self, gateway_env):
        url, channel, _gateway, _db = gateway_env

        async with AgentPassClient(url, TOKEN) as client:

            async def approve_after_delay():
                await asyncio.sleep(0.2)
                assert channel.last_request is not None
                await channel.approve(channel.last_request.approval_id)

            approve_task = asyncio.create_task(approve_after_delay())
            result = await client.tool_request(
                "ha_call_service",
                domain="light",
                service="turn_on",
                entity_id="light.bedroom",
            )
            await approve_task

        # The mock HA service returns {"result": []} for ha_call_service
        assert result == {"result": []}


class TestAskDeniedRequest:
    """An ask-flow request denied by the human raises AgentPassDenied."""

    async def test_ask_denied_request(self, gateway_env):
        url, channel, _gateway, _db = gateway_env

        async with AgentPassClient(url, TOKEN) as client:

            async def deny_after_delay():
                await asyncio.sleep(0.2)
                assert channel.last_request is not None
                await channel.deny(channel.last_request.approval_id)

            deny_task = asyncio.create_task(deny_after_delay())
            with pytest.raises(AgentPassDenied) as exc_info:
                await client.tool_request(
                    "ha_call_service",
                    domain="light",
                    service="turn_on",
                    entity_id="light.bedroom",
                )
            await deny_task

        assert exc_info.value.code == -32001


class TestOfflineRetrieval:
    """Results resolved while agent is offline can be retrieved later."""

    async def test_offline_retrieval(self, gateway_env):
        url, channel, _gateway, _db = gateway_env

        # Step 1: Client A connects and sends a tool_request that requires approval
        client_a = AgentPassClient(url, TOKEN)
        await client_a.connect()

        # Fire the tool_request in a background task (it will block waiting for approval)
        request_task = asyncio.create_task(
            client_a.tool_request(
                "ha_call_service",
                domain="light",
                service="turn_on",
                entity_id="light.bedroom",
            )
        )

        # Wait for the approval request to reach the channel
        await asyncio.sleep(0.3)
        assert channel.last_request is not None
        pending_request_id = channel.last_request.approval_id

        # Step 2: Disconnect client A while approval is still pending.
        # Cancel the pending request_task first, since it will never complete
        # on this connection.
        request_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await request_task

        await client_a.close()

        # Wait for the gateway to notice the disconnect and set up background handling
        await asyncio.sleep(0.3)

        # Step 3: Simulate approval via channel (gateway stores result in DB)
        await channel.approve(pending_request_id)

        # Wait for the offline execution + DB storage to complete
        await asyncio.sleep(0.5)

        # Step 4: Client B connects and retrieves pending results
        async with AgentPassClient(url, TOKEN) as client_b:
            results = await client_b.get_pending_results()

        # Verify the result is returned
        assert len(results) >= 1
        # Find the result for our request
        matching = [r for r in results if r["request_id"] == pending_request_id]
        assert len(matching) == 1

        # The result column is a JSON string stored in DB; the raw row is returned
        result_data = matching[0]["result"]
        if isinstance(result_data, str):
            result_data = json.loads(result_data)
        assert result_data["status"] == "executed"
        assert result_data["data"] == {"result": []}
