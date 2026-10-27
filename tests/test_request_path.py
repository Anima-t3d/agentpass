"""End-to-end and security tests for the request path.

Everything between the WebSocket and the service handler is real: GatewayServer,
PermissionEngine, ToolRegistry (from tools/homeassistant.yaml), Executor and
Database. Only the socket, the approval channel and the upstream service are fakes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from agentpass.config import (
    AuthConfig,
    PermissionRule,
    Permissions,
    ServiceConfig,
    load_tools_file,
)
from agentpass.db import Database
from agentpass.engine import PermissionEngine
from agentpass.executor import Executor
from agentpass.registry import build_registry
from agentpass.server import (
    APPROVAL_UNAVAILABLE,
    INVALID_PARAMS,
    NOT_AUTHENTICATED,
    POLICY_DENIED,
    UNKNOWN_TOOL,
    GatewayServer,
)
from agentpass.services.base import ServiceHandler
from agentpass.services.http import GenericHTTPService, HTTPServiceError
from tests.fakes import FakeChannel, make_coordinator

TOKEN = "e2e-secret-token"


class FakeWS:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.inbox: asyncio.Queue[str] = asyncio.Queue()
        self.closed = False
        self.close_code: int | None = None

    async def send(self, data: str) -> None:
        self.sent.append(json.loads(data))

    async def recv(self) -> str:
        return await self.inbox.get()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = True
        self.close_code = code

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        if self.closed:
            raise StopAsyncIteration
        try:
            return await asyncio.wait_for(self.inbox.get(), timeout=0.3)
        except TimeoutError:
            raise StopAsyncIteration from None

    def put(self, msg: dict | str) -> None:
        self.inbox.put_nowait(msg if isinstance(msg, str) else json.dumps(msg))


class RecordingService(ServiceHandler):
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, args))
        return {"ok": True}

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


@pytest.fixture
async def env(tmp_path):
    db = Database(str(tmp_path / "e2e.db"))
    await db.initialize()
    tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
    registry = build_registry(
        {
            "homeassistant": ServiceConfig(
                name="homeassistant",
                url="http://ha",
                auth=AuthConfig(type="bearer", token="x"),
                tools=tools,
            )
        }
    )
    service = RecordingService()
    channel = FakeChannel()
    permissions = Permissions(
        defaults=[
            PermissionRule(pattern="ha_get_state(*)", action="allow"),
            PermissionRule(pattern="*", action="ask"),
        ],
        rules=[PermissionRule(pattern="ha_call_service(lock.*)", action="deny")],
    )
    gateway = GatewayServer(
        agent_token=TOKEN,
        engine=PermissionEngine(permissions, registry=registry),
        executor=Executor({"homeassistant": service}, registry),
        coordinator=make_coordinator(db, channel),
        db=db,
        approval_timeout=60,
        registry=registry,
    )

    class Env:
        pass

    e = Env()
    e.db, e.service, e.channel, e.gateway, e.registry = db, service, channel, gateway, registry
    yield e
    await db.close()


def _auth(token: str = TOKEN) -> dict:
    return {"jsonrpc": "2.0", "method": "auth", "params": {"token": token}, "id": "a"}


def _req(tool: Any, args: Any, msg_id: Any = "r1") -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "tool_request",
        "params": {"tool": tool, "args": args},
        "id": msg_id,
    }


async def _session(env, *messages: dict | str) -> list[dict]:
    ws = FakeWS()
    ws.put(_auth())
    for m in messages:
        ws.put(m)
    await env.gateway.handle_connection(ws)
    return ws.sent[1:]  # drop auth response


# --- Happy paths through the real engine ---------------------------------


async def test_allow_executes_and_audits_registry_signature(env):
    (resp,) = await _session(env, _req("ha_get_state", {"entity_id": "sensor.temp"}))
    assert resp["result"]["status"] == "executed"
    assert env.service.calls == [("ha_get_state", {"entity_id": "sensor.temp"})]
    (entry,) = await env.db.get_audit_log()
    assert entry.signature == "ha_get_state(sensor.temp)"
    assert entry.decision == "allow"


async def test_deny_rule_uses_registry_signature(env):
    args = {"domain": "lock", "service": "unlock", "entity_id": "lock.front_door"}
    (resp,) = await _session(env, _req("ha_call_service", args))
    assert resp["error"]["code"] == POLICY_DENIED
    assert env.service.calls == []
    (entry,) = await env.db.get_audit_log()
    assert entry.signature == "ha_call_service(lock.unlock, lock.front_door)"


async def test_signature_same_in_policy_audit_and_approval(env):
    args = {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom"}
    ws = FakeWS()
    ws.put(_auth())
    ws.put(_req("ha_call_service", args))
    task = asyncio.create_task(env.gateway.handle_connection(ws))
    for _ in range(50):
        if env.channel.sent:
            break
        await asyncio.sleep(0.02)
    sent = env.channel.sent[0]
    assert sent.signature == "ha_call_service(light.turn_on, light.bedroom)"
    (entry,) = await env.db.get_audit_log()
    assert entry.signature == sent.signature
    await env.channel.approve(sent.approval_id, "1")
    await task
    assert ws.sent[-1]["result"]["status"] == "executed"
    assert env.service.calls == [("ha_call_service", args)]


async def test_optional_arg_absent_in_signature(env):
    args = {"domain": "homeassistant", "service": "restart"}
    ws = FakeWS()
    ws.put(_auth())
    ws.put(_req("ha_call_service", args))
    task = asyncio.create_task(env.gateway.handle_connection(ws))
    for _ in range(50):
        if env.channel.sent:
            break
        await asyncio.sleep(0.02)
    assert env.channel.sent[0].signature == "ha_call_service(homeassistant.restart)"
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task


# --- errors always answered -----------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        {"entity_id": "sensor.*"},  # glob injection
        {"entity_id": ["sensor.temp"]},  # wrong type
        {"entity_id": {"a": "b"}},
        {"entity_id": 5},
        {},  # missing required
        "not-an-object",
        None,
    ],
)
async def test_bad_args_get_invalid_params_error(env, args):
    (resp,) = await _session(env, _req("ha_get_state", args))
    assert resp["id"] == "r1"
    assert resp["error"]["code"] == INVALID_PARAMS
    assert env.service.calls == []
    assert env.channel.sent == []


async def test_engine_exception_still_answers_agent(env):
    env.gateway._engine = MagicMock()
    env.gateway._engine.evaluate.side_effect = RuntimeError("boom")
    (resp,) = await _session(env, _req("ha_get_state", {"entity_id": "sensor.temp"}))
    assert resp["id"] == "r1"
    assert resp["error"]["code"] == -32603
    assert "boom" not in resp["error"]["message"]


@pytest.mark.parametrize("params", ["str", 5, ["x"]])
async def test_non_object_params_answered(env, params):
    msg = {"jsonrpc": "2.0", "method": "tool_request", "params": params, "id": "p"}
    (resp,) = await _session(env, msg)
    assert resp["id"] == "p"
    assert "error" in resp


async def test_non_object_message_answered(env):
    (resp,) = await _session(env, "[1, 2]")
    assert "error" in resp


# --- unknown tools --------------------------------------------------


async def test_unknown_tool_rejected_before_engine_and_human(env):
    (resp,) = await _session(env, _req("rm_rf", {"path": "/"}))
    assert resp["error"]["code"] == UNKNOWN_TOOL
    assert env.channel.sent == []
    assert env.service.calls == []
    assert await env.db.get_audit_log() == []


# --- argument validation --------------------------------------------


@pytest.mark.parametrize(
    "entity_id",
    [
        "sensor.temp\n",  # trailing newline passed re.match $ anchor
        "sensor.temp/../../x",
        "sensor.temp?x=1",
        "sensor.temp#",
    ],
)
async def test_regex_is_fullmatch(env, entity_id):
    (resp,) = await _session(env, _req("ha_get_state", {"entity_id": entity_id}))
    assert resp["error"]["code"] == INVALID_PARAMS
    assert env.service.calls == []


async def test_unanchored_regex_cannot_be_partially_matched(env):
    env.registry.get_tool("ha_get_state").args["entity_id"].validate = r"[a-z]+\.[a-z]+"
    (resp,) = await _session(env, _req("ha_get_state", {"entity_id": "sensor.temp_x9"}))
    assert resp["error"]["code"] == INVALID_PARAMS


async def test_undeclared_arg_rejected(env):
    args = {"domain": "light", "service": "turn_on", "entity_id": "light.a", "extra": "x"}
    (resp,) = await _session(env, _req("ha_call_service", args))
    assert resp["error"]["code"] == INVALID_PARAMS
    assert env.channel.sent == []


async def test_undeclared_arg_on_arg_less_tool_rejected(env):
    (resp,) = await _session(env, _req("ha_get_states", {"x": "y"}))
    assert resp["error"]["code"] == INVALID_PARAMS


async def test_nested_forbidden_chars_rejected(env):
    args = {"template": {"k": ["a*b"]}}
    (resp,) = await _session(env, _req("ha_render_template", args))
    assert resp["error"]["code"] == INVALID_PARAMS


async def test_nested_value_in_signature_arg_rejected(env):
    (resp,) = await _session(env, _req("ha_render_template", {"template": ["x"]}))
    assert resp["error"]["code"] == INVALID_PARAMS


async def test_deny_rule_cannot_be_dodged_by_non_string(env):
    args = {"domain": "lock", "service": ["unlock"], "entity_id": "lock.front_door"}
    (resp,) = await _session(env, _req("ha_call_service", args))
    assert resp["error"]["code"] == INVALID_PARAMS
    assert env.channel.sent == []


class _Resp:
    status = 200

    async def json(self):
        return {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        ("a/b", "a%2Fb"),
        ("a?b=c", "a%3Fb%3Dc"),
        ("a#b", "a%23b"),
        ("a%2Fb", "a%252Fb"),
        ("a b", "a%20b"),
    ],
)
def test_path_args_percent_encoded_as_single_segment(value, encoded):
    path = GenericHTTPService._interpolate_path("/api/states/{entity_id}", {"entity_id": value})
    assert path == f"/api/states/{encoded}"


@pytest.mark.parametrize("value", [".", ".."])
def test_dot_segments_rejected_in_path(value):
    with pytest.raises(HTTPServiceError):
        GenericHTTPService._interpolate_path("/api/states/{entity_id}", {"entity_id": value})


def test_missing_path_arg_is_error_not_empty_segment():
    with pytest.raises(HTTPServiceError):
        GenericHTTPService._interpolate_path("/api/states/{entity_id}", {})


# --- auth ------------------------------------------------------------


async def test_wrong_token_rejected(env):
    ws = FakeWS()
    ws.put(_auth("wrong"))
    await env.gateway.handle_connection(ws)
    assert ws.sent[0]["error"]["code"] == NOT_AUTHENTICATED
    assert ws.closed


@pytest.mark.parametrize("token", [None, 123, ["x"], {"a": 1}, TOKEN + "x", TOKEN[:-1]])
async def test_odd_tokens_rejected(env, token):
    ws = FakeWS()
    ws.put({"jsonrpc": "2.0", "method": "auth", "params": {"token": token}, "id": "a"})
    await env.gateway.handle_connection(ws)
    assert ws.sent[0]["error"]["code"] == NOT_AUTHENTICATED


async def test_non_ascii_token_rejected_without_crash(env):
    ws = FakeWS()
    ws.put(_auth("tökén-ü"))
    await env.gateway.handle_connection(ws)
    assert ws.sent[0]["error"]["code"] == NOT_AUTHENTICATED


@pytest.mark.parametrize("params", [None, "x", [1]])
async def test_non_object_auth_params_rejected(env, params):
    ws = FakeWS()
    ws.put({"jsonrpc": "2.0", "method": "auth", "params": params, "id": "a"})
    await env.gateway.handle_connection(ws)
    assert ws.sent[0]["error"]["code"] == NOT_AUTHENTICATED


async def test_unauthenticated_connection_does_not_take_slot(env):
    squatter = FakeWS()  # connects, never authenticates
    squat_task = asyncio.create_task(env.gateway.handle_connection(squatter))
    await asyncio.sleep(0.05)

    real = FakeWS()
    real.put(_auth())
    real.put(_req("ha_get_state", {"entity_id": "sensor.temp"}))
    await env.gateway.handle_connection(real)
    assert real.close_code != 4000
    assert real.sent[0]["result"]["status"] == "authenticated"
    assert real.sent[1]["result"]["status"] == "executed"
    squat_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await squat_task


async def test_failed_auth_does_not_free_the_real_agents_slot(env):
    first = FakeWS()
    first.put(_auth())
    first_task = asyncio.create_task(env.gateway.handle_connection(first))
    await asyncio.sleep(0.05)

    intruder = FakeWS()
    intruder.put(_auth("wrong"))
    await env.gateway.handle_connection(intruder)

    second = FakeWS()
    second.put(_auth())
    await env.gateway.handle_connection(second)
    assert second.close_code == 4000  # slot still held by the real agent
    first_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await first_task


# --- channel send failure -------------------------------------------


async def test_send_failure_deletes_pending_and_answers_agent(env):
    env.channel.send_error = RuntimeError("telegram down")
    args = {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom"}
    (resp,) = await _session(env, _req("ha_call_service", args))
    assert resp["id"] == "r1"
    assert resp["error"]["code"] == APPROVAL_UNAVAILABLE
    assert env.service.calls == []
    assert env.gateway._pending == {}
    (entry,) = await env.db.get_audit_log()
    assert entry.resolution == "send_failed"
    conn = env.db._get_conn()
    async with conn.execute("SELECT COUNT(*) FROM pending_requests") as cur:
        assert (await cur.fetchone())[0] == 0
