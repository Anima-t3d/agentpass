"""agent_note: a gateway-added property, popped at the adapter, never part of the call."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from agentpass.config import AuthConfig, ServiceConfig, load_tools_file
from agentpass.engine import build_signature, validate_args
from agentpass.passkey.verify import approval_challenge
from agentpass.pipeline import InvalidParams, Outcome, Pipeline
from agentpass.registry import build_registry
from agentpass.remembered import args_hash
from tests import test_mcp
from tests.fakes import FakeChannel
from tests.test_mcp import call, rpc
from tests.test_server import MockWebSocket, _auth_msg, _make_server, _tool_request_msg

env = test_mcp.env  # the MCP fixture: real Pipeline, registry, DB; fake channel and service

NOTE_DESC = (
    "Optional: explain to the human approver why you need this call. "
    "Shown to them as unverified agent text."
)


async def _settle(env, tries=300):
    for _ in range(tries):
        if env.channel.sent:
            return
        await asyncio.sleep(0.01)


class TestSchemas:
    async def test_every_yaml_tool_has_the_property_gateway_tools_do_not(self, env):
        tools = (await rpc(env, "tools/list"))["result"]["tools"]
        for tool in tools:
            props = tool["inputSchema"]["properties"]
            if tool["name"].startswith("gateway_"):
                assert "agent_note" not in props
            else:
                assert props["agent_note"] == {
                    "type": "string",
                    "maxLength": 500,
                    "description": NOTE_DESC,
                }
                assert "agent_note" not in tool["inputSchema"].get("required", [])

    async def test_websocket_list_tools(self):
        tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
        svc = ServiceConfig(
            name="homeassistant",
            url="http://ha",
            auth=AuthConfig(type="bearer", token="x"),
            tools=tools,
        )
        server = _make_server(registry=build_registry({"homeassistant": svc}))
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue({"jsonrpc": "2.0", "method": "list_tools", "params": {}, "id": "lt"})
        await server.handle_connection(ws)
        [resp] = [r for r in ws.get_responses() if r.get("id") == "lt"]
        assert resp["result"]["tools"]
        for tool in resp["result"]["tools"]:
            assert tool["inputSchema"]["properties"]["agent_note"]["description"] == NOTE_DESC
            assert "agent_note" not in tool["args"]  # not a declared arg


class TestStripping:
    """A call with a note is indistinguishable from one without, except for the note."""

    @pytest.mark.parametrize("tool_args", [{"entity_id": "light.a"}, {"entity_id": "lock.front"}])
    async def test_mcp_call_is_identical_apart_from_the_note(self, env, tool_args):
        await call(env, "ha_call_service", tool_args)
        await _settle(env)
        plain = env.channel.last_request
        await env.answer("allow")
        await asyncio.sleep(0.05)

        env.channel.sent.clear()
        await call(env, "ha_call_service", {**tool_args, "agent_note": "because I was asked"})
        await _settle(env)
        noted = env.channel.last_request
        await env.answer("allow")
        await asyncio.sleep(0.05)

        assert noted.agent_note == "because I was asked" and plain.agent_note is None
        assert noted.args == plain.args == tool_args
        assert noted.signature == plain.signature
        assert noted.remember == plain.remember
        assert args_hash(noted.args) == args_hash(plain.args)
        assert approval_challenge("id", "alice", noted.tool, noted.args, 1000) == (
            approval_challenge("id", "alice", plain.tool, plain.args, 1000)
        )
        # the upstream request saw no note, in either call
        assert [a for _, a in env.service.calls] == [tool_args, tool_args]

    async def test_websocket_adapter_pops_before_the_pipeline(self):
        server = _make_server()
        server._pipeline.process = AsyncMock(return_value=Outcome(request_id="r", data={}))
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        msg = _tool_request_msg("t", {"entity_id": "a.b", "agent_note": "  why\nnot "})
        ws.enqueue(msg)
        await server.handle_connection(ws)
        [call_] = server._pipeline.process.await_args_list
        assert call_.args[2] == {"entity_id": "a.b"}
        assert call_.kwargs["agent_note"] == "why not"
        assert msg["params"]["args"]["agent_note"]  # the caller's dict is untouched

    async def test_websocket_rejects_a_non_string_note(self):
        server = _make_server()
        server._pipeline.process = AsyncMock()
        ws = MockWebSocket()
        ws.enqueue(_auth_msg())
        ws.enqueue(_tool_request_msg("t", {"agent_note": 5}))
        await server.handle_connection(ws)
        server._pipeline.process.assert_not_awaited()
        assert ws.last_response()["error"]["code"] == -32602

    async def test_bare_agent_note_in_pipeline_args_is_an_undeclared_arg(self, env):
        registry = env.pipeline._registry
        with pytest.raises(ValueError, match="Unknown argument: agent_note"):
            validate_args("ha_call_service", {"entity_id": "a.b", "agent_note": "x"}, registry)
        with pytest.raises(InvalidParams):
            await env.pipeline.process(
                "bob", "ha_call_service", {"entity_id": "a", "agent_note": "x"}
            )
        assert (
            build_signature("ha_call_service", {"entity_id": "a.b"}, registry)
            == "ha_call_service(a.b)"
        )


class TestSanitiseAtTheAdapter:
    async def test_non_string_is_invalid_params_and_nothing_runs(self, env):
        r = await call(env, "ha_call_service", {"entity_id": "a.b", "agent_note": ["x"]})
        assert r["structuredContent"]["error"]["code"] == "invalid_params"
        assert not env.channel.sent and not env.service.calls

    async def test_long_and_hostile_note_is_cleaned(self, env):
        note = "‮" + "ab\x00\n" * 5000
        await call(env, "ha_call_service", {"entity_id": "a.b", "agent_note": note})
        await _settle(env)
        shown = env.channel.last_request.agent_note
        assert len(shown) == 500 and shown.endswith("…")
        assert not any(c in shown for c in "‮\x00\n")
        await env.answer("deny")

    async def test_blank_note_becomes_none(self, env):
        await call(env, "ha_call_service", {"entity_id": "a.b", "agent_note": " \n "})
        await _settle(env)
        assert env.channel.last_request.agent_note is None
        await env.answer("deny")


class TestAuditAndReplay:
    async def test_audit_row_holds_the_sanitised_note(self, env):
        await call(env, "ha_call_service", {"entity_id": "a.b", "agent_note": "fix\tit"})
        await _settle(env)
        await env.answer("allow")
        await asyncio.sleep(0.05)
        entry = next(e for e in await env.db.get_audit_log() if e.tool_name == "ha_call_service")
        assert entry.agent_note == "fix it"

    async def test_replay_with_another_note_joins_and_keeps_the_first(self, env):
        base = {"entity_id": "light.a", "idempotency_key": "k9"}
        first = await call(env, "ha_call_service", {**base, "agent_note": "first"})
        second = await call(env, "ha_call_service", {**base, "agent_note": "reworded"})
        assert second["structuredContent"]["request_id"] == first["structuredContent"]["request_id"]
        assert len(env.channel.sent) == 1 and env.channel.last_request.agent_note == "first"
        await env.answer("allow")
        await asyncio.sleep(0.05)
        entries = [e for e in await env.db.get_audit_log() if e.tool_name == "ha_call_service"]
        assert [e.agent_note for e in entries] == ["first"]


class TestNeverReachesNotifyChannels:
    async def test_notify_channel_gets_no_note(self, env):
        hook = FakeChannel("hook", trust="notify")
        coordinator = env.pipeline._coordinator
        coordinator._channels["hook"] = coordinator._active["hook"] = hook
        hook.sink = coordinator
        await call(env, "ha_call_service", {"entity_id": "a.b", "agent_note": "secret reason"})
        await _settle(env)
        assert hook.last_request.agent_note is None and hook.last_request.preview is None
        await env.answer("deny")


async def test_remembered_exact_rule_ignores_the_note(tmp_path):
    from agentpass.config import ArgDefinition, PermissionRule, Permissions, ToolDefinition
    from agentpass.db import Database
    from agentpass.engine import PermissionEngine
    from agentpass.executor import Executor
    from agentpass.registry import ToolRegistry
    from agentpass.remembered import RememberedService
    from tests.fakes import started_coordinator

    tool = ToolDefinition(
        name="lowt",
        service_name="svc",
        signature="{q}",
        args={"q": ArgDefinition(required=True)},
        risk="low",
    )
    registry = ToolRegistry({"lowt": tool})
    db = Database(str(tmp_path / "t.db"))
    await db.initialize()
    remembered = RememberedService(db, registry)
    channel = FakeChannel()
    executor = AsyncMock(spec=Executor)
    executor.execute.return_value = {"ok": True}
    pipeline = Pipeline(
        engine=PermissionEngine(
            Permissions(defaults=[PermissionRule("*", "ask")], rules=[]), registry
        ),
        executor=executor,
        coordinator=await started_coordinator(db, channel, remembered=remembered),
        db=db,
        registry=registry,
        remembered=remembered,
    )
    task = asyncio.create_task(pipeline.process("bot", "lowt", {"q": "x"}, agent_note="note A"))
    for _ in range(300):
        if channel.sent:
            break
        await asyncio.sleep(0.01)
    await channel.answer(channel.last_request.approval_id, approved=True, remember="exact")
    await task
    sent = len(channel.sent)
    out = await pipeline.process("bot", "lowt", {"q": "x"}, agent_note="note B")
    assert out.data == {"ok": True} and len(channel.sent) == sent  # matched: no prompt
    out = await pipeline.process("bot", "lowt", {"q": "x"})
    assert out.data == {"ok": True} and len(channel.sent) == sent
    await db.close()
