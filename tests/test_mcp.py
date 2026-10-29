"""Tests for the MCP frontend: real Pipeline, engine, registry, executor and DB.

Only the HTTP client, the approval channel and the upstream service are fakes.
"""

from __future__ import annotations

import asyncio
import gc
import json
from typing import Any

import pytest
from aiohttp.test_utils import TestClient, TestServer

from agentpass.agents import AgentIdentity, AgentRegistry, generate_token
from agentpass.config import (
    ArgDefinition,
    PermissionRule,
    Permissions,
    RequestDefinition,
    ToolDefinition,
)
from agentpass.db import Database
from agentpass.engine import PermissionEngine
from agentpass.executor import Executor
from agentpass.mcp import McpServer
from agentpass.pipeline import (
    ApprovalDenied,
    ApprovalTimeout,
    ApprovalUnavailable,
    ExecutionFailed,
    InvalidParams,
    Pipeline,
    PolicyDenied,
    RateLimited,
    ServiceUnauthorized,
    UnknownTool,
)
from agentpass.registry import ToolRegistry
from agentpass.services.base import ServiceHandler, ServiceUnauthorizedError
from tests.fakes import FakeChannel, make_coordinator


class FakeService(ServiceHandler):
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail: Exception | None = None

    async def execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, args))
        if self.fail:
            raise self.fail
        return {"ok": True, "tool": tool_name}

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


def _rules(*pairs: tuple[str, str]) -> Permissions:
    return Permissions(defaults=[], rules=[PermissionRule(pattern=p, action=a) for p, a in pairs])


def _tools() -> dict[str, ToolDefinition]:
    entity = {"entity_id": ArgDefinition(required=True, validate="[a-z_.]+")}
    return {
        "ha_get_state": ToolDefinition(
            name="ha_get_state",
            service_name="svc",
            description="Read a state",
            signature="{entity_id}",
            args=entity,
            request=RequestDefinition(method="GET", path="/s/{entity_id}"),
        ),
        "ha_call_service": ToolDefinition(
            name="ha_call_service",
            service_name="svc",
            signature="{entity_id}",
            args=entity,
            request=RequestDefinition(method="POST", path="/c"),
        ),
        "ha_delete": ToolDefinition(
            name="ha_delete",
            service_name="svc",
            signature="{entity_id}",
            args=entity,
            request=RequestDefinition(method="DELETE", path="/d"),
        ),
        "secret_tool": ToolDefinition(name="secret_tool", service_name="svc"),
    }


def _identity(agent_id: str, permissions: Permissions, registry: ToolRegistry):
    token, token_hash = generate_token(agent_id)
    identity = AgentIdentity(
        id=agent_id,
        token_hash=token_hash.removeprefix("sha256:"),
        permissions=permissions,
        engine=PermissionEngine(permissions, registry=registry),
    )
    return identity, token


class Env:
    def __init__(self) -> None:
        self.service = FakeService()
        self.channel = FakeChannel()

    async def answer(self, action: str = "allow") -> str:
        for _ in range(200):
            if self.channel.sent:
                break
            await asyncio.sleep(0.01)
        rid = self.channel.last_request.approval_id
        await self.channel.answer(rid, action == "allow", "42")
        return rid


@pytest.fixture()
async def env(tmp_path):
    e = Env()
    registry = ToolRegistry(_tools())
    e.db = Database(str(tmp_path / "t.db"))
    await e.db.initialize()
    alice, e.alice_token = _identity(
        "alice",
        _rules(
            ("ha_get_state(*)", "allow"),
            ("ha_delete*", "deny"),
            ("secret_tool*", "deny"),
            ("ha_call_service(*)", "ask"),
        ),
        registry,
    )
    bob, e.bob_token = _identity("bob", _rules(("*", "allow")), registry)
    e.agents = AgentRegistry([alice, bob])
    e.pipeline = Pipeline(
        engine=PermissionEngine(_rules(), registry=registry),
        executor=Executor({"svc": e.service}, registry),
        coordinator=make_coordinator(e.db, e.channel),
        db=e.db,
        approval_timeout=30,
        registry=registry,
    )
    e.mcp = McpServer(
        pipeline=e.pipeline, agents=e.agents, registry=registry, db=e.db, inline_wait=0.2
    )
    async with TestClient(TestServer(e.mcp.build_app())) as client:
        e.client = client
        yield e
    await e.db.close()


async def rpc(env, method, params=None, token="alice", msg_id=1):
    tok = {"alice": env.alice_token, "bob": env.bob_token}.get(token, token)
    resp = await env.client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status == 200
    return await resp.json()


async def call(env, name, arguments=None, token="alice"):
    body = await rpc(env, "tools/call", {"name": name, "arguments": arguments or {}}, token)
    return body["result"]


class TestAuth:
    async def test_no_token_is_401_before_json_rpc(self, env):
        resp = await env.client.post("/mcp", data="not json at all")
        assert resp.status == 401
        assert resp.headers["WWW-Authenticate"] == "Bearer"

    async def test_bad_token_is_401_and_not_echoed(self, env):
        resp = await env.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer agp_alice_wrongwrongwrongwrong"},
        )
        assert resp.status == 401
        assert "wrongwrong" not in await resp.text()

    async def test_other_agents_token_for_wrong_id_rejected(self, env):
        swapped = env.bob_token.replace("agp_bob_", "agp_alice_")
        resp = await env.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": f"Bearer {swapped}"},
        )
        assert resp.status == 401

    async def test_initialize(self, env):
        body = await rpc(env, "initialize")
        assert body["result"]["capabilities"]["tools"] == {"listChanged": False}

    async def test_unknown_method_and_parse_error(self, env):
        assert (await rpc(env, "nope"))["error"]["code"] == -32601
        resp = await env.client.post(
            "/mcp", data="{", headers={"Authorization": f"Bearer {env.alice_token}"}
        )
        assert (await resp.json())["error"]["code"] == -32700

    def test_dashboard_app_has_no_mcp_route(self, env):
        from aiohttp import web

        from agentpass.dashboard import setup_dashboard

        app = web.Application()
        setup_dashboard(app, env.db)
        assert not any(r.resource.canonical == "/mcp" for r in app.router.routes())


class TestToolsList:
    async def test_shape(self, env):
        tools = {t["name"]: t for t in (await rpc(env, "tools/list"))["result"]["tools"]}
        state = tools["ha_get_state"]
        assert state["description"] == "Read a state"
        schema = state["inputSchema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert schema["required"] == ["entity_id"]
        assert schema["properties"]["entity_id"] == {
            "type": "string",
            "pattern": "^(?:[a-z_.]+)$",
        }
        assert state["annotations"] == {"readOnlyHint": True, "destructiveHint": False}
        # one annotations helper for both transports (schema.py): the keys are
        # always present, so a POST says readOnlyHint False explicitly
        assert tools["ha_call_service"]["annotations"] == {
            "readOnlyHint": False,
            "destructiveHint": False,
        }
        assert {"gateway_result", "gateway_pending", "gateway_audit"} <= set(tools)

    async def test_denied_tool_is_absent(self, env):
        alice = {t["name"] for t in (await rpc(env, "tools/list"))["result"]["tools"]}
        assert "ha_delete" not in alice and "secret_tool" not in alice
        assert "ha_get_state" in alice and "ha_call_service" in alice
        bob = {t["name"] for t in (await rpc(env, "tools/list", token="bob"))["result"]["tools"]}
        assert {"ha_delete", "secret_tool"} <= bob

    async def test_delete_is_destructive_for_agent_that_may_use_it(self, env):
        listing = (await rpc(env, "tools/list", token="bob"))["result"]["tools"]
        tools = {t["name"]: t for t in listing}
        assert tools["ha_delete"]["annotations"] == {
            "readOnlyHint": False,
            "destructiveHint": True,
        }

    async def test_denied_tool_call_still_blocked(self, env):
        result = await call(env, "ha_delete", {"entity_id": "a.b"})
        assert result["isError"] is True
        assert result["structuredContent"]["error"]["code"] == "policy_denied"
        assert env.service.calls == []


class TestToolsCall:
    async def test_allow(self, env):
        result = await call(env, "ha_get_state", {"entity_id": "sensor.t"})
        assert "isError" not in result
        data = result["structuredContent"]
        assert data["status"] == "executed" and data["data"]["ok"] is True
        assert env.service.calls == [("ha_get_state", {"entity_id": "sensor.t"})]

    async def test_ask_approved_inline(self, env):
        task = asyncio.create_task(call(env, "ha_call_service", {"entity_id": "light.a"}))
        await env.answer("allow")
        result = await task
        assert result["structuredContent"]["status"] == "executed"
        assert env.service.calls == [("ha_call_service", {"entity_id": "light.a"})]

    async def test_ask_denied_inline(self, env):
        task = asyncio.create_task(call(env, "ha_call_service", {"entity_id": "light.a"}))
        await env.answer("deny")
        result = await task
        assert result["isError"] is True
        assert result["structuredContent"]["error"]["code"] == "approval_denied"
        assert env.service.calls == []

    async def test_invalid_args_and_unknown_tool(self, env):
        r = await call(env, "ha_get_state", {"entity_id": "BAD"})
        assert r["structuredContent"]["error"]["code"] == "invalid_params"
        r = await call(env, "nope")
        assert r["structuredContent"]["error"]["code"] == "unknown_tool"

    async def test_service_unauthorized_code(self, env):
        env.service.fail = ServiceUnauthorizedError("Service authentication failed")
        r = await call(env, "ha_get_state", {"entity_id": "a.b"})
        assert r["structuredContent"]["error"]["code"] == "service_unauthorized"

    async def test_execution_failed_hides_upstream_detail(self, env):
        env.service.fail = RuntimeError("upstream said: token=abc123")
        r = await call(env, "ha_get_state", {"entity_id": "a.b"})
        assert r["structuredContent"]["error"]["code"] == "execution_failed"
        assert "abc123" not in str(r)

    async def test_rate_limited(self, env):
        env.pipeline._rate_limiters["alice"] = type(
            "L", (), {"check": staticmethod(lambda: False)}
        )()
        r = await call(env, "ha_get_state", {"entity_id": "a.b"})
        assert r["structuredContent"]["error"]["code"] == "rate_limited"

    async def test_no_channel(self, env):
        env.channel.send_error = RuntimeError("telegram down")
        r = await call(env, "ha_call_service", {"entity_id": "light.a"})
        assert r["structuredContent"]["error"]["code"] == "no_channel"

    async def test_idempotency_key_asks_once(self, env):
        args = {"entity_id": "light.a", "idempotency_key": "k1"}
        first = await call(env, "ha_call_service", args)
        assert first["structuredContent"]["status"] == "pending_approval"
        second = await call(env, "ha_call_service", args)
        assert second["structuredContent"]["request_id"] == first["structuredContent"]["request_id"]
        assert len(env.channel.sent) == 1
        await env.answer("allow")
        await asyncio.sleep(0.05)
        third = await call(env, "ha_call_service", args)
        assert third["structuredContent"]["status"] == "executed"
        assert len(env.service.calls) == 1

    async def test_idempotency_key_reuse_with_other_args_rejected(self, env):
        await call(env, "ha_get_state", {"entity_id": "a.b", "idempotency_key": "k"})
        r = await call(env, "ha_get_state", {"entity_id": "c.d", "idempotency_key": "k"})
        assert r["structuredContent"]["error"]["code"] == "invalid_params"

    async def test_idempotency_is_per_agent(self, env):
        await call(env, "ha_get_state", {"entity_id": "a.b", "idempotency_key": "k"})
        await call(env, "ha_get_state", {"entity_id": "a.b", "idempotency_key": "k"}, token="bob")
        assert len(env.service.calls) == 2


class TestPendingThenResult:
    async def _pend(self, env):
        r = await call(env, "ha_call_service", {"entity_id": "light.a"})
        data = r["structuredContent"]
        assert "isError" not in r  # a normal result, not an error
        assert data["status"] == "pending_approval"
        assert data["retry"] == "call gateway_result" and data["expires_at"]
        return data["request_id"]

    async def test_pending_then_approved(self, env):
        rid = await self._pend(env)
        still = (await call(env, "gateway_result", {"request_id": rid}))["structuredContent"]
        assert still["status"] == "pending_approval"
        waiter = asyncio.create_task(
            call(env, "gateway_result", {"request_id": rid, "wait_seconds": 5})
        )
        await env.answer("allow")
        done = (await waiter)["structuredContent"]
        assert done["status"] == "executed" and done["data"]["ok"] is True
        again = (await call(env, "gateway_result", {"request_id": rid}))["structuredContent"]
        assert again["status"] == "executed"
        assert len(env.service.calls) == 1
        await asyncio.sleep(0.05)
        row = await env.db.get_pending(rid)  # kept (24 h) so a later fetch still works
        assert json.loads(row["result"])["status"] == "executed"

    async def test_pending_then_denied(self, env):
        rid = await self._pend(env)
        await env.answer("deny")
        await asyncio.sleep(0.05)
        res = (await call(env, "gateway_result", {"request_id": rid}))["structuredContent"]
        assert res["status"] == "denied"
        assert res["error"]["code"] == "approval_denied"
        assert env.service.calls == []

    async def test_other_agents_result_is_invisible(self, env):
        rid = await self._pend(env)
        r = await call(env, "gateway_result", {"request_id": rid}, token="bob")
        assert r["isError"] is True
        assert r["structuredContent"]["error"]["code"] == "unknown_request"

    async def test_gateway_pending_is_own_only(self, env):
        rid = await self._pend(env)
        mine = (await call(env, "gateway_pending"))["structuredContent"]["pending"]
        assert [p["request_id"] for p in mine] == [rid]
        other = await call(env, "gateway_pending", token="bob")
        assert other["structuredContent"]["pending"] == []


class TestGatewayAudit:
    async def test_audit_is_own_rows_only(self, env):
        await call(env, "ha_get_state", {"entity_id": "a.b"})
        await call(env, "ha_get_state", {"entity_id": "c.d"}, token="bob")
        await call(env, "ha_delete", {"entity_id": "c.d"}, token="bob")
        alice = (await call(env, "gateway_audit"))["structuredContent"]["entries"]
        assert [e["signature"] for e in alice] == ["ha_get_state(a.b)"]
        bob = (await call(env, "gateway_audit", token="bob"))["structuredContent"]["entries"]
        assert len(bob) == 2
        assert "args" not in alice[0] and "execution_result" not in alice[0]

    async def test_audit_limit_validated(self, env):
        r = await call(env, "gateway_audit", {"limit": 0})
        assert r["structuredContent"]["error"]["code"] == "invalid_params"


class TestTimeoutAfterLeavingTheRequest:
    async def test_timeout_after_pending_is_stored_and_never_left_unretrieved(self, env):
        env.pipeline._approval_timeout = 1
        loop = asyncio.get_running_loop()
        unhandled: list[dict] = []
        loop.set_exception_handler(lambda _loop, ctx: unhandled.append(ctx))
        try:
            r = await call(env, "ha_call_service", {"entity_id": "light.a"})
            rid = r["structuredContent"]["request_id"]
            assert r["structuredContent"]["status"] == "pending_approval"
            res = (await call(env, "gateway_result", {"request_id": rid, "wait_seconds": 5}))[
                "structuredContent"
            ]
            assert res["status"] == "timeout" and res["error"]["code"] == "approval_timeout"
            await asyncio.sleep(0.05)
            assert not env.mcp._tasks
            gc.collect()  # "Task exception was never retrieved" is reported on collection
            await asyncio.sleep(0)
        finally:
            loop.set_exception_handler(None)
        assert unhandled == []

    async def test_run_call_returns_a_pipeline_error_instead_of_raising(self, env):
        env.pipeline._approval_timeout = 1
        task = asyncio.create_task(
            env.mcp._run_call(
                env.agents.get("alice"),
                "ha_call_service",
                {"entity_id": "x.y"},
                None,
                lambda *_: None,
            )
        )
        result = await task
        assert type(result).__name__ == "ApprovalTimeout" and result.request_id
        row = await env.db.get_pending(result.request_id)
        assert row is not None  # stored for a later gateway_result


class TestErrorCodes:
    def test_one_table_covers_every_stable_code(self):
        classes = [
            InvalidParams, UnknownTool, PolicyDenied, ApprovalDenied, ApprovalTimeout,
            ApprovalUnavailable, RateLimited, ExecutionFailed, ServiceUnauthorized,
        ]  # fmt: skip
        assert {c.code for c in classes} == {
            "invalid_params",
            "unknown_tool",
            "policy_denied",
            "approval_denied",
            "approval_timeout",
            "no_channel",
            "rate_limited",
            "execution_failed",
            "service_unauthorized",
        }


class TestSchemaHelper:
    def test_missing_type_is_string_and_validate_is_anchored(self):
        from agentpass.schema import input_schema

        schema = input_schema(
            {"a": ArgDefinition(required=True), "b": ArgDefinition(validate="x+")}
        )
        assert schema["properties"]["a"] == {"type": "string"}
        assert schema["properties"]["b"]["pattern"] == "^(?:x+)$"
        assert schema["required"] == ["a"]


class TestMayPermit:
    def test_cases(self):
        e = PermissionEngine(_rules(("a_*", "deny"), ("b(x*)", "allow")))
        assert not e.may_permit("a_tool")
        assert e.may_permit("b")  # an allow rule might match some args
        assert e.may_permit("c")  # fallback is ask
        d = PermissionEngine(
            Permissions(
                defaults=[PermissionRule("*", "deny")], rules=_rules(("c(1)", "allow")).rules
            )
        )
        assert d.may_permit("c") and not d.may_permit("z")


# --- Restart: the database, not memory, answers gateway_result and idempotency ---


class Instance:
    """A gateway "process": fresh Pipeline + McpServer + HTTP app over a shared DB file."""

    def __init__(self, path, tokens_env, approval_timeout=30):
        self.path = path
        self.approval_timeout = approval_timeout
        self.base = tokens_env

    async def start(self):
        e = Env()
        registry = ToolRegistry(_tools())
        e.db = Database(self.path)
        await e.db.initialize()
        e.agents = self.base.agents
        e.alice_token, e.bob_token = self.base.alice_token, self.base.bob_token
        e.pipeline = Pipeline(
            engine=PermissionEngine(_rules(), registry=registry),
            executor=Executor({"svc": e.service}, registry),
            coordinator=make_coordinator(e.db, e.channel),
            db=e.db,
            approval_timeout=self.approval_timeout,
            registry=registry,
        )
        mcp = McpServer(
            pipeline=e.pipeline, agents=e.agents, registry=registry, db=e.db, inline_wait=0.1
        )
        e.client = TestClient(TestServer(mcp.build_app()))
        await e.client.start_server()
        self.env = e
        return e

    async def stop(self):
        await self.env.client.close()
        await self.env.db.close()


@pytest.fixture()
async def restartable(env, tmp_path):
    inst = Instance(str(tmp_path / "restart.db"), env)
    first = await inst.start()
    state = {"inst": inst, "env": first}

    async def restart(*, settle=False, approval_timeout=None):
        await state["inst"].stop()
        if approval_timeout is not None:
            inst.approval_timeout = approval_timeout
        state["env"] = await inst.start()
        if settle:
            await state["env"].db.settle_orphans()
        return state["env"]

    yield first, restart
    await state["inst"].stop()


async def _ask(env, args=None):
    r = await call(env, "ha_call_service", {"entity_id": "light.a", **(args or {})})
    return r["structuredContent"]


class TestRestart:
    async def test_pending_survives_restart(self, restartable):
        env, restart = restartable
        pend = await _ask(env)
        env2 = await restart()
        res = (await call(env2, "gateway_result", {"request_id": pend["request_id"]}))[
            "structuredContent"
        ]
        assert res["status"] == "pending_approval"
        assert res["request_id"] == pend["request_id"] and res["expires_at"]

    async def test_orphaned_pending_is_settled_at_startup(self, restartable):
        env, restart = restartable
        pend = await _ask(env)
        env2 = await restart(settle=True)  # what __main__ does after a crash
        res = (await call(env2, "gateway_result", {"request_id": pend["request_id"]}))[
            "structuredContent"
        ]
        assert res["status"] == "denied" and res["error"]["code"] == "approval_denied"
        assert env2.service.calls == []

    async def test_executed_survives_restart(self, restartable):
        env, restart = restartable
        pend = await _ask(env)
        await env.answer("allow")
        await asyncio.sleep(0.1)
        env2 = await restart()
        res = (await call(env2, "gateway_result", {"request_id": pend["request_id"]}))[
            "structuredContent"
        ]
        assert res["status"] == "executed" and res["data"]["ok"] is True
        assert env2.service.calls == []  # not re-executed

    async def test_result_stored_when_nobody_is_waiting(self, restartable):
        env, _restart = restartable
        pend = await _ask(env)  # inline wait is over, the HTTP request is gone
        await env.answer("allow")
        await asyncio.sleep(0.1)
        row = await env.db.get_pending(pend["request_id"])
        assert json.loads(row["result"])["status"] == "executed"

    async def test_denied_survives_restart(self, restartable):
        env, restart = restartable
        pend = await _ask(env)
        await env.answer("deny")
        await asyncio.sleep(0.1)
        env2 = await restart()
        res = (await call(env2, "gateway_result", {"request_id": pend["request_id"]}))[
            "structuredContent"
        ]
        assert res["status"] == "denied" and res["error"]["code"] == "approval_denied"

    async def test_timeout_survives_restart(self, restartable):
        env, restart = restartable
        env = await restart(approval_timeout=1)
        pend = await _ask(env)
        await asyncio.sleep(1.3)
        env2 = await restart()
        res = (await call(env2, "gateway_result", {"request_id": pend["request_id"]}))[
            "structuredContent"
        ]
        assert res["status"] == "timeout" and res["error"]["code"] == "approval_timeout"

    async def test_expired_unanswered_row_reports_timeout(self, restartable):
        env, _ = restartable
        await env.db.insert_pending(
            "old-req", "ha_call_service", {}, "ha_call_service", "2020-01-01T00:00:00Z", "alice"
        )
        res = (await call(env, "gateway_result", {"request_id": "old-req"}))["structuredContent"]
        assert res["status"] == "timeout"

    async def test_agent_scoped_lookup_after_restart(self, restartable):
        env, restart = restartable
        pend = await _ask(env)
        env2 = await restart()
        r = await call(env2, "gateway_result", {"request_id": pend["request_id"]}, token="bob")
        assert r["isError"] is True
        assert r["structuredContent"]["error"]["code"] == "unknown_request"
        missing = await call(env2, "gateway_result", {"request_id": "nope"})
        assert missing["structuredContent"]["error"]["code"] == "unknown_request"

    async def test_results_expire_after_24h(self, restartable):
        env, _ = restartable
        pend = await _ask(env)
        await env.answer("allow")
        await asyncio.sleep(0.1)
        await env.db._get_conn().execute(
            "UPDATE pending_requests SET created_at = '2020-01-01T00:00:00Z'"
        )
        r = await call(env, "gateway_result", {"request_id": pend["request_id"]})
        assert r["structuredContent"]["error"]["code"] == "unknown_request"

    async def test_idempotency_key_survives_restart(self, restartable):
        env, restart = restartable
        args = {"idempotency_key": "k9"}
        first = await _ask(env, args)
        await env.answer("allow")
        await asyncio.sleep(0.1)
        env2 = await restart()
        again = await _ask(env2, args)
        assert again["status"] == "executed"
        assert again["request_id"] == first["request_id"]
        assert len(env2.channel.sent) == 0  # owner not asked again
        assert env2.service.calls == []

    async def test_pending_idempotent_call_after_crash_asks_afresh(self, restartable):
        env, restart = restartable
        args = {"idempotency_key": "k10"}
        await _ask(env, args)
        env2 = await restart(settle=True)
        again = await _ask(env2, args)
        assert again["status"] == "pending_approval"
        assert len(env2.channel.sent) == 1

    async def test_idempotency_key_other_args_rejected_after_restart(self, restartable):
        env, restart = restartable
        await _ask(env, {"idempotency_key": "k11"})
        await env.answer("allow")
        await asyncio.sleep(0.1)
        env2 = await restart()
        r = await call(env2, "ha_call_service", {"entity_id": "light.b", "idempotency_key": "k11"})
        assert r["structuredContent"]["error"]["code"] == "invalid_params"


class TestSchemaV2:
    async def test_v1_database_migrates_and_keeps_data(self, tmp_path):
        import sqlite3

        path = str(tmp_path / "v1.db")
        db = Database(path)
        await db.initialize()
        await db.insert_pending("r1", "t", {}, "t", "2099-01-01T00:00:00Z", "alice")
        await db.close()
        con = sqlite3.connect(path)
        con.execute("DROP TABLE idempotency_keys")
        con.execute("PRAGMA user_version = 1")
        con.commit()
        con.close()
        db = Database(path)
        await db.initialize()
        await db.put_idempotency("alice", "k", "t", "{}")
        assert (await db.get_idempotency("alice", "k"))["tool_name"] == "t"
        assert await db.get_pending("r1") is not None
        await db.close()
