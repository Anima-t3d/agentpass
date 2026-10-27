"""Tests for agentpass.models — shared data models."""

import asyncio
import time

from agentpass.models import (
    AuditEntry,
    Decision,
    PendingApproval,
    ToolRequest,
)


class TestDecision:
    def test_enum_values(self):
        assert Decision.ALLOW.value == "allow"
        assert Decision.DENY.value == "deny"
        assert Decision.ASK.value == "ask"

    def test_from_string(self):
        assert Decision("allow") is Decision.ALLOW
        assert Decision("deny") is Decision.DENY
        assert Decision("ask") is Decision.ASK


class TestToolRequest:
    def test_construction(self):
        req = ToolRequest(id="req-1", tool_name="ha_get_state", args={"entity_id": "sensor.temp"})
        assert req.id == "req-1"
        assert req.tool_name == "ha_get_state"
        assert req.args == {"entity_id": "sensor.temp"}

    def test_signature_default_empty(self):
        req = ToolRequest(id="req-1", tool_name="test", args={})
        assert req.signature == ""

    def test_args_is_dict(self):
        req = ToolRequest(id="req-1", tool_name="test", args={"a": 1, "b": "two"})
        assert isinstance(req.args, dict)


class TestPendingApproval:
    def test_construction(self):
        req = ToolRequest(id="req-1", tool_name="test", args={})
        loop = asyncio.new_event_loop()
        future = loop.create_future()
        before = time.time()
        pending = PendingApproval(request=req, future=future)
        after = time.time()
        assert pending.request is req
        assert pending.future is future
        assert before <= pending.created_at <= after
        loop.close()

    def test_defaults(self):
        req = ToolRequest(id="req-1", tool_name="test", args={})
        loop = asyncio.new_event_loop()
        future = loop.create_future()
        pending = PendingApproval(request=req, future=future)
        assert pending.future is future
        assert pending.expires_at == 0
        loop.close()


class TestAuditEntry:
    def test_construction(self):
        before = time.time()
        entry = AuditEntry(
            request_id="req-1",
            tool_name="ha_get_state",
            args={"entity_id": "sensor.temp"},
            signature="ha_get_state(sensor.temp)",
            decision="allow",
        )
        after = time.time()
        assert entry.request_id == "req-1"
        assert entry.tool_name == "ha_get_state"
        assert before <= entry.timestamp <= after

    def test_defaults(self):
        entry = AuditEntry(request_id="req-1")
        assert entry.tool_name == ""
        assert entry.args == {}
        assert entry.signature == ""
        assert entry.decision == ""
        assert entry.resolution is None
        assert entry.resolved_by is None
        assert entry.resolved_at is None
        assert entry.execution_result is None
        assert entry.agent_id == "default"
