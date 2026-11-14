"""Tests for agentpass.db — SQLite storage for audit log and pending requests."""

import json
import os
import platform
import stat
import time
from datetime import UTC, datetime

import pytest

from agentpass.db import Database
from agentpass.models import AuditEntry


@pytest.fixture()
async def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    database = Database(db_path)
    await database.initialize()
    yield database
    await database.close()


class TestInitialize:
    async def test_creates_tables(self, db):
        # Verify tables exist by querying sqlite_master
        conn = db._get_conn()
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in await cursor.fetchall()]
        assert "audit_log" in tables
        assert "pending_requests" in tables

    async def test_creates_indexes(self, db):
        conn = db._get_conn()
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        )
        indexes = [row[0] for row in await cursor.fetchall()]
        assert "idx_audit_timestamp" in indexes
        assert "idx_audit_tool" in indexes
        assert "idx_pending_expires" in indexes

    @pytest.mark.skipif(platform.system() == "Windows", reason="Unix permissions")
    async def test_file_permissions_0600(self, tmp_path):
        db_path = str(tmp_path / "perms.db")
        database = Database(db_path)
        await database.initialize()
        mode = stat.S_IMODE(os.stat(db_path).st_mode)
        assert mode == 0o600
        await database.close()


class TestAuditLog:
    async def test_log_and_query(self, db):
        entry = AuditEntry(
            request_id="req-1",
            tool_name="ha_get_state",
            args={"entity_id": "sensor.temp"},
            signature="ha_get_state(sensor.temp)",
            decision="allow",
            resolution="executed",
            resolved_by="policy",
        )
        await db.log_audit(entry)

        entries = await db.get_audit_log()
        assert len(entries) == 1
        assert isinstance(entries[0], AuditEntry)
        assert entries[0].request_id == "req-1"
        assert entries[0].tool_name == "ha_get_state"
        assert entries[0].decision == "allow"
        assert entries[0].resolution == "executed"
        assert entries[0].resolved_by == "policy"
        assert entries[0].args == {"entity_id": "sensor.temp"}
        assert entries[0].signature == "ha_get_state(sensor.temp)"

    async def test_timestamp_round_trips(self, db):
        now = time.time()
        entry = AuditEntry(request_id="req-1", timestamp=now, tool_name="test", decision="allow")
        await db.log_audit(entry)

        entries = await db.get_audit_log()
        assert isinstance(entries[0], AuditEntry)
        # Timestamps should be close (within 1 second due to ISO truncation)
        assert abs(entries[0].timestamp - now) < 1.0

    async def test_args_round_trip(self, db):
        args = {"entity_id": "sensor.temp", "extra": "val"}
        entry = AuditEntry(request_id="req-1", args=args, decision="allow")
        await db.log_audit(entry)

        entries = await db.get_audit_log()
        assert isinstance(entries[0], AuditEntry)
        assert entries[0].args == args

    async def test_reverse_chronological_order(self, db):
        for i in range(3):
            entry = AuditEntry(request_id=f"req-{i}", decision="allow")
            await db.log_audit(entry)

        entries = await db.get_audit_log()
        ids = [e.request_id for e in entries]
        assert ids == ["req-2", "req-1", "req-0"]

    async def test_limit(self, db):
        for i in range(5):
            entry = AuditEntry(request_id=f"req-{i}", decision="allow")
            await db.log_audit(entry)

        entries = await db.get_audit_log(limit=2)
        assert len(entries) == 2

    async def test_empty_audit_log(self, db):
        entries = await db.get_audit_log()
        assert entries == []

    async def test_execution_result_round_trip(self, db):
        result = {"state": "on", "attributes": {"brightness": 255}}
        entry = AuditEntry(
            request_id="req-1",
            tool_name="ha_call_service",
            decision="allow",
            execution_result=result,
        )
        await db.log_audit(entry)

        entries = await db.get_audit_log()
        assert isinstance(entries[0], AuditEntry)
        assert entries[0].execution_result == result

    async def test_resolved_at_round_trip(self, db):
        now = time.time()
        entry = AuditEntry(
            request_id="req-1",
            decision="allow",
            resolved_at=now,
        )
        await db.log_audit(entry)

        entries = await db.get_audit_log()
        assert isinstance(entries[0], AuditEntry)
        assert entries[0].resolved_at is not None
        assert abs(entries[0].resolved_at - now) < 1.0


class TestPendingRequests:
    async def test_insert_and_get(self, db):
        expires = datetime.now(UTC).isoformat()
        await db.insert_pending(
            request_id="req-1",
            tool_name="ha_call_service",
            args={"domain": "light"},
            signature="ha_call_service(light.turn_on, light.bedroom)",
            expires_at=expires,
        )
        pending = await db.get_pending("req-1")
        assert pending is not None
        assert pending["request_id"] == "req-1"
        assert pending["tool_name"] == "ha_call_service"
        assert pending["signature"] == "ha_call_service(light.turn_on, light.bedroom)"

    async def test_get_missing_returns_none(self, db):
        result = await db.get_pending("nonexistent")
        assert result is None

    async def test_delete(self, db):
        expires = datetime.now(UTC).isoformat()
        await db.insert_pending("req-1", "test", {}, "test", expires)
        await db.delete_pending("req-1")
        assert await db.get_pending("req-1") is None

    async def test_cleanup_stale_removes_expired(self, db):
        # Insert an expired request (expires_at in the past)
        past = "2020-01-01T00:00:00Z"
        await db.insert_pending("req-old", "test", {}, "test", past)

        # Insert a fresh request
        future = "2099-01-01T00:00:00Z"
        await db.insert_pending("req-new", "test", {}, "test", future)

        stale = await db.cleanup_stale_requests()
        assert len(stale) == 1
        assert stale[0]["request_id"] == "req-old"

        # Old one removed, new one remains
        assert await db.get_pending("req-old") is None
        assert await db.get_pending("req-new") is not None

    async def test_cleanup_stale_no_expired(self, db):
        future = "2099-01-01T00:00:00Z"
        await db.insert_pending("req-1", "test", {}, "test", future)
        stale = await db.cleanup_stale_requests()
        assert stale == []


class TestInterruptExecuting:
    async def test_interrupt_executing_marks_only_resolved_rows_without_result(self, db):
        future = "2099-01-01T00:00:00Z"
        for rid in ("run", "done", "wait", "gone"):
            await db.insert_pending(rid, "t", {}, "t", future)
        for rid in ("run", "done"):
            assert await db.transition_pending(rid, "resolved")
        await db.update_pending_result("done", '{"status": "executed", "data": 1}')
        await db.abandon_pending()  # "wait" and "gone" become abandoned...
        await db.insert_pending("open", "t", {}, "t", future)  # ...this one stays pending

        payload = {"status": "error", "code": "execution_interrupted", "data": "msg"}
        rows = await db.interrupt_executing(json.dumps(payload))

        assert [r["request_id"] for r in rows] == ["run"]
        stored = json.loads((await db.get_pending("run"))["result"])
        assert stored == {**payload, "request_id": "run"}
        assert json.loads((await db.get_pending("done"))["result"])["status"] == "executed"
        for rid in ("wait", "gone", "open"):
            assert (await db.get_pending(rid))["result"] is None
        assert (await db.get_pending("open"))["state"] == "pending"
        assert await db.interrupt_executing(json.dumps(payload)) == []  # idempotent


class TestUpdatePendingResult:
    async def test_stores_result_json(self, db):
        """update_pending_result writes JSON to the result column."""
        expires = "2099-01-01T00:00:00Z"
        await db.insert_pending(
            "req-1", "ha_get_state", {"entity_id": "sensor.temp"}, "sig", expires
        )

        result = {"status": "executed", "data": {"state": "on"}}
        await db.update_pending_result("req-1", json.dumps(result))

        row = await db.get_pending("req-1")
        assert row is not None
        assert row["result"] is not None
        parsed = json.loads(row["result"])
        assert parsed["status"] == "executed"
        assert parsed["data"]["state"] == "on"

    async def test_update_nonexistent_request_is_noop(self, db):
        """update_pending_result on missing request_id does not raise."""
        await db.update_pending_result("nonexistent", '{"status": "ok"}')
        # No error raised, no row to verify


class TestGetCompletedResults:
    async def test_returns_rows_with_result(self, db):
        """get_completed_results returns pending_requests where result IS NOT NULL."""
        expires = "2099-01-01T00:00:00Z"
        await db.insert_pending("req-1", "tool_a", {}, "sig_a", expires)
        await db.insert_pending("req-2", "tool_b", {}, "sig_b", expires)

        # Only req-1 has a result
        await db.update_pending_result("req-1", '{"status": "executed"}')

        completed = await db.get_completed_results()
        assert len(completed) == 1
        assert completed[0]["request_id"] == "req-1"
        assert completed[0]["result"] is not None

    async def test_returns_empty_when_no_results(self, db):
        """get_completed_results returns empty list when no results stored."""
        expires = "2099-01-01T00:00:00Z"
        await db.insert_pending("req-1", "tool_a", {}, "sig_a", expires)

        completed = await db.get_completed_results()
        assert completed == []

    async def test_returns_empty_when_no_pending(self, db):
        """get_completed_results returns empty list when no pending requests."""
        completed = await db.get_completed_results()
        assert completed == []


class TestDeleteCompletedResults:
    async def test_deletes_specified_request_ids(self, db):
        """delete_completed_results removes rows by request_id."""
        expires = "2099-01-01T00:00:00Z"
        await db.insert_pending("req-1", "tool_a", {}, "sig_a", expires)
        await db.insert_pending("req-2", "tool_b", {}, "sig_b", expires)
        await db.update_pending_result("req-1", '{"status": "ok"}')
        await db.update_pending_result("req-2", '{"status": "ok"}')

        await db.delete_completed_results(["req-1"])

        # req-1 deleted, req-2 remains
        assert await db.get_pending("req-1") is None
        assert await db.get_pending("req-2") is not None

    async def test_deletes_multiple_ids(self, db):
        """delete_completed_results can delete multiple IDs at once."""
        expires = "2099-01-01T00:00:00Z"
        await db.insert_pending("req-1", "tool_a", {}, "sig_a", expires)
        await db.insert_pending("req-2", "tool_b", {}, "sig_b", expires)

        await db.delete_completed_results(["req-1", "req-2"])

        assert await db.get_pending("req-1") is None
        assert await db.get_pending("req-2") is None

    async def test_empty_list_is_noop(self, db):
        """delete_completed_results with empty list does not raise."""
        await db.delete_completed_results([])


class TestUpdateAuditResolution:
    async def test_updates_resolution_fields(self, db):
        """update_audit_resolution sets resolution, resolved_by, resolved_at, execution_result."""
        entry = AuditEntry(
            request_id="req-1",
            tool_name="ha_call_service",
            decision="ask",
        )
        await db.log_audit(entry)

        now = time.time()
        exec_result = {"state": "on"}
        await db.update_audit_resolution(
            request_id="req-1",
            resolution="approved",
            resolved_by="12345",
            resolved_at=now,
            execution_result=exec_result,
        )

        entries = await db.get_audit_log()
        assert len(entries) == 1
        assert entries[0].resolution == "approved"
        assert entries[0].resolved_by == "12345"
        assert entries[0].resolved_at is not None
        assert abs(entries[0].resolved_at - now) < 1.0
        assert entries[0].execution_result == exec_result

    async def test_updates_without_execution_result(self, db):
        """update_audit_resolution works when execution_result is None (e.g. deny)."""
        entry = AuditEntry(
            request_id="req-1",
            tool_name="ha_call_service",
            decision="ask",
        )
        await db.log_audit(entry)

        now = time.time()
        await db.update_audit_resolution(
            request_id="req-1",
            resolution="denied",
            resolved_by="67890",
            resolved_at=now,
            execution_result=None,
        )

        entries = await db.get_audit_log()
        assert entries[0].resolution == "denied"
        assert entries[0].resolved_by == "67890"
        assert entries[0].execution_result is None

    async def test_nonexistent_request_is_noop(self, db):
        """update_audit_resolution on non-existent request_id does not raise."""
        await db.update_audit_resolution(
            request_id="nonexistent",
            resolution="approved",
            resolved_by="12345",
            resolved_at=time.time(),
        )


class TestHealthCheck:
    async def test_returns_true_when_connected(self, db):
        """health_check returns True when database connection is alive."""
        assert await db.health_check() is True

    async def test_returns_false_when_closed(self, tmp_path):
        """health_check returns False after connection is closed."""
        database = Database(str(tmp_path / "test.db"))
        await database.initialize()
        await database.close()
        assert await database.health_check() is False
