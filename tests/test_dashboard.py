"""Tests for agentpass.dashboard — audit dashboard routes and API."""

import time

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agentpass.dashboard import setup_dashboard
from agentpass.db import Database
from agentpass.models import AuditEntry


@pytest.fixture()
async def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    database = Database(db_path)
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture()
async def client(db):
    app = web.Application()
    setup_dashboard(app, db)
    async with TestClient(TestServer(app)) as c:
        yield c


async def _seed_entries(db, count=5):
    """Insert sample audit entries for testing."""
    tools = ["ha_get_state", "ha_call_service", "ha_get_history"]
    decisions = ["allow", "deny", "ask"]
    for i in range(count):
        entry = AuditEntry(
            request_id=f"req-{i}",
            tool_name=tools[i % len(tools)],
            args={"entity_id": f"sensor.test_{i}"},
            signature=f"{tools[i % len(tools)]}(sensor.test_{i})",
            decision=decisions[i % len(decisions)],
            resolution="executed" if decisions[i % len(decisions)] == "allow" else None,
            resolved_by="policy" if decisions[i % len(decisions)] == "allow" else None,
        )
        await db.log_audit(entry)


class TestApiLog:
    async def test_returns_json(self, client, db):
        await _seed_entries(db, 3)
        resp = await client.get("/audit/api/log")
        assert resp.status == 200
        data = await resp.json()
        assert "entries" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert "pages" in data
        assert data["total"] == 3
        assert len(data["entries"]) == 3

    async def test_empty_log(self, client):
        resp = await client.get("/audit/api/log")
        data = await resp.json()
        assert data["total"] == 0
        assert data["entries"] == []
        assert data["pages"] == 1

    async def test_pagination(self, client, db):
        await _seed_entries(db, 10)
        resp = await client.get("/audit/api/log?per_page=3&page=2")
        data = await resp.json()
        assert len(data["entries"]) == 3
        assert data["page"] == 2
        assert data["per_page"] == 3
        assert data["total"] == 10
        assert data["pages"] == 4

    async def test_filter_by_tool_name(self, client, db):
        await _seed_entries(db, 6)
        resp = await client.get("/audit/api/log?tool_name=ha_get_state")
        data = await resp.json()
        assert all(e["tool_name"] == "ha_get_state" for e in data["entries"])
        assert data["total"] == 2

    async def test_filter_by_decision(self, client, db):
        await _seed_entries(db, 6)
        resp = await client.get("/audit/api/log?decision=allow")
        data = await resp.json()
        assert all(e["decision"] == "allow" for e in data["entries"])

    async def test_filter_by_resolution(self, client, db):
        await _seed_entries(db, 6)
        resp = await client.get("/audit/api/log?resolution=executed")
        data = await resp.json()
        assert all(e["resolution"] == "executed" for e in data["entries"])

    async def test_invalid_page_defaults(self, client, db):
        await _seed_entries(db, 3)
        resp = await client.get("/audit/api/log?page=abc&per_page=invalid")
        data = await resp.json()
        assert data["page"] == 1
        assert data["per_page"] == 50


class TestApiStats:
    async def test_returns_stats(self, client, db):
        await _seed_entries(db, 6)
        resp = await client.get("/audit/api/stats")
        assert resp.status == 200
        data = await resp.json()
        assert "total_requests" in data
        assert "last_24h" in data
        assert "approval_rate" in data
        assert "top_tools" in data
        assert "decision_breakdown" in data
        assert data["total_requests"] == 6

    async def test_empty_stats(self, client):
        resp = await client.get("/audit/api/stats")
        data = await resp.json()
        assert data["total_requests"] == 0
        assert data["last_24h"] == 0
        assert data["approval_rate"] == 0.0
        assert data["top_tools"] == []

    async def test_decision_breakdown(self, client, db):
        await _seed_entries(db, 6)
        resp = await client.get("/audit/api/stats")
        data = await resp.json()
        breakdown = data["decision_breakdown"]
        assert "allow" in breakdown
        assert "deny" in breakdown
        assert "ask" in breakdown


class TestAuditPage:
    async def test_renders_html(self, client, db):
        await _seed_entries(db, 3)
        resp = await client.get("/audit/")
        assert resp.status == 200
        assert "text/html" in resp.content_type
        text = await resp.text()
        assert "agentpass" in text
        assert "Audit Dashboard" in text

    async def test_empty_state(self, client):
        resp = await client.get("/audit/")
        assert resp.status == 200
        text = await resp.text()
        assert "No audit entries yet" in text

    async def test_filters_render(self, client, db):
        await _seed_entries(db, 3)
        resp = await client.get("/audit/?tool_name=ha_get_state")
        assert resp.status == 200
        text = await resp.text()
        assert "ha_get_state" in text

    async def test_no_match_message(self, client, db):
        await _seed_entries(db, 3)
        resp = await client.get("/audit/?tool_name=nonexistent_tool")
        text = await resp.text()
        assert "No entries match your filters" in text


class TestFilteredQuery:
    async def test_combined_filters(self, db):
        for i in range(10):
            entry = AuditEntry(
                request_id=f"req-{i}",
                tool_name="ha_get_state" if i < 5 else "ha_call_service",
                decision="allow" if i % 2 == 0 else "ask",
            )
            await db.log_audit(entry)

        entries, total = await db.get_audit_log_filtered(tool_name="ha_get_state", decision="allow")
        assert total == 3  # i=0, 2, 4
        assert all(e.tool_name == "ha_get_state" for e in entries)
        assert all(e.decision == "allow" for e in entries)

    async def test_pagination_offset(self, db):
        for i in range(10):
            entry = AuditEntry(request_id=f"req-{i}", decision="allow")
            await db.log_audit(entry)

        entries, total = await db.get_audit_log_filtered(limit=3, offset=3)
        assert total == 10
        assert len(entries) == 3

    async def test_empty_result(self, db):
        entries, total = await db.get_audit_log_filtered(tool_name="nonexistent")
        assert entries == []
        assert total == 0

    async def test_date_range_filter(self, db):
        now = time.time()
        old = AuditEntry(
            request_id="old",
            timestamp=now - 86400 * 7,
            tool_name="ha_get_state",
            decision="allow",
        )
        recent = AuditEntry(
            request_id="recent",
            timestamp=now,
            tool_name="ha_get_state",
            decision="allow",
        )
        await db.log_audit(old)
        await db.log_audit(recent)

        entries, total = await db.get_audit_log_filtered(from_ts=now - 3600)
        assert total == 1
        assert entries[0].request_id == "recent"


class TestAuditStats:
    async def test_approval_rate(self, db):
        for i in range(4):
            entry = AuditEntry(
                request_id=f"req-{i}",
                decision="ask",
                resolution="approved" if i < 3 else "denied",
            )
            await db.log_audit(entry)

        stats = await db.get_audit_stats()
        assert stats["approval_rate"] == 0.75

    async def test_top_tools_ordering(self, db):
        for i in range(5):
            await db.log_audit(
                AuditEntry(request_id=f"a-{i}", tool_name="tool_a", decision="allow")
            )
        for i in range(3):
            await db.log_audit(
                AuditEntry(request_id=f"b-{i}", tool_name="tool_b", decision="allow")
            )

        stats = await db.get_audit_stats()
        assert len(stats["top_tools"]) == 2
        assert stats["top_tools"][0]["name"] == "tool_a"
        assert stats["top_tools"][0]["count"] == 5
        assert stats["top_tools"][1]["name"] == "tool_b"


class TestPreviewAndNote:
    async def _seed(self, db):
        await db.log_audit(
            AuditEntry(
                request_id="r1",
                tool_name="gmail_send_message",
                decision="ask",
                resolution="approved",
                preview_digest="d" * 64,
                preview_title="Send email to bob@example.com",
                preview_status="partial",
                agent_note="<script>alert(1)</script> please",
            )
        )
        await db.log_audit(AuditEntry(request_id="r2", tool_name="ha_get_state", decision="allow"))

    async def test_api_carries_digest_title_status_and_note(self, client, db):
        await self._seed(db)
        data = await (await client.get("/audit/api/log")).json()
        by_id = {e["request_id"]: e for e in data["entries"]}
        assert by_id["r1"]["preview_digest"] == "d" * 64
        assert by_id["r1"]["preview_title"] == "Send email to bob@example.com"
        assert by_id["r1"]["preview_status"] == "partial"
        assert by_id["r1"]["agent_note"].startswith("<script>")
        assert by_id["r2"]["preview_digest"] is None and by_id["r2"]["agent_note"] is None

    async def test_page_shows_them_labelled_and_escaped(self, client, db):
        await self._seed(db)
        text = await (await client.get("/audit/")).text()
        assert "Send email to bob@example.com" in text and "d" * 64 in text
        assert "Unverified text from the agent" in text
        assert "<script>alert(1)</script>" not in text
        assert "&lt;script&gt;alert(1)&lt;/script&gt; please" in text

    async def test_page_without_previews_has_no_preview_boxes(self, client, db):
        await _seed_entries(db, 2)
        text = await (await client.get("/audit/")).text()
        assert "<h4>Unverified text from the agent</h4>" not in text
        assert "<h4>Preview shown to the approver</h4>" not in text
