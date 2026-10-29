"""Previews through the coordinator: storage, audit, channel exclusion, failure handling."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from unittest.mock import AsyncMock

import pytest

from agentpass.approval import ApprovalCoordinator, ApprovalRequest
from agentpass.config import (
    ArgDefinition,
    PreviewField,
    PreviewLookup,
    PreviewSpec,
    ToolDefinition,
)
from agentpass.db import SCHEMA_VERSION, Database
from agentpass.models import AuditEntry
from agentpass.preview import Preview, PreviewService, Unavailable, preview_from_json
from agentpass.registry import ToolRegistry
from tests.fakes import FakeChannel
from tests.test_preview import FakeLookupService


def _tool() -> ToolDefinition:
    return ToolDefinition(
        name="lock_it",
        service_name="svc",
        signature="{entity_id}",
        args={"entity_id": ArgDefinition(required=True), "raw": ArgDefinition()},
        redact_args=["raw"],
        preview=PreviewSpec(
            lookups=[PreviewLookup("state", "/s/{entity_id}")],
            title="Lock {state.name}",
            summary="{state.name} is {state.state}; raw={raw}",
            fields=[PreviewField("Now", "{state.state}")],
        ),
    )


@pytest.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "t.db"))
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture
def svc():
    return FakeLookupService({"name": "Front door", "state": "locked"})


def _coordinator(db, svc, *channels, **kw):
    registry = ToolRegistry({"lock_it": _tool()})
    previews = PreviewService(registry, {"svc": svc}, **kw)
    coordinator = ApprovalCoordinator(db, list(channels), previews=previews)
    for channel in channels:
        channel.sink = coordinator
        coordinator._active[channel.name] = channel
    return coordinator


def _req(approval_id="r1", args=None, **kw) -> ApprovalRequest:
    import time

    return ApprovalRequest(
        approval_id=approval_id,
        agent_id="bot",
        tool="lock_it",
        signature="lock.front",
        args=args or {"entity_id": "lock.front", "raw": "[redacted]"},
        expires_at=time.time() + 30,
        **kw,
    )


async def _run(coordinator, channel, req, **kw):
    task = asyncio.create_task(coordinator.request(req, **kw))
    for _ in range(200):
        if any(r.approval_id == req.approval_id for r in channel.sent):
            break
        await asyncio.sleep(0.01)
    return task


async def test_preview_attached_for_trusted_channel_only(db, svc):
    trusted, notify = FakeChannel("tg"), FakeChannel("hook", trust="notify")
    coordinator = _coordinator(db, svc, trusted, notify)
    await db.log_audit(AuditEntry(request_id="r1", tool_name="lock_it", decision="ask"))
    task = await _run(coordinator, trusted, _req(agent_note="please"))
    preview = trusted.last_request.preview
    assert isinstance(preview, Preview) and preview.title == "Lock Front door"
    assert trusted.last_request.agent_note == "please"
    # the notify channel gets neither the preview nor the agent's note
    assert notify.last_request.preview is None
    assert notify.last_request.agent_note is None
    await trusted.approve("r1")
    await task


async def test_lookup_uses_unredacted_args_but_req_args_stay_redacted(db, svc):
    ch = FakeChannel("tg")
    coordinator = _coordinator(db, svc, ch)
    real = {"entity_id": "lock.front", "raw": "REAL-BODY"}
    task = await _run(coordinator, ch, _req(), preview_args=real)
    assert "raw=REAL-BODY" in ch.last_request.preview.summary
    assert ch.last_request.args["raw"] == "[redacted]"
    await ch.approve("r1")
    await task


async def test_preview_stored_while_pending_and_cleared_on_resolution(db, svc):
    ch = FakeChannel("tg")
    coordinator = _coordinator(db, svc, ch)
    task = await _run(coordinator, ch, _req())
    row = await db.get_pending("r1")
    stored = preview_from_json(row["preview_json"])
    assert stored == ch.last_request.preview
    await ch.approve("r1")
    await task
    assert (await db.get_pending("r1"))["preview_json"] is None


async def test_preview_cleared_on_timeout_and_denial(db, svc):
    ch = FakeChannel("tg")
    coordinator = _coordinator(db, svc, ch)
    import time

    req = _req("t1")
    req.expires_at = time.time() + 0.2
    outcome = await coordinator.request(req)
    assert outcome.reason == "timeout"
    assert (await db.get_pending("t1"))["preview_json"] is None
    task = await _run(coordinator, ch, _req("d1"))
    await ch.deny("d1")
    await task
    assert (await db.get_pending("d1"))["preview_json"] is None


async def test_restart_abandon_clears_preview(db, svc):
    await db.insert_pending(
        "old", "lock_it", {}, "s", "2999-01-01T00:00:00Z", preview_json='{"title": "x"}'
    )
    rows = await db.abandon_pending()
    assert rows[0]["request_id"] == "old"
    assert (await db.get_pending("old"))["preview_json"] is None


async def test_audit_row_holds_digest_title_status_only(db, svc):
    ch = FakeChannel("tg")
    coordinator = _coordinator(db, svc, ch)
    await db.log_audit(AuditEntry(request_id="r1", tool_name="lock_it", decision="ask"))
    task = await _run(coordinator, ch, _req())
    await ch.approve("r1")
    await task
    [entry] = await db.get_audit_log()
    preview = ch.last_request.preview
    assert (entry.preview_digest, entry.preview_title, entry.preview_status) == (
        preview.digest,
        "Lock Front door",
        "ok",
    )
    conn = sqlite3.connect(db._path)
    dump = " ".join(str(v) for row in conn.execute("SELECT * FROM audit_log") for v in row)
    assert "locked" not in dump  # no lookup content in the audit row


async def test_lookup_failure_never_blocks_and_never_approves(db, svc):
    svc.error = RuntimeError("boom")
    ch = FakeChannel("tg")
    coordinator = _coordinator(db, svc, ch)
    await db.log_audit(AuditEntry(request_id="r1", tool_name="lock_it", decision="ask"))
    task = await _run(coordinator, ch, _req())
    assert isinstance(ch.last_request.preview, Unavailable)
    assert not task.done()  # still waiting for a human
    await ch.deny("r1")
    outcome = await task
    assert outcome.approved is False
    [entry] = await db.get_audit_log()
    assert entry.preview_status.startswith("unavailable:") and entry.preview_digest is None


async def test_slow_lookup_times_out_without_delaying_the_request_past_the_cap(db, svc):
    svc.delay = 5
    ch = FakeChannel("tg")
    coordinator = _coordinator(db, svc, ch, timeout=0.1)
    task = await _run(coordinator, ch, _req())
    assert ch.last_request.preview == Unavailable("timeout", ch.last_request.preview.built_at)
    await ch.approve("r1")
    assert (await task).approved


async def test_service_that_raises_is_contained(db):
    broken = AsyncMock()
    broken.build.side_effect = RuntimeError("bug")
    ch = FakeChannel("tg")
    coordinator = ApprovalCoordinator(db, [ch], previews=broken)
    ch.sink = coordinator
    coordinator._active["tg"] = ch
    task = await _run(coordinator, ch, _req())
    assert ch.last_request.preview is None
    await ch.approve("r1")
    assert (await task).approved


async def test_no_preview_when_only_notify_channels(db, svc):
    hook = FakeChannel("hook", trust="notify")
    coordinator = _coordinator(db, svc, hook)
    task = asyncio.create_task(coordinator.request(_req()))
    await asyncio.sleep(0.1)
    assert svc.lookups == []  # no lookups made for nobody to read
    task.cancel()


async def test_tool_without_preview_block_is_untouched(db, svc):
    registry = ToolRegistry({"plain": ToolDefinition(name="plain", service_name="svc")})
    ch = FakeChannel("tg")
    coordinator = ApprovalCoordinator(db, [ch], previews=PreviewService(registry, {"svc": svc}))
    ch.sink = coordinator
    coordinator._active["tg"] = ch
    req = _req()
    req.tool = "plain"
    task = await _run(coordinator, ch, req)
    assert ch.last_request.preview is None and svc.lookups == []
    await ch.approve("r1")
    await task


async def test_v4_database_migrates_idempotently(tmp_path):
    path = str(tmp_path / "v4.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            request_id TEXT NOT NULL, tool_name TEXT NOT NULL, args TEXT NOT NULL,
            signature TEXT NOT NULL, decision TEXT NOT NULL, resolution TEXT, resolved_by TEXT,
            resolved_at TEXT, execution_result TEXT, agent_id TEXT DEFAULT 'default',
            remembered_rule_id INTEGER);
        CREATE TABLE pending_requests (request_id TEXT PRIMARY KEY, tool_name TEXT NOT NULL,
            args TEXT NOT NULL, signature TEXT NOT NULL, message_id TEXT, chat_id INTEGER,
            result TEXT, created_at TEXT NOT NULL DEFAULT 'x', expires_at TEXT NOT NULL,
            agent_id TEXT NOT NULL DEFAULT 'default', state TEXT NOT NULL DEFAULT 'pending',
            handles TEXT);
        INSERT INTO audit_log (timestamp, request_id, tool_name, args, signature, decision)
            VALUES ('2026-01-01T00:00:00Z', 'old', 't', '{}', 't', 'allow');
        PRAGMA user_version = 4;
        """
    )
    conn.commit()
    conn.close()
    for i in range(2):  # a second start changes nothing
        database = Database(path)
        await database.initialize()
        [entry] = await database.get_audit_log()
        assert entry.request_id == "old"
        assert entry.preview_digest is None and entry.agent_note is None
        await database.insert_pending(
            f"n{i}", "t", {}, "t", "2999-01-01T00:00:00Z", preview_json="{}"
        )
        await database.close()
    check = sqlite3.connect(path)
    assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 6
    cols = {r[1] for r in check.execute("PRAGMA table_info(audit_log)")}
    assert {"preview_digest", "preview_title", "preview_status", "agent_note"} <= cols
    pending = {r[1] for r in check.execute("PRAGMA table_info(pending_requests)")}
    assert {"preview_json", "agent_note"} <= pending


def test_digest_is_stable_json():
    p = Preview(title="t", summary="s", built_at="2026-01-01T00:00:00Z").seal()
    assert p.digest == Preview.from_dict(json.loads(json.dumps(p.to_dict()))).compute_digest()


async def test_agent_note_is_stored_on_the_pending_row_and_cleared_on_resolution(db, svc):
    ch = FakeChannel("tg")
    coordinator = _coordinator(db, svc, ch)
    task = await _run(coordinator, ch, _req(agent_note="opening the door for the courier"))
    assert (await db.get_pending("r1"))["agent_note"] == "opening the door for the courier"
    await ch.approve("r1")
    await task
    assert (await db.get_pending("r1"))["agent_note"] is None


async def test_agent_note_cleared_on_timeout_denial_and_restart(db, svc):
    import time

    ch = FakeChannel("tg")
    coordinator = _coordinator(db, svc, ch)
    req = _req("t1", agent_note="n")
    req.expires_at = time.time() + 0.2
    assert (await coordinator.request(req)).reason == "timeout"
    assert (await db.get_pending("t1"))["agent_note"] is None
    task = await _run(coordinator, ch, _req("d1", agent_note="n"))
    await ch.deny("d1")
    await task
    assert (await db.get_pending("d1"))["agent_note"] is None
    await db.insert_pending("old", "lock_it", {}, "s", "2999-01-01T00:00:00Z", agent_note="n")
    await db.abandon_pending()
    assert (await db.get_pending("old"))["agent_note"] is None
