"""GET /api/history: the audit log behind the page session, filtered by agent and decision."""

from __future__ import annotations

import time

from agentpass.models import AuditEntry
from tests.test_passkey import env  # noqa: F401


async def _seed(db):
    rows = [
        ("r1", "hermes", "gmail_send", "ask", "approved", "passkey:phone"),
        ("r2", "hermes", "gh_mirror_fetch", "deny", None, None),
        ("r3", "other", "gmail_send", "ask", "denied", "push:Pixel 8"),
        ("one-tap:dev1", "", "", "ask", "approval_rejected", "passkey:1.2.3.4"),
    ]
    for rid, agent, tool, decision, resolution, by in rows:
        await db.log_audit(
            AuditEntry(
                request_id=rid,
                tool_name=tool,
                args={},
                signature=f"{tool}()",
                decision=decision,
                resolution=resolution,
                resolved_by=by,
                agent_id=agent,
            )
        )


async def test_history_requires_session(env):  # noqa: F811
    await _seed(env.db)
    r = await env.get("/api/history")
    assert r.status == 401
    assert "gmail_send" not in await r.text()


async def test_history_returns_dashboard_shape_newest_first(env):  # noqa: F811
    await _seed(env.db)
    await env.sign_in()
    r = await env.get("/api/history")
    assert r.status == 200
    data = await r.json()
    assert set(data) == {"entries", "total", "page", "per_page", "pages"}
    assert data["total"] == 4 and data["per_page"] == 50 and data["pages"] == 1
    assert [e["request_id"] for e in data["entries"]] == ["one-tap:dev1", "r3", "r2", "r1"]
    assert isinstance(data["entries"][0]["timestamp"], (int, float))  # epoch seconds; the UI scales
    assert {"timestamp", "tool_name", "signature", "decision", "resolved_by", "agent_id"} <= set(
        data["entries"][0]
    )


async def test_history_filters_by_agent_and_decision(env):  # noqa: F811
    await _seed(env.db)
    await env.sign_in()
    data = await (await env.get("/api/history?agent_id=hermes")).json()
    assert sorted(e["request_id"] for e in data["entries"]) == ["r1", "r2"]
    data = await (await env.get("/api/history?agent_id=hermes&decision=deny")).json()
    assert [e["request_id"] for e in data["entries"]] == ["r2"]
    data = await (await env.get("/api/history?tool_name=gmail_send")).json()
    assert sorted(e["request_id"] for e in data["entries"]) == ["r1", "r3"]


async def test_history_paginates(env):  # noqa: F811
    await _seed(env.db)
    await env.sign_in()
    data = await (await env.get("/api/history?per_page=3&page=2")).json()
    assert data["total"] == 4 and data["pages"] == 2 and data["page"] == 2
    assert [e["request_id"] for e in data["entries"]] == ["r1"]


async def test_history_without_a_database_is_empty(env):  # noqa: F811
    await env.sign_in()
    env.channel.page.db = None
    data = await (await env.get("/api/history")).json()
    assert data["entries"] == [] and data["total"] == 0


async def test_history_filters_by_date_range(env):  # noqa: F811
    await _seed(env.db)
    await env.sign_in()
    day = time.strftime("%Y-%m-%d", time.gmtime())
    for params, expected in (
        (f"from={day}&to={day}T23:59:59", 4),
        (f"from={day}T00:00:00", 4),
        ("to=2000-01-01", 0),
        ("from=2999-01-01", 0),
    ):
        data = await (await env.get(f"/api/history?{params}")).json()
        assert data["total"] == expected, params


async def test_history_leaves_out_call_arguments(env):  # noqa: F811
    await env.db.log_audit(
        AuditEntry(
            request_id="r9",
            tool_name="gmail_send",
            args={"to": "someone@example.com", "body": "private text"},
            signature="gmail_send(someone@example.com)",
            decision="ask",
            agent_id="hermes",
        )
    )
    await env.sign_in()
    r = await env.get("/api/history")
    (entry,) = (await r.json())["entries"]
    assert "args" not in entry
    assert "private text" not in await r.text()
    assert entry["signature"] == "gmail_send(someone@example.com)"  # what the table shows
