"""Remembered decisions scoped to one resource ("this repo"): ``remember_resource``."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from agentpass.approval import AnswerStatus
from agentpass.config import (
    ApprovalSpec,
    ArgDefinition,
    ConfigError,
    PermissionRule,
    RememberResource,
    ToolDefinition,
    load_tools_file,
)
from agentpass.db import SCHEMA_VERSION, Database
from agentpass.pipeline import ApprovalDenied, ApprovalUnavailable, PolicyDenied
from agentpass.remembered import build_offer, resource_of, rule_state, tool_fingerprint
from tests.test_remembered import _ask_and_answer, _cancel, _registry, _stack

REPO = RememberResource(label="repo", template="{owner}/{repo}")


def _repo_tool(name, risk="medium", resource=REPO):
    return ToolDefinition(
        name=name,
        service_name="svc",
        signature="{owner}/{repo}, {number}",
        args={
            "owner": ArgDefinition(required=True),
            "repo": ArgDefinition(required=True),
            "number": ArgDefinition(type="integer", required=True),
            "body": ArgDefinition(signature=False),
        },
        risk=risk,
        remember_resource=resource,
    )


@pytest.fixture
def tools():
    return {
        "upd": _repo_tool("upd"),
        "cmt": _repo_tool("cmt"),
        "hot": _repo_tool("hot", risk="high"),
        "bare": _repo_tool("bare", risk=None),
        "plain": _repo_tool("plain", resource=None),
    }


@pytest.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "t.db"))
    await database.initialize()
    yield database
    await database.close()


def _args(owner="o", repo="r", number=1, **kw):
    return {"owner": owner, "repo": repo, "number": number, **kw}


async def _pending(task):
    await asyncio.sleep(0.1)
    pending = not task.done()
    await _cancel(task)
    return pending


# --- configuration ---


def test_github_repo_tools_declare_the_repo_resource():
    tools = {t.name: t for t in load_tools_file("tools/github.yaml", "github")}
    for name in ("gh_update_issue", "gh_create_issue", "gh_create_issue_comment", "gh_get_repo"):
        assert tools[name].remember_resource == REPO, name
    assert tools["gh_list_repos"].remember_resource is None


@pytest.mark.parametrize(
    "spec",
    [
        {"label": "repo", "template": "{owner}/{nope}"},  # undeclared arg
        {"label": "repo", "template": "{owner}/{body}"},  # optional arg
        {"label": "repo", "template": "fixed"},  # names nothing
        {"label": "", "template": "{owner}"},
        {"label": "a very long label indeed", "template": "{owner}"},
        "{owner}/{repo}",
    ],
)
def test_a_resource_must_be_built_from_required_args(tmp_path, spec):
    import yaml

    path = tmp_path / "t.yaml"
    tool = {
        "description": "t",
        "signature": "{owner}",
        "args": {"owner": {"type": "string", "required": True}, "body": {"type": "string"}},
        "request": {"method": "GET", "path": "/x"},
        "risk": "low",
        "remember_resource": spec,
    }
    path.write_text(yaml.safe_dump({"tools": {"t": tool}}))
    with pytest.raises(ConfigError, match="remember_resource"):
        load_tools_file(str(path), "svc")


def test_fingerprint_of_a_tool_without_a_resource_is_unchanged(tools):
    tool = tools["plain"]
    data = dataclasses.asdict(tool)
    data.pop("description")
    data.pop("remember_resource")
    old = hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()
    assert tool_fingerprint(tool) == old
    assert tool_fingerprint(tools["upd"]) != tool_fingerprint(
        dataclasses.replace(tools["upd"], remember_resource=None)
    )


# --- the offer ---


def test_resource_of_renders_the_template(tools):
    assert resource_of(tools["upd"], _args(owner="octo", repo="hello-world")) == (
        "octo/hello-world"
    )
    assert resource_of(tools["plain"], _args()) is None
    assert resource_of(tools["upd"], {"owner": "o"}) is None  # missing arg: no resource


def test_offer_includes_the_resource_scope_when_eligible(tools):
    offer = build_offer(tools["upd"], None, "upd(o/r, 1)", _args())
    assert (offer.allow_resource, offer.deny_resource) == (True, True)
    assert (offer.resource, offer.resource_label, offer.allow_resource_days) == ("o/r", "repo", 30)
    assert offer.permits(True, "resource") and offer.permits(False, "resource")


@pytest.mark.parametrize(
    ("name", "approval", "floor"),
    [
        ("hot", None, False),  # high risk
        ("bare", None, False),  # no risk level, like the tool scope
        ("upd", ApprovalSpec(require="passkey"), False),
        ("upd", None, True),  # a floor ask covers it
    ],
)
def test_no_allow_for_the_resource_when_policy_forbids_it(tools, name, approval, floor):
    offer = build_offer(tools[name], approval, f"{name}(o/r, 1)", _args(), floor)
    assert not offer.allow_resource
    assert offer.deny_resource  # denying is always possible


def test_no_resource_scope_without_a_resource(tools):
    offer = build_offer(tools["plain"], None, "plain(o/r, 1)", _args())
    assert offer.resource is None
    assert not offer.permits(True, "resource") and not offer.permits(False, "resource")


# --- end to end ---


async def test_allow_always_for_this_repo_covers_that_tool_in_that_repo_only(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    req, status, task = await _ask_and_answer(
        pipeline, channel, "upd", _args(number=1), approved=True, remember="resource"
    )
    assert req.remember.resource == "o/r"
    assert status is AnswerStatus.ACCEPTED
    await task

    [rule] = await db.list_remembered_rules()
    assert (rule["scope"], rule["signature"], rule["args_hash"]) == ("resource", "o/r", None)
    assert rule["pattern"] == "upd(o/r, *)"
    expires = datetime.strptime(rule["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert timedelta(days=29) < expires - datetime.now(UTC) <= timedelta(days=30)

    sent = len(channel.sent)
    out = await pipeline.process("bot", "upd", _args(number=99, body="anything"))
    assert out.data == {"ok": True} and len(channel.sent) == sent

    assert await _pending(asyncio.create_task(pipeline.process("bot", "upd", _args(repo="x"))))
    assert await _pending(asyncio.create_task(pipeline.process("bot", "upd", _args(owner="x"))))
    assert await _pending(asyncio.create_task(pipeline.process("bot", "cmt", _args())))
    assert await _pending(asyncio.create_task(pipeline.process("other", "upd", _args())))


async def test_the_resource_is_compared_literally(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "upd", _args(owner="o", repo="r"), approved=True, remember="resource"
    )
    await task
    # "o/r" must not cover "o/r2" or "o/r/x"-like values
    assert await _pending(asyncio.create_task(pipeline.process("bot", "upd", _args(repo="r2"))))


async def test_deny_always_for_this_repo_blocks_without_asking(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "upd", _args(), approved=False, remember="resource"
    )
    with pytest.raises(ApprovalDenied):
        await task
    [rule] = await db.list_remembered_rules()
    assert rule["action"] == "deny" and rule["expires_at"] is None
    with pytest.raises(PolicyDenied):
        await pipeline.process("bot", "upd", _args(number=7))


async def test_a_resource_allow_stops_when_policy_later_needs_a_passkey(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _, _, task = await _ask_and_answer(
        pipeline, channel, "upd", _args(), approved=True, remember="resource"
    )
    await task
    strict, _, _, _ = await _stack(
        db, tools, [PermissionRule("upd(*)", "ask", approval=ApprovalSpec(require="passkey"))]
    )
    # the remembered allow is not used: the call needs an approval (none can be delivered here)
    with pytest.raises(ApprovalUnavailable):
        await strict.process("bot", "upd", _args(number=2))


async def test_resource_scope_not_offered_is_rejected(db, tools):
    pipeline, _, channel, _ = await _stack(db, tools, [])
    _req, status, task = await _ask_and_answer(
        pipeline, channel, "plain", _args(), approved=True, remember="resource"
    )
    assert status is AnswerStatus.REJECTED
    await _cancel(task)
    assert await db.list_remembered_rules() == []


def test_rule_state_of_a_resource_rule(tools):
    registry = _registry(**tools)
    rule = {
        "id": 1,
        "agent_id": "bot",
        "scope": "resource",
        "tool_name": "upd",
        "signature": "o/r",
        "args_hash": None,
        "pattern": "upd(o/r, *)",
        "action": "allow",
        "revoked_at": None,
        "expires_at": None,
        "tool_fingerprint": tool_fingerprint(tools["upd"]),
    }
    assert rule_state(rule, registry, now_iso="2026-11-19T00:00:00Z") == ("active", "")
    floored = rule_state(
        rule, registry, now_iso="2026-11-19T00:00:00Z", floor_for=lambda a, t, s: s is None
    )
    assert floored == ("inactive", "policy: covered by a floor rule")


# --- database ---


async def test_v7_database_migrates_and_keeps_its_rules(tmp_path):
    path = tmp_path / "old.db"
    fresh = Database(str(path))
    await fresh.initialize()
    await fresh.close()
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        DROP TABLE remembered_rules;
        CREATE TABLE remembered_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            scope TEXT NOT NULL CHECK (scope IN ('exact', 'tool')),
            tool_name TEXT NOT NULL, signature TEXT, args_hash TEXT, pattern TEXT NOT NULL,
            action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
            created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT,
            revoked_at TEXT, revoked_by TEXT, source_request_id TEXT NOT NULL,
            tool_fingerprint TEXT NOT NULL, use_count INTEGER NOT NULL DEFAULT 0,
            last_used_at TEXT);
        INSERT INTO remembered_rules (agent_id, scope, tool_name, pattern, action, created_by,
            created_at, source_request_id, tool_fingerprint, use_count)
            VALUES ('bot', 'tool', 'medt', 'medt(*)', 'allow', '42', 'x', 'req', 'fp', 3);
        PRAGMA user_version = 7;
        """
    )
    conn.close()
    database = Database(str(path))
    await database.initialize()
    try:
        [old] = await database.list_remembered_rules()
        assert (old["id"], old["scope"], old["use_count"]) == (1, "tool", 3)
        rule_id, _ = await database.upsert_remembered_rule(
            {
                "agent_id": "bot",
                "scope": "resource",
                "tool_name": "upd",
                "signature": "o/r",
                "args_hash": None,
                "pattern": "upd(o/r, *)",
                "action": "allow",
                "created_by": "42",
                "created_at": "x",
                "expires_at": None,
                "source_request_id": "req2",
                "tool_fingerprint": "fp",
            }
        )
        assert rule_id == 2
    finally:
        await database.close()
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 8
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO remembered_rules (agent_id, scope, tool_name, pattern, action,"
            " created_by, created_at, source_request_id, tool_fingerprint)"
            " VALUES ('b', 'bogus', 't', 'p', 'allow', 'c', 'x', 'r', 'f')"
        )
    conn.close()
