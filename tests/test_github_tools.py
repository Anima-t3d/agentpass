"""GitHub write tools, policy for default branches, risk levels."""

from __future__ import annotations

from pathlib import Path

import yaml

from agentpass.agents import generate_token, load_agents
from agentpass.config import load_tools_file
from agentpass.engine import PermissionEngine, build_signature, validate_args
from agentpass.models import Decision
from agentpass.registry import ToolRegistry
from tests.preview_helpers import b64, build, section

ROOT = Path(__file__).parent.parent


def _registry() -> ToolRegistry:
    return ToolRegistry({t.name: t for t in load_tools_file("tools/github.yaml", "github")})


def _engine(tmp_path, agent_extra: str = "") -> PermissionEngine:
    (tmp_path / "agents").mkdir()
    _, digest = generate_token("a")
    (tmp_path / "agents" / "a.yaml").write_text(
        f"id: a\ntoken_hash: '{digest}'\nextends: [github]\n{agent_extra}"
    )
    agent = load_agents(tmp_path / "agents", ROOT / "policy").get("a")
    return PermissionEngine(agent.permissions, _registry())


def _decide(engine, tool, **args):
    return engine.evaluate(tool, args, build_signature(tool, args, engine._registry)).decision


def test_new_tools_and_risk_levels():
    reg = _registry()
    low = ("gh_get_branch", "gh_get_contents")
    med = ("gh_create_branch", "gh_put_contents", "gh_update_issue", "gh_update_pull")
    assert all(reg.get_tool(n).risk == "low" for n in low)
    assert all(reg.get_tool(n).risk == "medium" for n in med)
    assert reg.get_tool("gh_put_contents").preview.renderer == "diff"
    assert reg.get_tool("gh_put_contents").args["sha"].signature is False
    drive = {t.name: t.risk for t in load_tools_file("tools/drive.yaml", "drive")}
    assert drive == {
        "drive_list_files": "low",
        "drive_get_file": "low",
        "drive_create_folder": "medium",
    }


def test_every_shipped_high_risk_tool_has_a_preview():
    for name, svc in (("github", "github"), ("gmail", "gmail"), ("homeassistant", "homeassistant")):
        for t in load_tools_file(f"tools/{name}.yaml", svc):
            if t.risk == "high":
                assert t.preview is not None, t.name


def test_gmail_send_redacts_raw_and_requires_the_page():
    send = next(
        t for t in load_tools_file("tools/gmail.yaml", "gmail") if t.name == "gmail_send_message"
    )
    assert send.redact_args == ["raw"] and send.preview.require_page


def test_calendar_pins_send_updates_and_takes_attendees():
    create = next(
        t
        for t in load_tools_file("tools/calendar.yaml", "calendar")
        if t.name == "calendar_create_event"
    )
    assert create.request.query == {"sendUpdates": "all"}
    assert "sendUpdates" not in create.args and "attendees" in create.args


def test_writes_to_main_and_master_are_denied_unless_a_rule_allows(tmp_path):
    engine = _engine(tmp_path)
    put = {"owner": "me", "repo": "notes", "path": "a.md", "message": "m", "content": b64("x")}
    assert _decide(engine, "gh_put_contents", branch="main", **put) == Decision.DENY
    assert _decide(engine, "gh_put_contents", branch="master", **put) == Decision.DENY
    assert _decide(engine, "gh_put_contents", branch="feat/x", **put) == Decision.ASK
    assert (
        _decide(engine, "gh_create_branch", owner="me", repo="notes", branch="main", sha="a" * 40)
        == Decision.DENY
    )
    assert (
        _decide(engine, "gh_get_contents", owner="me", repo="notes", path="a.md") == Decision.ALLOW
    )


def test_an_explicit_rule_opens_one_repository(tmp_path):
    extra = 'rules:\n  - {pattern: "gh_put_contents(me/notes, main)", action: ask}\n'
    engine = _engine(tmp_path, extra)
    put = {"path": "a.md", "message": "m", "content": b64("x"), "branch": "main"}
    assert _decide(engine, "gh_put_contents", owner="me", repo="notes", **put) == Decision.ASK
    assert _decide(engine, "gh_put_contents", owner="me", repo="other", **put) == Decision.DENY


def test_put_contents_validates_args():
    reg = _registry()
    ok = {
        "owner": "me",
        "repo": "r",
        "branch": "b",
        "path": "dir/a.md",
        "message": "m",
        "content": b64("x"),
    }
    validate_args("gh_put_contents", ok, reg)
    for bad in ({"sha": "xyz"}, {"content": "not base64!"}, {"path": "a\nb"}):
        try:
            validate_args("gh_put_contents", ok | bad, reg)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad}")


def test_create_branch_body_pins_the_ref():
    tool = _registry().get_tool("gh_create_branch")
    assert tool.request.body_map == {"ref": "refs/heads/{branch}"}


async def test_update_issue_preview_shows_current_and_new():
    issue = {"title": "Old title", "state": "open", "body": "old", "labels": []}
    p = await build(
        "github", "github", "gh_update_issue",
        {"owner": "o", "repo": "r", "number": 7, "title": "New title", "state": "closed"},
        {"/repos/{owner}/{repo}/issues/{number}": issue},
    )  # fmt: skip
    rows = dict(section(p, "Details").data)
    assert rows["Issue now"] == "#7 Old title (open)"
    assert rows["New title"] == "New title" and rows["New state"] == "closed"
    assert "New body" not in rows  # unchanged fields are not shown as changing


async def test_create_branch_preview_names_the_base_commit():
    p = await build(
        "github", "github", "gh_create_branch",
        {"owner": "o", "repo": "r", "branch": "feat/x", "sha": "c" * 40},
        {"/repos/{owner}/{repo}/git/commits/{sha}": {"message": "Fix the thing"}},
    )  # fmt: skip
    assert dict(section(p, "Details").data)["Commit message"] == "Fix the thing"


async def test_calendar_preview_states_that_invites_are_emailed():
    p = await build(
        "calendar", "calendar", "calendar_create_event",
        {
            "calendar_id": "primary",
            "summary": "Standup",
            "start": {"dateTime": "2026-11-03T14:00:00+01:00"},
            "end": {"dateTime": "2026-11-03T14:30:00+01:00"},
            "attendees": [{"email": "bob@example.com"}],
        },
        {"/calendar/v3/calendars/{calendar_id}": {"summary": "Work"}},
    )  # fmt: skip
    rows = dict(section(p, "Details").data)
    assert rows["Calendar"] == "Work (primary)" and "bob@example.com" in rows["Attendees"]
    assert "sendUpdates is pinned to all" in rows["Invitations"]


def test_yaml_files_still_parse_as_yaml():
    for f in ("github", "gmail", "calendar", "drive"):
        assert yaml.safe_load((ROOT / "tools" / f"{f}.yaml").read_text())["tools"]
