"""gh_merge_pull_request (passkey every time) and per-repo "always" for gh_mirror_fetch."""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from agentpass.agents import generate_token, load_agents
from agentpass.config import load_tools_file
from agentpass.engine import PermissionEngine, build_signature, validate_args
from agentpass.models import Decision
from agentpass.registry import ToolRegistry
from agentpass.remembered import build_offer
from agentpass.services.http import GenericHTTPService
from tests.preview_helpers import build

ROOT = Path(__file__).resolve().parent.parent
MERGE = "gh_merge_pull_request"
PR = "/repos/{owner}/{repo}/pulls/{number}"
SHA = "b" * 40
ARGS = {"owner": "o", "repo": "r", "number": 7, "sha": SHA}
CURRENT = {
    "title": "Add the reader",
    "state": "open",
    "head": {"ref": "feat/reader", "sha": SHA},
    "base": {"ref": "main"},
    "mergeable": True,
    "mergeable_state": "clean",
    "commits": 3,
    "changed_files": 4,
    "additions": 120,
    "deletions": 8,
}


def _gh():
    return {t.name: t for t in load_tools_file(str(ROOT / "tools/github.yaml"), "github")}


def _mirror():
    return {t.name: t for t in load_tools_file(str(ROOT / "tools/git_mirror.yaml"), "git_mirror")}


def _engine(tmp_path, extends, tools, policy=None):
    """The agent under the shipped rule sets and the example floor (or *policy*)."""
    if policy is None:
        policy = tmp_path / "policy"
        policy.mkdir()
        for name in ("github.yaml", "git_mirror.yaml"):
            shutil.copy(ROOT / "policy" / name, policy / name)
        shutil.copy(ROOT / "policy/_floor.example.yaml", policy / "_floor.yaml")
    (tmp_path / "agents").mkdir()
    _, digest = generate_token("a")
    (tmp_path / "agents" / "a.yaml").write_text(
        f"id: a\ntoken_hash: '{digest}'\nextends: [{extends}]\n"
    )
    agent = load_agents(tmp_path / "agents", policy).get("a")
    reg = ToolRegistry(tools)
    return PermissionEngine(agent.permissions, reg), reg


# --- merge ---


def test_merge_puts_to_the_merge_endpoint():
    tool = _gh()[MERGE]
    assert tool.request.method == "PUT"
    assert tool.request.path == PR + "/merge"
    assert tool.signature == "{owner}/{repo}, {number}"
    assert tool.risk == "high"
    assert tool.args["sha"].required and tool.args["sha"].signature is False
    assert tool.args["merge_method"].values == ["merge", "squash", "rebase"]


def test_merge_body_carries_the_approved_head_sha():
    tool = _gh()[MERGE]
    body = GenericHTTPService._build_body(
        tool, {**ARGS, "merge_method": "squash", "commit_title": "Reader (#7)"}
    )
    assert body == {"sha": SHA, "merge_method": "squash", "commit_title": "Reader (#7)"}


def test_merge_needs_a_sha():
    reg = ToolRegistry(_gh())
    validate_args(MERGE, dict(ARGS), reg)
    no_sha = {k: v for k, v in ARGS.items() if k != "sha"}
    try:
        validate_args(MERGE, no_sha, reg)
    except ValueError:
        return
    raise AssertionError("a merge without sha was accepted")


def test_merge_needs_a_passkey_every_time(tmp_path):
    engine, reg = _engine(tmp_path, "github", _gh())
    sig = build_signature(MERGE, ARGS, reg)
    assert sig == "gh_merge_pull_request(o/r, 7)"
    result = engine.evaluate(MERGE, ARGS, sig)
    assert result.decision == Decision.ASK
    assert result.approval is not None and result.approval.require == "passkey"
    offer = build_offer(reg.get_tool(MERGE), result.approval, sig, ARGS, result.floor)
    assert offer is None or not offer.any_allow


async def test_merge_preview_shows_the_pull_request():
    p = await build("github", "github", MERGE, dict(ARGS), {PR: CURRENT})
    assert p.title == "Merge pull request #7 into main in o/r"
    fields = {f[0]: f[1] for s in p.sections if s.kind == "kv" for f in s.data}
    assert fields["Pull request"] == "#7 Add the reader (open)"
    assert fields["Branches"] == "feat/reader into main"
    assert fields["Head commit now"] == SHA
    assert fields["Changes"] == "3 commits, 4 files, +120 / -8"
    assert p.warnings == []


async def test_merge_preview_warns_when_github_cannot_merge():
    p = await build(
        "github", "github", MERGE, dict(ARGS), {PR: CURRENT | {"mergeable_state": "dirty"}}
    )
    assert "GitHub reports conflicts with the base branch" in p.warnings


# --- mirror: always for one repo ---


def test_mirror_fetch_can_be_remembered_per_repo(tmp_path):
    engine, reg = _engine(tmp_path, "git_mirror", _mirror())
    args = {"owner": "o", "repo": "r", "branch": "main", "sha": "a" * 40}
    sig = build_signature("gh_mirror_fetch", args, reg)
    result = engine.evaluate("gh_mirror_fetch", args, sig)
    assert result.decision == Decision.ASK and not result.floor
    offer = build_offer(reg.get_tool("gh_mirror_fetch"), result.approval, sig, args, result.floor)
    assert offer.allow_resource and offer.resource == "o/r" and offer.resource_label == "repo"
    assert offer.allow_exact


def floor_problems(path: Path) -> list[str]:
    """What a floor file gets wrong about merges and the mirror (shared with deploy tests)."""
    rules = yaml.safe_load(path.read_text())["rules"]
    problems = []
    if [r for r in rules if r["pattern"].startswith("gh_mirror_fetch")]:
        problems.append("a floor rule still covers gh_mirror_fetch")
    merge = [r for r in rules if r["pattern"] == "gh_merge_*"]
    if not merge or merge[0].get("approval") != {"require": "passkey"}:
        problems.append("gh_merge_* does not ask for a passkey")
    return problems


def test_example_floor_needs_a_passkey_to_merge_and_leaves_the_mirror_alone():
    assert floor_problems(ROOT / "policy/_floor.example.yaml") == []
