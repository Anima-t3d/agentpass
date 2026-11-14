"""gh_mirror_fetch: tool definition, policy, approval preview and example units."""

from __future__ import annotations

import grp
import os
from pathlib import Path

import pytest

from agentpass.agents import generate_token, load_agents
from agentpass.check import check
from agentpass.config import load_tools_file
from agentpass.engine import PermissionEngine, build_signature, validate_args
from agentpass.models import Decision
from agentpass.passkey.verify import approval_challenge
from agentpass.preview import Unavailable
from agentpass.registry import ToolRegistry
from tests.preview_helpers import build, build_any

ROOT = Path(__file__).resolve().parent.parent
TOOL = "gh_mirror_fetch"
SHA = "0123456789abcdef0123456789abcdef01234567"
PREV = "fedcba9876543210fedcba9876543210fedcba98"
ARGS = {"owner": "o", "repo": "r", "branch": "feat/x", "sha": SHA}
COMMIT = {
    "sha": SHA,
    "headline": "Fix the login form",
    "author": "Ada",
    "date": "2026-11-14T10:00:00Z",
    "is_tip": "yes",
}
REWRITTEN = {
    "state": "rewritten",
    "previous": PREV,
    "summary": "history rewritten: 3 commits dropped, 5 new",
}
FAST_FORWARD = {"state": "fast-forward", "previous": PREV, "summary": "2 new commits"}
UNKNOWN = {"state": "unknown", "previous": None, "summary": "history check unavailable"}

W_REWRITTEN = "⚠ History rewritten: commits on this branch will be dropped from the mirror"
W_UNKNOWN = "History check unavailable: cannot confirm this is a fast-forward"
W_NOT_TIP = "This commit is no longer the branch tip"


def _registry() -> ToolRegistry:
    tools = load_tools_file(str(ROOT / "tools/git_mirror.yaml"), "git_mirror")
    return ToolRegistry({t.name: t for t in tools})


def _routes(commit=COMMIT, relation=FAST_FORWARD) -> dict:
    return {"/commit": commit, "/relation": relation}


async def _preview(routes):
    return await build("git_mirror", "git_mirror", TOOL, ARGS, routes)


def _fields(preview) -> dict[str, str]:
    return {label: value for label, value in preview.sections[0].data}


# --- definition -------------------------------------------------------------


def test_tool_definition():
    reg = _registry()
    tool = reg.get_tool(TOOL)
    assert tool is not None
    assert tool.risk == "medium"
    assert set(tool.args) == {"owner", "repo", "branch", "sha"}
    assert all(a.required for a in tool.args.values())
    assert tool.args["sha"].signature is False
    assert not tool.redact_args  # the approval proof covers the args as audited
    assert "gh_get_branch" in tool.description
    assert [(lk.id, lk.path, lk.on_error, lk.timeout) for lk in tool.preview.lookups] == [
        ("commit", "/commit", "unavailable", 5.0),
        ("relation", "/relation", "unavailable", 5.0),
    ]


def test_signature_is_owner_repo_at_branch():
    assert build_signature(TOOL, ARGS, _registry()) == "gh_mirror_fetch(o/r@feat/x)"


def test_sha_is_required_and_validated():
    reg = _registry()
    validate_args(TOOL, ARGS, reg)
    validate_args(TOOL, ARGS | {"sha": "a" * 64}, reg)
    no_sha = {k: v for k, v in ARGS.items() if k != "sha"}
    bad_values = ["A" * 40, "a" * 39, "a" * 41, "a" * 63, "g" * 40, "", f"{SHA}\n", f"-{SHA[1:]}"]
    for bad in [no_sha, *(ARGS | {"sha": v} for v in bad_values)]:
        with pytest.raises(ValueError):
            validate_args(TOOL, bad, reg)


def test_sha_is_in_the_approval_proof_not_the_signature():
    reg = _registry()
    other = ARGS | {"sha": PREV}
    assert build_signature(TOOL, other, reg) == build_signature(TOOL, ARGS, reg)

    def challenge(args):
        return approval_challenge("ap1", "a", TOOL, args, 1_800_000_000)

    assert challenge(other) != challenge(ARGS)


@pytest.mark.parametrize(
    "bad",
    [
        {"owner": "-o"},
        {"owner": "o/x"},
        {"repo": ".."},
        {"repo": "r x"},
        {"branch": "a b"},
        {"branch": "a\nb"},
        {"branch": "x" * 256},
    ],
)
def test_owner_repo_branch_validated(bad):
    with pytest.raises(ValueError):
        validate_args(TOOL, ARGS | bad, _registry())


# --- check-config and policy ------------------------------------------------


def test_check_config_has_no_lookup_warning(tmp_path):
    group = grp.getgrgid(os.getgid()).gr_name
    (tmp_path / "gateway.yaml").write_text(
        f"""\
gateway: {{health_port: 8210}}
listen: {{socket: /run/agentpass/agent.sock, group: {group}, admin_group: {group}}}
agent: {{token: t}}
messenger: {{type: telegram, telegram: {{token: t, chat_id: 1, allowed_users: [1]}}}}
services:
  git_mirror:
    url: "unix:///run/agentgit/helper.sock"
    auth: {{type: none}}
    handler: python
    handler_class: "agentpass.gitmirror.plugin:GitMirrorService"
    preview_lookups: true
    tools: "{ROOT / "tools/git_mirror.yaml"}"
storage: {{type: sqlite, path: ./d.db}}
"""
    )
    (tmp_path / "permissions.yaml").write_text("defaults: []\nrules: []\n")
    report = check(str(tmp_path / "gateway.yaml"), str(tmp_path / "permissions.yaml"))
    assert not report.errors, report.errors
    assert "preview-lookup-unsupported" not in [f.code for f in report.warnings]
    assert report.warnings == []


def test_policy_asks(tmp_path):
    (tmp_path / "agents").mkdir()
    _, digest = generate_token("a")
    (tmp_path / "agents" / "a.yaml").write_text(
        f"id: a\ntoken_hash: '{digest}'\nextends: [git_mirror]\n"
    )
    agent = load_agents(tmp_path / "agents", ROOT / "policy").get("a")
    reg = _registry()
    engine = PermissionEngine(agent.permissions, reg)
    sig = build_signature(TOOL, ARGS, reg)
    assert engine.evaluate(TOOL, ARGS, sig).decision == Decision.ASK


# --- preview ----------------------------------------------------------------


async def test_preview_fast_forward():
    p = await _preview(_routes())
    assert p.title == "Update mirror of o/r (feat/x)"
    fields = _fields(p)
    assert fields["Repository"] == "o/r"
    assert fields["Branch"] == "feat/x"
    assert fields["Commit"] == SHA
    assert fields["Headline"] == "Fix the login form"
    assert fields["Author"] == "Ada"
    assert "14 Nov" in fields["Date"] and "UTC" in fields["Date"]
    assert fields["Still the branch tip"] == "yes"
    assert fields["Previous"] == PREV
    assert fields["History"] == "2 new commits"
    assert p.warnings == []


async def test_preview_rewritten_history_warns():
    p = await _preview(_routes(relation=REWRITTEN))
    assert _fields(p)["History"] == "history rewritten: 3 commits dropped, 5 new"
    assert p.warnings == [W_REWRITTEN]


async def test_preview_unknown_relation_warns():
    p = await _preview(_routes(relation=UNKNOWN))
    fields = _fields(p)
    assert fields["History"] == "history check unavailable"
    assert "Previous" not in fields  # previous is null
    assert p.warnings == [W_UNKNOWN]


async def test_preview_not_tip_warns():
    p = await _preview(_routes(commit=COMMIT | {"is_tip": "no"}))
    assert _fields(p)["Still the branch tip"] == "no"
    assert p.warnings == [W_NOT_TIP]


async def test_preview_relation_failing_is_unavailable():
    """A helper or transport failure never hides the history check: no preview at all."""
    result = await build_any(
        "git_mirror", "git_mirror", TOOL, ARGS, _routes(relation=LookupError("internal"))
    )
    assert isinstance(result, Unavailable)


async def test_preview_unknown_relation_shows_known_previous():
    p = await _preview(_routes(relation=UNKNOWN | {"previous": PREV}))
    fields = _fields(p)
    assert fields["Previous"] == PREV
    assert fields["History"] == "history check unavailable"
    assert p.warnings == [W_UNKNOWN]


async def test_preview_commit_failing_is_unavailable():
    result = await build_any(
        "git_mirror", "git_mirror", TOOL, ARGS, _routes(commit=LookupError("not_found"))
    )
    assert isinstance(result, Unavailable)


# --- example units ----------------------------------------------------------


def _unit(name: str, section: str | None = None) -> dict[str, list[str]]:
    """Key -> values of a unit file; only the keys of [section] when one is given."""
    out: dict[str, list[str]] = {}
    current = None
    for line in (ROOT / "contrib/systemd" / name).read_text().splitlines():
        line = line.strip()
        if line.startswith("["):
            current = line.strip("[]")
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if section is not None and current != section:
            continue
        key, _, value = line.partition("=")
        out.setdefault(key, []).append(value)
    return out


def test_socket_unit():
    u = _unit("agentgit.socket")
    assert u["ListenStream"] == ["/run/agentgit/helper.sock"]
    assert u["SocketUser"] == ["agentgit"]
    assert u["SocketGroup"] == ["agentgit-clients"]
    assert u["SocketMode"] == ["0660"]
    assert u["Accept"] == ["yes"]
    assert u["MaxConnections"] == ["4"]


def test_service_unit_collects_failed_instances():
    """CollectMode is a [Unit] setting; systemd ignores it under [Service]."""
    assert _unit("agentgit@.service", "Unit").get("CollectMode") == ["inactive-or-failed"]
    assert "CollectMode" not in _unit("agentgit@.service", "Service")


def test_service_unit():
    u = _unit("agentgit@.service", "Service")
    expected = {
        "User": "agentgit",
        "Group": "agentgit",
        "SupplementaryGroups": "agentgit-readers",
        "StandardInput": "socket",
        "StandardOutput": "socket",
        "StandardError": "journal",
        "ExecStart": "/opt/agentpass/venv/bin/python -I -m agentpass.gitmirror.helper",
        "LoadCredential": "github-token:/etc/agentgit/token",
        "StateDirectory": "agentgit",
        "UMask": "0027",
        "RuntimeMaxSec": "660",
        "Environment": "AGENTGIT_FETCH_TIMEOUT_S=600",
        "MemoryMax": "1G",
        "ProtectSystem": "strict",
        "ReadWritePaths": "/srv/git-mirror",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "NoNewPrivileges": "yes",
        "RestrictSUIDSGID": "yes",
        "CapabilityBoundingSet": "",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
    }
    for key, value in expected.items():
        assert u.get(key) == [value], key


def test_timeouts_are_nested():
    """helper budget < RuntimeMaxSec < plugin deadline: systemd stops a stuck helper
    before the gateway gives up, and the helper reports timeout before systemd kills it."""
    from agentpass.gitmirror.helper import DEFAULT_FETCH_TIMEOUT_S
    from agentpass.gitmirror.plugin import FETCH_TIMEOUT_S

    u = _unit("agentgit@.service")
    env = dict(e.split("=", 1) for e in u["Environment"])
    budget = float(env["AGENTGIT_FETCH_TIMEOUT_S"])
    runtime_max = float(u["RuntimeMaxSec"][0])
    assert budget == DEFAULT_FETCH_TIMEOUT_S == 600
    assert budget < runtime_max < FETCH_TIMEOUT_S

