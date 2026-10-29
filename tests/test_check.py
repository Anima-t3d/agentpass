"""agentpass check-config: loaders, reference reporting and rule lints."""

from __future__ import annotations

import grp
import json
import os
from pathlib import Path

import pytest

from agentpass.__main__ import main
from agentpass.agents import generate_token
from agentpass.check import _VALUE, check, globs_intersect

ROOT = Path(__file__).resolve().parent.parent

TOOLS = """\
tools:
  t_get:
    signature: "{id}"
    args:
      id: {required: true}
    request: {method: GET, path: "/x/{id}"}
  t_two:
    signature: "{a}.{b}, {c}"
    args:
      a: {required: true}
      b: {required: true}
      c: {required: false}
    request: {method: GET, path: "/y/{a}"}
  t_bare:
    request: {method: GET, path: "/z"}
"""

PERMS = """\
defaults:
  - {pattern: "t_get*", action: allow}
  - {pattern: "*", action: ask}
rules:
  - {pattern: "t_two(a.*)", action: deny}
"""


# A group that exists on any host running the tests, so the group lint stays quiet
LISTEN = (
    f"listen: {{socket: /run/agentpass/agent.sock, group: {grp.getgrgid(os.getgid()).gr_name}, "
    f"admin_group: {grp.getgrgid(os.getgid()).gr_name}}}"
)


def write_setup(tmp_path, perms=PERMS, gateway_extra="", tools=TOOLS, token="tok"):
    (tmp_path / "tools.yaml").write_text(tools)
    (tmp_path / "gateway.yaml").write_text(
        f"""\
gateway: {{health_port: 8210}}
{LISTEN}
agent: {{token: "{token}"}}
messenger: {{type: telegram, telegram: {{token: "t", chat_id: 1, allowed_users: [1]}}}}
services:
  svc: {{url: "http://localhost", auth: {{type: bearer, token: "t"}}, tools: tools.yaml}}
storage: {{type: sqlite, path: ./d.db}}
{gateway_extra}"""
    )
    (tmp_path / "permissions.yaml").write_text(perms)
    return str(tmp_path / "gateway.yaml"), str(tmp_path / "permissions.yaml")


def codes(findings):
    return [f.code for f in findings]


def test_clean_setup_has_no_findings(tmp_path):
    report = check(*write_setup(tmp_path), env={})
    assert report.errors == [] and report.warnings == []
    assert report.exit_code() == 0


def test_golden_example_permissions_against_real_tools(tmp_path):
    """The shipped permission examples must lint clean against the shipped tool YAML."""
    services = "\n".join(
        f"  {name}: {{url: 'http://localhost', auth: {{type: bearer, token: t}}, "
        f"tools: '{ROOT / 'tools' / (name + '.yaml')}'}}"
        for name in ("homeassistant", "github")
    )
    for name in ("gmail", "calendar", "drive"):
        services += (
            f"\n  {name}: {{url: 'http://localhost', auth: {{type: oauth2, provider: google, "
            f"account: personal}}, tools: '{ROOT / 'tools' / (name + '.yaml')}'}}"
        )
    (tmp_path / "gateway.yaml").write_text(
        f"""\
gateway: {{health_port: 8210}}
{LISTEN}
agent: {{agents_dir: agents, policy_dir: '{ROOT / "policy"}'}}
messenger: {{type: telegram, telegram: {{token: t, chat_id: 1, allowed_users: [1]}}}}
services:
{services}
storage: {{type: sqlite, path: ./d.db}}
"""
    )
    (tmp_path / "agents").mkdir()
    _, digest = generate_token("hermes")
    (tmp_path / "agents" / "hermes.yaml").write_text(
        f"id: hermes\ntoken_hash: '{digest}'\nextends: [github]\n"
    )
    report = check(str(tmp_path / "gateway.yaml"), str(ROOT / "permissions.example.yaml"), env={})
    assert report.errors == [] and report.warnings == []
    assert report.summary["agents"] == 1 and report.summary["rule_sets"] == 2


def test_lint_unreachable_default(tmp_path):
    perms = 'defaults:\n  - {pattern: "*", action: ask}\n  - {pattern: "t_get*", action: allow}\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.warnings) == ["unreachable-default"]
    assert report.errors == []


def test_lint_pattern_matches_no_tool(tmp_path):
    perms = 'defaults:\n  - {pattern: "nothing_*", action: allow}\nrules: []\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.warnings) == ["pattern-matches-no-tool"]


def test_lint_rule_matches_no_signature(tmp_path):
    # t_get has one placeholder, so a comma in the argument part can never occur
    perms = 'rules:\n  - {pattern: "t_get(a, b)", action: deny}\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.warnings) == ["rule-matches-no-signature"]
    # A tool with no signature template only produces the bare name
    perms = 'rules:\n  - {pattern: "t_bare(x)", action: deny}\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.warnings) == ["rule-matches-no-signature"]


def test_optional_signature_part_can_be_absent(tmp_path):
    perms = 'rules:\n  - {pattern: "t_two(a.b)", action: deny}\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert report.warnings == []


def test_lint_rule_names_no_tool(tmp_path):
    perms = 'rules:\n  - {pattern: "*", action: deny}\n  - {pattern: "(x*)", action: deny}\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.warnings) == ["rule-names-no-tool"] * 2


def test_unknown_literal_tool_is_an_error(tmp_path):
    perms = 'rules:\n  - {pattern: "ghost_tool(x)", action: allow}\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.errors) == ["unknown-tool"]
    assert report.exit_code() == 1


def test_approval_warnings_are_folded_in(tmp_path):
    perms = (
        "rules:\n"
        '  - {pattern: "t_get(*)", action: ask, approval: {require: passkey}}\n'
        '  - {pattern: "t_two(*)", action: ask, approval: {require: telegram, channels: []}}\n'
    )
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.warnings) == ["approval"]
    assert "channels is empty" in report.warnings[0].message


def test_require_passkey_without_a_passkey_channel_is_an_error(tmp_path):
    perms = 'rules:\n  - {pattern: "t_get(*)", action: ask, approval: {require: passkey}}\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.errors) == ["approval-passkey"]
    assert "no trusted passkey channel" in report.errors[0].message
    assert report.exit_code() == 1


def test_unknown_channel_name_is_an_error(tmp_path):
    perms = 'rules:\n  - {pattern: "t_get(*)", action: ask, approval: {channels: [nope]}}\n'
    report = check(*write_setup(tmp_path, perms), env={})
    assert codes(report.errors) == ["config-error"]
    assert "nope" in report.errors[0].message


def test_unknown_keys_and_parse_errors(tmp_path):
    cfg, perms = write_setup(tmp_path, gateway_extra="bogus_key: 1\n")
    report = check(cfg, perms, env={})
    assert any(f.code == "unknown-key" and "bogus_key" in f.message for f in report.errors)

    (tmp_path / "permissions.yaml").write_text("defaults: [unclosed\n")
    report = check(cfg, perms, env={})
    assert any(f.code == "config-error" for f in report.errors)
    assert "Traceback" not in json.dumps(report.as_dict())


def test_unknown_tool_key_and_bad_regex(tmp_path):
    bad_key = TOOLS.replace("  t_bare:", "  t_bare:\n    sig: 1")
    report = check(*write_setup(tmp_path, tools=bad_key), env={})
    assert any(f.code == "unknown-key" and "sig" in f.message for f in report.errors)

    bad_re = TOOLS.replace("id: {required: true}", 'id: {required: true, validate: "(["}')
    report = check(*write_setup(tmp_path, tools=bad_re), env={})
    assert codes(report.errors) == ["config-error"]


def test_unresolved_references_report_names_only(tmp_path):
    cfg, perms = write_setup(tmp_path, token="${MISSING_ONE}")
    report = check(cfg, perms, env={})
    assert [(r.kind, r.name, r.resolved) for r in report.references] == [
        ("env", "MISSING_ONE", False)
    ]
    assert codes(report.errors) == ["unresolved-reference"]
    assert "MISSING_ONE" in report.errors[0].message
    assert report.skipped


def test_env_and_secret_prefixed_references(tmp_path):
    (tmp_path / "secrets.yaml").write_text("have_it: s3cretvalue-xyz\n")
    cfg, perms = write_setup(tmp_path, token="${secret:have_it}")
    (tmp_path / "permissions.yaml").write_text(PERMS + "# ${env:SET_ONE} ${secret:lost}\n")
    report = check(cfg, perms, env={"SET_ONE": "v-1234567"})
    resolved = {(r.kind, r.name): r.resolved for r in report.references}
    assert resolved == {
        ("secret", "have_it"): True,
        ("env", "SET_ONE"): True,
        ("secret", "lost"): False,
    }
    assert codes(report.errors) == ["unresolved-reference"]
    assert "reference-not-substituted" in codes(report.warnings)


def test_globs_intersect():
    assert globs_intersect("gh_*", "gh_get_issue(*)")
    assert not globs_intersect("t_get(a, b)", f"t_get({_VALUE})")
    assert globs_intersect("t[wx]o", "tw?")
    assert not globs_intersect("abc", "abd*")


def test_no_secret_value_in_any_output(tmp_path, capsys, monkeypatch):
    secret = "hunter2-very-secret-value"
    monkeypatch.setenv("LEAKY_TOKEN", secret)
    (tmp_path / "secrets.yaml").write_text(f"api_key: {secret}\n")
    cfg, perms = write_setup(
        tmp_path,
        gateway_extra="",
        token="${LEAKY_TOKEN}",
    )
    # The loader quotes the offending value in this message; the output must still be clean
    text = (tmp_path / "gateway.yaml").read_text().replace("type: sqlite", "type: ${LEAKY_TOKEN}")
    (tmp_path / "gateway.yaml").write_text(text + "# ${secret:api_key} ${MISSING_X}\n")
    for extra in ([], ["--json"], ["--strict"]):
        with pytest.raises(SystemExit):
            main(["check-config", "--config", cfg, "--permissions", perms, *extra])
        captured = capsys.readouterr()
        assert secret not in captured.out + captured.err
    report = check(cfg, perms)
    assert secret not in json.dumps(report.as_dict())


def test_cli_exit_codes_and_json(tmp_path, capsys):
    cfg, perms = write_setup(tmp_path)
    with pytest.raises(SystemExit) as ok:
        main(["check-config", "--config", cfg, "--permissions", perms])
    assert ok.value.code == 0
    assert "OK" in capsys.readouterr().out

    (tmp_path / "permissions.yaml").write_text('defaults:\n  - {pattern: "nope_*", action: ask}\n')
    with pytest.raises(SystemExit) as warn:
        main(["check-config", "--config", cfg, "--permissions", perms, "--json"])
    assert warn.value.code == 2
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "warnings" and data["warnings"][0]["code"] == "pattern-matches-no-tool"
    with pytest.raises(SystemExit) as strict:
        main(["check-config", "--config", cfg, "--permissions", perms, "--strict"])
    assert strict.value.code == 1

    (tmp_path / "permissions.yaml").write_text("defaults: [{pattern: x}]\n")
    with pytest.raises(SystemExit) as err:
        main(["check-config", "--config", cfg, "--permissions", perms])
    assert err.value.code == 1
