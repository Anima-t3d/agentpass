"""Offline configuration validation (``agentpass check-config``).

Loads everything with the same loaders ``serve`` uses, then lints the rules. It makes no
network calls, imports no plugin code and never prints a secret value: environment and
secret references are reported by NAME only, and any referenced value that does show up
in a loader message is scrubbed before output.
"""

from __future__ import annotations

import grp
import json
import os
import re
import sqlite3
import string
from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase, translate
from pathlib import Path
from typing import Any

import yaml

from agentpass.agents import AgentIdentity, load_agents
from agentpass.config import (
    Config,
    ConfigError,
    PermissionRule,
    Permissions,
    approval_findings,
    is_wildcard_host,
    load_config,
    load_permissions,
    validate_rule_channels,
)
from agentpass.engine import PermissionEngine
from agentpass.models import Decision
from agentpass.registry import ToolRegistry, build_registry
from agentpass.remembered import iso, rule_state

CONFIG_KEYS = {
    "gateway",
    "listen",
    "agent",
    "messenger",
    "channels",
    "services",
    "storage",
    "approval_timeout",
    "approval",
    "rate_limit",
    "mcp",
    "passkey",
}
PERMISSIONS_KEYS = {"defaults", "rules"}
TOOL_KEYS = {
    "description",
    "signature",
    "args",
    "request",
    "response",
    "audit",
    "risk",
    "remember",
    "preview",
}

# ${NAME}, ${env:NAME}, ${secret:name}. Only the bare form is substituted by the loader today.
_REF_RE = re.compile(r"\$\{(?:(env|secret):)?([\w.-]+)\}")
_MIN_SCRUB_LEN = 4
_VALUE = "\x01"  # signature placeholder: any run of characters an argument value may hold
_FORBIDDEN_IN_VALUES = ",()*?[]"  # engine._check_forbidden rejects these in signature args
_ALPHABET = [c for c in string.printable if c not in "\t\n\r\x0b\x0c"]


@dataclass
class Finding:
    code: str
    where: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "where": self.where, "message": self.message}


@dataclass
class Reference:
    kind: str  # env | secret
    name: str
    file: str
    resolved: bool

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "file": self.file, "resolved": self.resolved}


@dataclass
class Report:
    errors: list[Finding] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)

    def error(self, code: str, where: str, message: str) -> None:
        self.errors.append(Finding(code, where, message))

    def warn(self, code: str, where: str, message: str) -> None:
        self.warnings.append(Finding(code, where, message))

    def exit_code(self, strict: bool = False) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 1 if strict else 2
        return 0

    def as_dict(self, strict: bool = False) -> dict[str, Any]:
        code = self.exit_code(strict)
        return {
            "status": {0: "ok", 1: "errors", 2: "warnings"}[code],
            "exit_code": code,
            "errors": [f.as_dict() for f in self.errors],
            "warnings": [f.as_dict() for f in self.warnings],
            "references": [r.as_dict() for r in self.references],
            "skipped": self.skipped,
            "summary": self.summary,
        }


# --- Glob intersection -------------------------------------------------------------------
# A rule "matches no signature" when its fnmatch pattern and the tool's signature shape
# (template placeholders become ``*``) have no string in common. Both are globs, so this is
# a small product-automaton search rather than a guess.


def _tokens(glob: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    i, n = 0, len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            while i + 1 < n and glob[i + 1] == "*":
                i += 1
            out.append(("*", c))
        elif c == _VALUE:
            out.append(("vstar", c))
        elif c == "?":
            out.append(("?", c))
        elif c == "[":
            j = i + 1
            if j < n and glob[j] == "!":
                j += 1
            if j < n and glob[j] == "]":
                j += 1
            while j < n and glob[j] != "]":
                j += 1
            if j >= n:
                out.append(("lit", c))
            else:
                out.append(("cls", glob[i : j + 1]))
                i = j
        else:
            out.append(("lit", c))
        i += 1
    return out


def _closure(toks: list[tuple[str, str]], states: Iterable[int]) -> frozenset[int]:
    seen = set(states)
    stack = list(seen)
    while stack:
        s = stack.pop()
        if s < len(toks) and toks[s][0] in ("*", "vstar") and s + 1 not in seen:
            seen.add(s + 1)
            stack.append(s + 1)
    return frozenset(seen)


def _step(toks: list[tuple[str, str]], states: frozenset[int], ch: str) -> frozenset[int]:
    nxt: set[int] = set()
    for s in states:
        if s >= len(toks):
            continue
        kind, val = toks[s]
        if kind == "*" or (kind == "vstar" and ch not in _FORBIDDEN_IN_VALUES):
            nxt.add(s)
        elif (
            kind == "?" or (kind == "lit" and val == ch) or (kind == "cls" and fnmatchcase(ch, val))
        ):
            nxt.add(s + 1)
    return _closure(toks, nxt)


def globs_intersect(a: str, b: str) -> bool:
    """True when some string matches both fnmatch patterns *a* and *b*."""
    ta, tb = _tokens(a), _tokens(b)
    alphabet = {v for t in (*ta, *tb) for k, v in [t] if k == "lit"} | {"a"}
    classes = [v for k, v in (*ta, *tb) if k == "cls"]
    alphabet |= {c for c in _ALPHABET if any(fnmatchcase(c, cl) for cl in classes)}
    start = (_closure(ta, {0}), _closure(tb, {0}))
    seen = {start}
    stack = [start]
    while stack:
        sa, sb = stack.pop()
        if len(ta) in sa and len(tb) in sb:
            return True
        for ch in alphabet:
            nxt = (_step(ta, sa, ch), _step(tb, sb, ch))
            if nxt[0] and nxt[1] and nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return False


def _escape_glob(text: str) -> str:
    return "".join(f"[{c}]" if c in "*?[" else c for c in text)


def signature_shapes(registry: ToolRegistry, name: str) -> list[str]:
    """Globs describing every signature a tool can produce (optional parts may be absent)."""
    tool = registry.get_tool(name)
    if tool is None:
        return []
    parts = [p.strip() for p in tool.signature.split(",")] if tool.signature else []
    variants: list[list[str]] = [[]]
    for part in parts:
        refs = re.findall(r"\{(\w+)\}", part)
        glob = "".join(
            _VALUE if seg.startswith("\0") else _escape_glob(seg)
            for seg in re.split(r"(\0)", re.sub(r"\{\w+\}", "\0", part))
        )
        optional = any(not tool.args[r].required for r in refs if r in tool.args)
        variants = [[*v, glob] for v in variants] + (list(variants) if optional else [])
    esc = _escape_glob(name)
    return [f"{esc}({', '.join(v)})" if v else esc for v in variants]


# --- Rule lints --------------------------------------------------------------------------


def _name_part(pattern: str) -> str:
    return pattern.split("(", 1)[0]


def _has_literal(text: str) -> bool:
    return bool(re.sub(r"[*?\[\]!]", "", text).strip())


def _is_glob(text: str) -> bool:
    return any(c in text for c in "*?[")


def lint_permissions(
    label: str, perms: Permissions, registry: ToolRegistry, report: Report
) -> None:
    names = [t.name for t in registry.all_tools()]

    # Unreachable defaults: an earlier default whose pattern covers this one wins first.
    for j, later in enumerate(perms.defaults):
        for earlier in perms.defaults[:j]:
            cover = earlier.pattern
            if "?" not in cover and "[" not in cover and fnmatchcase(later.pattern, cover):
                report.warn(
                    "unreachable-default",
                    label,
                    f"default {later.pattern!r} ({later.action}) can never apply: "
                    f"{earlier.pattern!r} ({earlier.action}) above it matches everything it does",
                )
                break

    for kind, rules in (("default", perms.defaults), ("rule", perms.rules)):
        for rule in rules:
            _lint_rule(label, kind, rule, names, registry, report)


def _lint_rule(
    label: str,
    kind: str,
    rule: PermissionRule,
    names: list[str],
    registry: ToolRegistry,
    report: Report,
) -> None:
    pattern = rule.pattern
    head = _name_part(pattern)
    desc = f"{kind} {pattern!r}"
    if not isinstance(pattern, str):
        report.error("bad-pattern", label, f"{kind} pattern must be a string")
        return
    try:
        re.compile(translate(pattern))
    except re.error:
        report.error("bad-pattern", label, f"{desc} does not compile")
        return
    if kind == "rule" and not _has_literal(head):
        report.warn("rule-names-no-tool", label, f"{desc} names no tool")
        return
    if not _is_glob(head) and head not in names:
        report.error("unknown-tool", label, f"{desc} names unknown tool {head!r}")
        return
    tools = [
        n
        for n in names
        if globs_intersect(pattern, _escape_glob(n))
        or globs_intersect(pattern, _escape_glob(n) + "(*)")
    ]
    if not tools:
        report.warn("pattern-matches-no-tool", label, f"{desc} matches no tool in the registry")
        return
    if not any(globs_intersect(pattern, s) for n in tools for s in signature_shapes(registry, n)):
        report.warn(
            "rule-matches-no-signature",
            label,
            f"{desc} matches no signature that its tools can produce",
        )


# --- Loading -----------------------------------------------------------------------------


def _scan_references(
    paths: Iterable[Path], secret_names: set[str], report: Report, env: dict[str, str]
) -> None:
    for path in paths:
        try:
            text = path.read_text()
        except OSError:
            continue
        seen: set[tuple[str, str]] = set()
        for m in _REF_RE.finditer(text):
            kind = m.group(1) or "env"
            name = m.group(2)
            if (kind, name) in seen:
                continue
            seen.add((kind, name))
            resolved = name in env if kind == "env" else name in secret_names
            report.references.append(Reference(kind, name, str(path), resolved))
            if not resolved:
                what = "environment variable" if kind == "env" else "secret"
                report.error("unresolved-reference", str(path), f"{what} {name} is not set")
            if m.group(1):
                report.warn(
                    "reference-not-substituted",
                    str(path),
                    f"${{{kind}:{name}}} is not substituted by the loader yet; only ${{NAME}} is",
                )


def _secret_names(path: Path) -> set[str]:
    """Key names in secrets.yaml, dotted for nesting. Values are never kept."""
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return set()

    def walk(node: Any, prefix: str) -> set[str]:
        if not isinstance(node, dict):
            return set()
        out: set[str] = set()
        for key, value in node.items():
            full = f"{prefix}{key}"
            out.add(full)
            out |= walk(value, full + ".")
        return out

    return walk(raw, "")


def _unknown_keys(path: Path, allowed: set[str], where: str, report: Report) -> None:
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return  # the real loader reports it
    if isinstance(raw, dict):
        unknown = sorted(map(str, set(raw) - allowed))
        if unknown:
            report.error("unknown-key", str(path), f"unknown {where} key(s): {', '.join(unknown)}")


def _guard(report: Report, where: str, fn: Any, *args: Any) -> Any:
    """Run a loader; turn its failure into one error finding (no traceback, no values)."""
    try:
        return fn(*args)
    except ConfigError as e:
        report.error("config-error", where, str(e))
    except KeyError as e:
        report.error("config-error", where, f"missing required key {e}")
    except Exception as e:  # malformed structure: name the type only, the text may hold values
        report.error("config-error", where, f"invalid structure ({type(e).__name__})")
    return None


def _lint_listen(config: Config, report: Report) -> None:
    """The listen block: socket default, TCP without socket, wildcard, group existence."""
    listen = config.listen
    if listen.tcp is not None and not listen.socket:
        report.warn(
            "tcp-without-socket",
            "listen",
            "TCP is enabled without the Unix socket: access is limited by the agent token only, "
            "not by the agentpass-clients group (set listen.socket)",
        )
    if listen.tcp is not None and is_wildcard_host(listen.tcp.host):
        report.warn(
            "wildcard-listen",
            "listen.tcp",
            f"listen.tcp.host {listen.tcp.host!r} binds every interface "
            "(allow_wildcard: true is set); prefer 127.0.0.1",
        )
    if listen.socket or config.mcp.socket:
        try:
            grp.getgrnam(listen.group)
        except KeyError:
            report.warn(
                "listen-group-missing",
                "listen.group",
                f"group {listen.group!r} does not exist on this host "
                "(the gateway refuses to start without it)",
            )


def _lint_previews(config: Config, registry: ToolRegistry, report: Report) -> None:
    """Preview lints that need the whole registry (the block itself is validated at load)."""
    from agentpass.preview.service import IMPLEMENTED_RENDERERS

    for tool in registry.all_tools():
        where = f"tool {tool.name!r}"
        spec = tool.preview
        if spec is None:
            continue
        service = config.services.get(tool.service_name)
        if spec.lookups and service is not None and service.handler != "http":
            report.warn(
                "preview-lookup-unsupported",
                where,
                f"preview lookups need an http service; {tool.service_name!r} uses "
                f"handler {service.handler!r}, so the preview will be unavailable",
            )
        if spec.renderer not in IMPLEMENTED_RENDERERS:
            report.warn(
                "preview-renderer-unavailable",
                where,
                f"renderer {spec.renderer!r} is not implemented yet; the preview will be "
                "unavailable",
            )


def _lint_health_and_dashboard(config: Config, report: Report) -> None:
    """healthz port must not hit a reserved port; the dashboard on TCP needs auth and warns."""
    reserved = set(config.gateway.reserved_ports)
    health_port = config.gateway.health_port
    if health_port in reserved:
        report.error(
            "reserved-port",
            "gateway.health_port",
            f"gateway.health_port {health_port} is in gateway.reserved_ports; "
            "leave it unset to disable /healthz, or use a free port",
        )
    listen = config.listen
    if listen.admin_socket:
        try:
            grp.getgrnam(listen.admin_group)
        except KeyError:
            report.warn(
                "admin-group-missing",
                "listen.admin_group",
                f"group {listen.admin_group!r} does not exist on this host "
                "(the gateway refuses to start without it)",
            )
    dash = listen.dashboard_tcp
    if dash is None:
        return
    if not dash.admin_token:
        report.error(
            "dashboard-tcp-no-auth",
            "listen.dashboard_tcp",
            "the audit dashboard is on TCP without an admin_token; the audit log holds every "
            "agent's arguments and results, so it must not be served unauthenticated",
        )
    if dash.port in reserved:
        report.error(
            "reserved-port",
            "listen.dashboard_tcp.port",
            f"listen.dashboard_tcp.port {dash.port} is in gateway.reserved_ports",
        )
    report.warn(
        "dashboard-tcp",
        "listen.dashboard_tcp",
        "the audit dashboard is served on TCP: every local user can reach the port and only the "
        "admin token protects it; prefer the admin socket (listen.admin_socket)",
    )


def _tool_files(config: Config, config_dir: Path) -> list[Path]:
    return [config_dir / s.tools_file for s in config.services.values() if s.tools_file]


def check(config_path: str, permissions_path: str, env: dict[str, str] | None = None) -> Report:
    """Validate a deployment's files offline and return the findings."""
    env = dict(os.environ if env is None else env)
    report = Report()
    cfg_file = Path(config_path)
    config_dir = cfg_file.parent

    secrets = _secret_names(config_dir / "secrets.yaml")
    _scan_references([cfg_file, Path(permissions_path)], secrets, report, env)
    _unknown_keys(cfg_file, CONFIG_KEYS, "gateway.yaml", report)
    _unknown_keys(Path(permissions_path), PERMISSIONS_KEYS, "permissions.yaml", report)

    config: Config | None = None
    permissions: Permissions | None = None
    if not any(f.code == "unresolved-reference" for f in report.errors):
        config = _guard(report, config_path, load_config, config_path)
        permissions = _guard(report, permissions_path, load_permissions, permissions_path)
    else:
        report.skipped.append("loading and rule lints (unresolved references above)")

    if config is not None:
        _lint_listen(config, report)
        _lint_health_and_dashboard(config, report)

    agents: list[AgentIdentity] = []
    if config is not None:
        files = _tool_files(config, config_dir)
        _scan_references(files, secrets, report, env)
        for tools_file in files:
            _check_tool_keys(tools_file, report)
        if config.agent.agents_dir:
            agent_dir = Path(config.agent.agents_dir)
            _scan_references(sorted(agent_dir.glob("*.yaml")), secrets, report, env)
            reg = _guard(report, str(agent_dir), load_agents, agent_dir, config.agent.policy_dir)
            agents = reg.all() if reg else []
    registry = _guard(report, "services", build_registry, config.services) if config else None

    if config is not None and registry is not None:
        policies: list[tuple[str, Permissions]] = []
        if permissions is not None:
            policies.append((permissions_path, permissions))
        policies += [(f"agent {a.id}", a.permissions) for a in agents]
        for label, perms in policies:
            lint_permissions(label, perms, registry, report)
            rules = [*perms.defaults, *perms.rules]
            _guard(report, label, validate_rule_channels, rules, config.channels)
            for kind, message in approval_findings(rules, config.channels):
                if kind == "passkey-without-channel":
                    report.error("approval-passkey", label, message)
                else:
                    report.warn("approval", label, message)
        report.summary = {
            "services": len(config.services),
            "tools": len(registry.all_tools()),
            "channels": len(config.channels),
            "agents": len(agents),
            "rule_sets": len(policies),
        }
        _lint_remembered(config, registry, agents, report)
        _lint_previews(config, registry, report)
    elif config is not None or permissions is not None:
        report.skipped.append("rule lints (registry could not be built)")

    _scrub(report, env)
    return report


def _lint_remembered(
    config: Config, registry: ToolRegistry, agents: list[AgentIdentity], report: Report
) -> None:
    """Count active remembered rules (read-only) and flag rules that no longer apply."""
    db_path = Path(config.storage.path)
    if not db_path.exists():
        report.summary["remembered rules active"] = 0
        return
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rules = [dict(r) for r in conn.execute("SELECT * FROM remembered_rules")]
        finally:
            conn.close()
    except sqlite3.Error:
        rules = []  # no table yet (older database) or unreadable: nothing remembered

    by_id = {a.id: a for a in agents}
    engines: dict[str, PermissionEngine] = {}

    def approval_for(agent_id: str, tool: str, signature: str):
        agent = by_id.get(agent_id)
        if agent is None or agent.permissions is None:
            return None
        engine = engines.setdefault(agent_id, PermissionEngine(agent.permissions, registry))
        verdict = engine.evaluate(tool, {}, signature=signature)
        return verdict.approval if verdict.decision is Decision.ASK else None

    known = (lambda agent_id: agent_id in by_id) if agents else (lambda _agent_id: True)
    active = 0
    for rule in rules:
        state, reason = rule_state(
            rule, registry, now_iso=iso(), agent_known=known, approval_for=approval_for
        )
        if state == "active":
            active += 1
        elif state == "inactive":
            report.warn(
                "remembered-inactive",
                f"remembered rule #{rule['id']}",
                f"{rule['agent_id']} {rule['action']} {rule['pattern']} is inactive: {reason}",
            )
    report.summary["remembered rules active"] = active


def _check_tool_keys(path: Path, report: Report) -> None:
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return
    tools = raw.get("tools") if isinstance(raw, dict) else None
    if isinstance(tools, dict):
        for name, body in tools.items():
            if isinstance(body, dict):
                unknown = sorted(map(str, set(body) - TOOL_KEYS))
                if unknown:
                    report.error(
                        "unknown-key",
                        str(path),
                        f"tool {name!r}: unknown key(s): {', '.join(unknown)}",
                    )


def _scrub(report: Report, env: dict[str, str]) -> None:
    """Replace any referenced env value that leaked into a message with ${NAME}."""
    values = {
        env[r.name]: r.name
        for r in report.references
        if r.kind == "env" and r.name in env and len(env[r.name]) >= _MIN_SCRUB_LEN
    }
    for finding in (*report.errors, *report.warnings):
        for value, name in values.items():
            finding.message = finding.message.replace(value, f"${{{name}}}")
            finding.where = finding.where.replace(value, f"${{{name}}}")


# --- Output ------------------------------------------------------------------------------


def format_report(report: Report, strict: bool = False) -> str:
    lines: list[str] = []
    for ref in report.references:
        mark = "ok     " if ref.resolved else "MISSING"
        lines.append(f"  {mark} {ref.kind}:{ref.name}  ({ref.file})")
    if lines:
        lines.insert(0, "References:")
    for title, items in (("Errors", report.errors), ("Warnings", report.warnings)):
        if items:
            lines.append(f"{title}:")
            lines += [f"  [{f.code}] {f.where}: {f.message}" for f in items]
    for note in report.skipped:
        lines.append(f"Skipped: {note}")
    if report.summary:
        lines.append("Checked: " + ", ".join(f"{v} {k}" for k, v in report.summary.items()))
    code = report.exit_code(strict)
    verdict = {0: "OK", 1: "FAILED", 2: "OK with warnings"}[code]
    lines.append(
        f"check-config: {verdict} ({len(report.errors)} errors, {len(report.warnings)} warnings)"
    )
    return "\n".join(lines)


def run_check(args: Any) -> int:
    report = check(args.config, args.permissions)
    if args.json:
        print(json.dumps(report.as_dict(args.strict), indent=2))
    else:
        print(format_report(report, args.strict))
    return report.exit_code(args.strict)
