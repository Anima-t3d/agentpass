"""Per-agent identities: token format, agent files, extends and the policy floor.

Token format is ``agp_<id>_<secret>``. Only ``sha256`` of the full token is
stored in the agent file; auth resolves ``<id>`` to an agent and then compares
digests with ``hmac.compare_digest`` (DESIGN section 6).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agentpass.config import ConfigError, PermissionRule, Permissions, parse_approval

TOKEN_PREFIX = "agp_"
AGENT_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_SECRET_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")
_TOKEN_RE = re.compile(r"agp_([a-z0-9][a-z0-9-]{0,31})_([A-Za-z0-9_-]{16,128})")
_HASH_PREFIX = "sha256:"
_VALID_ACTIONS = {"allow", "deny", "ask"}
FLOOR_FILE = "_floor.yaml"

_AGENT_KEYS = {"id", "token_hash", "rate_limit", "max_sessions", "extends", "defaults", "rules"}
_SET_KEYS = {"extends", "defaults", "rules"}
_RATE_KEYS = {"requests_per_minute", "max_pending"}

# Compared against when the id is unknown, so lookup failures cost the same
_DUMMY_HASH = hashlib.sha256(b"agentpass-dummy").hexdigest()


@dataclass
class AgentIdentity:
    """Who is on the other end of a connection."""

    id: str
    name: str = ""
    token_hash: str = ""  # hex sha256 of the full token
    requests_per_minute: int | None = None  # None = gateway default
    max_pending: int | None = None  # None = gateway default
    max_sessions: int | None = None  # None = unlimited
    approval_timeout: int | None = None  # seconds; None = gateway default
    permissions: Permissions | None = None
    engine: Any = None  # PermissionEngine; None = the pipeline default

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.id


# --- Tokens ---


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token(agent_id: str) -> tuple[str, str]:
    """Return (token, token_hash_field). The token is shown once and never stored."""
    if not AGENT_ID_RE.fullmatch(agent_id):
        raise ConfigError(f"Invalid agent id {agent_id!r}: use lowercase letters, digits, '-'")
    token = f"{TOKEN_PREFIX}{agent_id}_{secrets.token_urlsafe(32)}"
    return token, _HASH_PREFIX + hash_token(token)


def parse_token(token: Any) -> str | None:
    """Return the agent id embedded in *token*, or None if malformed."""
    if not isinstance(token, str):
        return None
    m = _TOKEN_RE.fullmatch(token)
    return m.group(1) if m else None


# --- Registry ---


class AgentRegistry:
    """Loaded agents, keyed by id."""

    def __init__(self, agents: list[AgentIdentity] | None = None) -> None:
        self._agents: dict[str, AgentIdentity] = {}
        for agent in agents or []:
            if agent.id in self._agents:
                raise ConfigError(f"Duplicate agent id: {agent.id}")
            self._agents[agent.id] = agent

    def __len__(self) -> int:
        return len(self._agents)

    def get(self, agent_id: str) -> AgentIdentity | None:
        return self._agents.get(agent_id)

    def all(self) -> list[AgentIdentity]:
        return list(self._agents.values())

    def authenticate(self, token: Any) -> AgentIdentity | None:
        """Resolve a presented token to an identity, or None."""
        agent_id = parse_token(token)
        agent = self._agents.get(agent_id) if agent_id else None
        expected = agent.token_hash if agent else _DUMMY_HASH
        presented = hash_token(token) if isinstance(token, str) else ""
        ok = hmac.compare_digest(presented.encode(), expected.encode())
        return agent if (agent is not None and ok) else None


# --- Loading ---


def _read_yaml(path: Path) -> dict:
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from None
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping at top level")
    return raw


def _check_keys(raw: dict, allowed: set[str], path: Path) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError(f"{path}: unknown keys: {', '.join(sorted(unknown))}")


def _parse_rules(items: Any, path: Path, what: str) -> list[PermissionRule]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ConfigError(f"{path}: {what} must be a list")
    out = []
    for item in items:
        if not isinstance(item, dict) or "pattern" not in item or "action" not in item:
            raise ConfigError(f"{path}: each entry in {what} needs pattern and action")
        if item["action"] not in _VALID_ACTIONS:
            raise ConfigError(f"{path}: invalid action {item['action']!r} (must be allow/deny/ask)")
        out.append(
            PermissionRule(
                pattern=str(item["pattern"]),
                action=item["action"],
                description=str(item.get("description", "")),
                approval=parse_approval(item.get("approval"), str(path), str(item["pattern"])),
            )
        )
    return out


def load_floor(policy_dir: Path) -> list[PermissionRule]:
    """Gateway-wide deny rules (policy/_floor.yaml). Missing file means no floor."""
    path = policy_dir / FLOOR_FILE
    if not path.exists():
        return []
    raw = _read_yaml(path)
    _check_keys(raw, {"rules"}, path)
    rules = _parse_rules(raw.get("rules"), path, "rules")
    for rule in rules:
        if rule.action != "deny":
            raise ConfigError(f"{path}: the floor may only contain deny rules")
    return rules


def _load_rule_set(
    name: str, policy_dir: Path, seen: tuple[str, ...]
) -> tuple[list[PermissionRule], list[PermissionRule]]:
    """Return (defaults, rules) of a shared rule set, resolving nested extends."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
        raise ConfigError(f"Invalid extends name: {name!r}")
    if name in seen:
        raise ConfigError(f"Circular extends: {' -> '.join((*seen, name))}")
    path = policy_dir / f"{name}.yaml"
    if not path.exists():
        raise ConfigError(f"Rule set not found: {path}")
    raw = _read_yaml(path)
    _check_keys(raw, _SET_KEYS, path)
    defaults = _parse_rules(raw.get("defaults"), path, "defaults")
    rules = _parse_rules(raw.get("rules"), path, "rules")
    for parent in raw.get("extends") or []:
        pd, pr = _load_rule_set(str(parent), policy_dir, (*seen, name))
        defaults += pd
        rules += pr
    return defaults, rules


def _opt_positive_int(value: Any, label: str, path: Path) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{path}: {label} must be a positive integer")
    return value


def load_agent_file(path: Path, policy_dir: Path, floor: list[PermissionRule]) -> AgentIdentity:
    raw = _read_yaml(path)
    _check_keys(raw, _AGENT_KEYS, path)
    agent_id = raw.get("id")
    if not isinstance(agent_id, str) or not AGENT_ID_RE.fullmatch(agent_id):
        raise ConfigError(f"{path}: id must match {AGENT_ID_RE.pattern}")
    if path.stem != agent_id:
        raise ConfigError(f"{path}: file name must match id {agent_id!r}")

    token_hash = raw.get("token_hash")
    if not isinstance(token_hash, str) or not token_hash.startswith(_HASH_PREFIX):
        raise ConfigError(f"{path}: token_hash must be 'sha256:<hex>'")
    digest = token_hash[len(_HASH_PREFIX) :].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ConfigError(f"{path}: token_hash is not a sha256 hex digest")

    rate = raw.get("rate_limit") or {}
    if not isinstance(rate, dict):
        raise ConfigError(f"{path}: rate_limit must be a mapping")
    _check_keys(rate, _RATE_KEYS, path)

    defaults = _parse_rules(raw.get("defaults"), path, "defaults")
    rules = _parse_rules(raw.get("rules"), path, "rules")
    extends = raw.get("extends") or []
    if not isinstance(extends, list):
        raise ConfigError(f"{path}: extends must be a list")
    for name in extends:
        ed, er = _load_rule_set(str(name), policy_dir, ())
        defaults += ed
        rules += er

    # Deny always wins in the engine, so floor denies cannot be overridden
    permissions = Permissions(defaults=defaults, rules=[*floor, *rules])
    return AgentIdentity(
        id=agent_id,
        token_hash=digest,
        requests_per_minute=_opt_positive_int(
            rate.get("requests_per_minute"), "rate_limit.requests_per_minute", path
        ),
        max_pending=_opt_positive_int(rate.get("max_pending"), "rate_limit.max_pending", path),
        max_sessions=_opt_positive_int(raw.get("max_sessions"), "max_sessions", path),
        permissions=permissions,
    )


def load_agents(agents_dir: str | Path, policy_dir: str | Path | None = None) -> AgentRegistry:
    """Load every ``agents/*.yaml``. *policy_dir* defaults to ``<agents_dir>/../policy``."""
    agents_path = Path(agents_dir)
    if not agents_path.is_dir():
        raise ConfigError(f"Agents directory not found: {agents_dir}")
    policy_path = Path(policy_dir) if policy_dir else agents_path.parent / "policy"
    floor = load_floor(policy_path)
    agents = [load_agent_file(p, policy_path, floor) for p in sorted(agents_path.glob("*.yaml"))]
    if not agents:
        raise ConfigError(f"No agent files in {agents_dir}")
    return AgentRegistry(agents)


def write_agent_file(agents_dir: str | Path, agent_id: str) -> str:
    """Create ``agents/<id>.yaml`` with a fresh token hash; return the token (shown once)."""
    token, token_hash = generate_token(agent_id)
    agents_path = Path(agents_dir)
    agents_path.mkdir(parents=True, exist_ok=True)
    path = agents_path / f"{agent_id}.yaml"
    content = (
        f"id: {agent_id}\n"
        f'token_hash: "{token_hash}"\n'
        "rate_limit: { requests_per_minute: 60 }\n"
        "defaults:\n"
        '  - { pattern: "*", action: ask }\n'
        "rules: []\n"
    )
    try:
        with open(path, "x") as f:  # never overwrite an existing identity
            f.write(content)
    except FileExistsError:
        raise ConfigError(f"Agent file already exists: {path}") from None
    path.chmod(0o600)
    return token
