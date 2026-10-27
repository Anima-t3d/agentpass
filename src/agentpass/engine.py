"""Permission engine — signature building, input validation, policy evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import TYPE_CHECKING

from agentpass.config import ApprovalSpec, ArgDefinition, Permissions
from agentpass.models import Decision

if TYPE_CHECKING:
    from agentpass.registry import ToolRegistry

# Characters forbidden in every string that reaches the signature (prevents
# glob/signature injection); free-text args are exempt
FORBIDDEN_CHARS_RE = re.compile(r"[*?\[\](),\x00-\x1f]")


def _check_forbidden(label: str, value: object) -> None:
    """Recursively reject forbidden characters in strings, dict keys and list items."""
    if isinstance(value, str):
        if FORBIDDEN_CHARS_RE.search(value):
            raise ValueError(f"Argument '{label}' contains forbidden characters")
    elif isinstance(value, dict):
        for k, v in value.items():
            _check_forbidden(label, k)
            _check_forbidden(label, v)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _check_forbidden(label, item)


def check_value(label: str, value: object, arg: ArgDefinition) -> None:
    """Check *value* against the declared type and constraints of one arg."""
    t = arg.type
    if t in ("string", "text"):
        if not isinstance(value, str):
            raise ValueError(f"Invalid value for {label}: must be a string")
        if arg.max_length is not None and len(value) > arg.max_length:
            raise ValueError(f"Invalid value for {label}: longer than {arg.max_length}")
        if arg.validate is not None and not re.fullmatch(arg.validate, value):
            raise ValueError(f"Invalid value for {label}: {value!r}")
    elif t in ("integer", "number"):
        ok = isinstance(value, int) if t == "integer" else isinstance(value, (int, float))
        if isinstance(value, bool) or not ok or (isinstance(value, float) and value != value):
            raise ValueError(f"Invalid value for {label}: must be {t}")
        if arg.min is not None and value < arg.min:
            raise ValueError(f"Invalid value for {label}: below {arg.min}")
        if arg.max is not None and value > arg.max:
            raise ValueError(f"Invalid value for {label}: above {arg.max}")
    elif t == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"Invalid value for {label}: must be a boolean")
    elif t == "enum":
        if not any(type(value) is type(v) and value == v for v in arg.values or []):
            raise ValueError(f"Invalid value for {label}: {value!r}")
    elif t == "array":
        if not isinstance(value, list):
            raise ValueError(f"Invalid value for {label}: must be an array")
        if arg.max_items is not None and len(value) > arg.max_items:
            raise ValueError(f"Invalid value for {label}: more than {arg.max_items} items")
        if arg.items is not None:
            for item in value:
                check_value(label, item, arg.items)
    elif t == "object":
        if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
            raise ValueError(f"Invalid value for {label}: must be an object")


def validate_args(tool_name: str, args: dict, registry: ToolRegistry | None = None) -> None:
    """Validate *args* against the tool definition.

    For a tool in *registry*: undeclared args are rejected, required args must be
    present, every value is checked against its declared type and constraints
    (``validate`` is a fullmatch), and the forbidden characters are rejected in
    every arg that reaches the signature (recursively).  Free-text args may
    contain them.  For other tools the forbidden-character check applies to all
    args.
    """
    if not isinstance(args, dict):
        raise ValueError("Arguments must be an object")

    tool = registry.get_tool(tool_name) if registry else None
    if tool is None:
        for key, value in args.items():
            _check_forbidden(str(key), key)
            _check_forbidden(str(key), value)
        return

    for key in args:
        if not isinstance(key, str) or key not in tool.args:
            raise ValueError(f"Unknown argument: {key}")
    for req_arg in registry.get_required_args(tool_name):
        if req_arg not in args:
            raise ValueError(f"Missing required argument: {req_arg}")
    signature_args = registry.get_signature_arg_names(tool_name)
    for key, value in args.items():
        if key in signature_args:
            _check_forbidden(key, value)
            if isinstance(value, (list, tuple, dict)):
                raise ValueError(f"Invalid value for {key}: must be a scalar")
        check_value(key, value, tool.args[key])


def build_signature(tool_name: str, args: dict, registry: ToolRegistry | None = None) -> str:
    """Build a deterministic, matchable signature string.

    When *registry* is provided and contains the tool, the YAML-defined
    signature template is used.  Otherwise sorted-keys fallback applies.

    Examples (with registry):
        build_signature("ha_get_state", {"entity_id": "sensor.temp"}, registry)
        -> "ha_get_state(sensor.temp)"

        build_signature("ha_call_service",
            {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom"},
            registry)
        -> "ha_call_service(light.turn_on, light.bedroom)"
    """
    validate_args(tool_name, args, registry)

    if registry:
        parts = registry.get_signature_parts(tool_name, args)
        if parts is not None:  # Tool found in registry
            return f"{tool_name}({', '.join(parts)})" if parts else tool_name

    # Fallback for tools not in registry: sorted keys for determinism
    parts = [str(args[k]) for k in sorted(args.keys())]
    return f"{tool_name}({', '.join(parts)})" if parts else tool_name


@dataclass(frozen=True)
class Evaluation:
    """A policy verdict and the ``approval`` block of the rule that produced it (if any)."""

    decision: Decision
    approval: ApprovalSpec | None = None


class PermissionEngine:
    """Evaluates tool requests against permission rules."""

    def __init__(self, permissions: Permissions, registry: ToolRegistry | None = None) -> None:
        self._permissions = permissions
        self._registry = registry

    def evaluate(self, tool_name: str, args: dict, signature: str | None = None) -> Evaluation:
        """Evaluate a tool request and return allow/deny/ask with the matched rule's approval.

        Pass *signature* when the caller already built it, so policy, audit and
        approval text all use the same string.
        """
        if signature is None:
            signature = build_signature(tool_name, args, self._registry)

        # Phase 1: Check explicit rules (deny > allow > ask)
        for action_type in ("deny", "allow", "ask"):
            for rule in self._permissions.rules:
                if rule.action == action_type and fnmatch(signature, rule.pattern):
                    return Evaluation(Decision(action_type), rule.approval)

        # Phase 2: Check defaults (first match wins)
        for default in self._permissions.defaults:
            if fnmatch(signature, default.pattern):
                return Evaluation(Decision(default.action), default.approval)

        # Phase 3: Global fallback
        return Evaluation(Decision.ASK)

    def may_permit(self, tool_name: str) -> bool:
        """False when policy denies *tool_name* for every call, with no allow/ask possible.

        Used to hide tools from listings; the pipeline still enforces policy per call.
        Errs towards True: a rule that might match some argument values keeps the tool.
        """
        probes = (tool_name, f"{tool_name}(x)")
        rules = self._permissions.rules
        if any(r.action == "deny" and all(fnmatch(p, r.pattern) for p in probes) for r in rules):
            return False
        if any(r.action != "deny" and _may_match(r.pattern, tool_name) for r in rules):
            return True
        for default in self._permissions.defaults:
            if any(fnmatch(p, default.pattern) for p in probes):
                return default.action != "deny"
        return True  # nothing matches: the fallback is ask


def _may_match(pattern: str, tool_name: str) -> bool:
    """Could *pattern* match some signature of *tool_name* (``tool`` or ``tool(...)``)?"""
    cut = re.search(r"[*?\[]", pattern)
    prefix = pattern[: cut.start()] if cut else pattern
    return prefix.startswith(tool_name) or (cut is not None and tool_name.startswith(prefix))
