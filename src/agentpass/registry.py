"""Tool registry -- maps tool names to definitions and services."""

from __future__ import annotations

import json
import re

from agentpass.config import ConfigError, ServiceConfig, ToolDefinition

REDACTED = "[redacted]"
AUDIT_RESULT_LIMIT = 2000


class ToolRegistry:
    """Central registry mapping tool names to definitions and services."""

    def __init__(self, tools: dict[str, ToolDefinition]) -> None:
        self._tools = tools
        # Pre-compile arg validators
        self._validators: dict[str, dict[str, re.Pattern]] = {}
        for name, tool in tools.items():
            validators: dict[str, re.Pattern] = {}
            for arg_name, arg_def in tool.args.items():
                if arg_def.validate:
                    validators[arg_name] = re.compile(arg_def.validate)
            self._validators[name] = validators

    def get_tool(self, name: str) -> ToolDefinition | None:
        """Return the tool definition for the given name, or None."""
        return self._tools.get(name)

    def get_service_name(self, name: str) -> str | None:
        """Return the service name for the given tool, or None."""
        tool = self._tools.get(name)
        return tool.service_name if tool else None

    def get_signature_parts(self, name: str, args: dict) -> list[str] | None:
        """Build signature parts from the tool's signature template.

        Template: "{domain}.{service}, {entity_id}"
        Returns: ["light.turn_on", "light.bedroom"]

        Returns None if tool not in registry (caller should use fallback).
        """
        tool = self._tools.get(name)
        if tool is None:
            return None
        if not tool.signature:
            return []
        # Split by ", " to get parts, then interpolate each part
        parts = [p.strip() for p in tool.signature.split(",")]
        result: list[str] = []
        for part in parts:
            # A part referencing an absent arg is omitted, not rendered empty
            keys = re.findall(r"\{(\w+)\}", part)
            if any(k not in args for k in keys):
                continue
            # Replace {arg_name} with actual values, support {a}.{b} composites
            result.append(re.sub(r"\{(\w+)\}", lambda m, _a=args: str(_a[m.group(1)]), part))
        return result

    def get_signature_arg_names(self, name: str) -> set[str]:
        """Return the arg names referenced by the tool's signature template."""
        tool = self._tools.get(name)
        if tool is None or not tool.signature:
            return set()
        return set(re.findall(r"\{(\w+)\}", tool.signature))

    def get_arg_validators(self, name: str) -> dict[str, re.Pattern]:
        """Return pre-compiled regex validators for the tool's args."""
        return self._validators.get(name, {})

    def get_required_args(self, name: str) -> set[str]:
        """Return the set of required argument names for the tool."""
        tool = self._tools.get(name)
        if tool is None:
            return set()
        return {arg_name for arg_name, arg_def in tool.args.items() if arg_def.required}

    def apply_defaults(self, name: str, args: dict) -> dict:
        """Return *args* plus declared defaults for absent args.

        Defaults only affect the executed request; the signature is built from
        the args the agent sent, so it stays stable.
        """
        tool = self._tools.get(name)
        if tool is None:
            return dict(args)
        out = dict(args)
        for arg_name, arg_def in tool.args.items():
            if arg_name not in out and arg_def.default is not None:
                out[arg_name] = arg_def.default
        return out

    def redact_args(self, name: str, args: dict) -> dict:
        """Return *args* with the tool's ``audit.redact_args`` values masked."""
        tool = self._tools.get(name)
        if tool is None or not tool.redact_args:
            return args
        return {k: (REDACTED if k in tool.redact_args else v) for k, v in args.items()}

    def audit_result(self, name: str, result: dict | None) -> dict | None:
        """Return the part of *result* to keep in the audit row (``audit.store_result``)."""
        tool = self._tools.get(name)
        if result is None or tool is None or tool.store_result == "full":
            return result
        if tool.store_result == "none":
            return None
        text = json.dumps(result)
        if len(text) <= AUDIT_RESULT_LIMIT:
            return result
        return {"truncated": text[:AUDIT_RESULT_LIMIT]}

    def all_tools(self) -> list[ToolDefinition]:
        """Return all tool definitions in the registry."""
        return list(self._tools.values())


def build_registry(services: dict[str, ServiceConfig]) -> ToolRegistry:
    """Build a ToolRegistry from all service configurations.

    Raises ConfigError if duplicate tool names found across services.
    """
    all_tools: dict[str, ToolDefinition] = {}
    for svc_name, svc_config in services.items():
        for tool in svc_config.tools:
            if tool.name in all_tools:
                existing = all_tools[tool.name]
                raise ConfigError(
                    f"Duplicate tool name '{tool.name}' in services "
                    f"'{existing.service_name}' and '{svc_name}'"
                )
            all_tools[tool.name] = tool
    return ToolRegistry(all_tools)
