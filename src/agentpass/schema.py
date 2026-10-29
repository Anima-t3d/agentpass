"""JSON Schema generation from tool arg definitions.

``arg_to_json_schema`` is the single converter from YAML arg definitions to
JSON Schema (DESIGN 8.1). It knows nothing about MCP or any transport. The MCP
adapter builds its ``inputSchema`` through ``input_schema``, a thin alias of
``args_to_json_schema`` kept so both card branches share one implementation.
Extend this module rather than adding another converter; a missing ``type``
means ``string``.
"""

from __future__ import annotations

from typing import Any

from agentpass.config import ArgDefinition, ToolDefinition


def arg_to_json_schema(arg: ArgDefinition) -> dict[str, Any]:
    """Return the JSON Schema for one arg definition."""
    t = arg.type or "string"
    schema: dict[str, Any] = {}
    if t in ("string", "text"):
        schema["type"] = "string"
        if arg.max_length is not None:
            schema["maxLength"] = arg.max_length
        if arg.validate:
            # validate is a fullmatch; JSON Schema "pattern" is a search
            schema["pattern"] = f"^(?:{arg.validate})$"
    elif t in ("integer", "number"):
        schema["type"] = t
        if arg.min is not None:
            schema["minimum"] = arg.min
        if arg.max is not None:
            schema["maximum"] = arg.max
    elif t == "boolean":
        schema["type"] = "boolean"
    elif t == "enum":
        schema["enum"] = list(arg.values or [])
    elif t == "array":
        schema["type"] = "array"
        if arg.items is not None:
            schema["items"] = arg_to_json_schema(arg.items)
        if arg.max_items is not None:
            schema["maxItems"] = arg.max_items
    elif t == "object":
        schema["type"] = "object"
    if arg.description:
        schema["description"] = arg.description
    if arg.default is not None:
        schema["default"] = arg.default
    return schema


def args_to_json_schema(args: dict[str, ArgDefinition]) -> dict[str, Any]:
    """Return an object schema for a tool's args (undeclared args are rejected)."""
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {name: arg_to_json_schema(a) for name, a in args.items()},
        "additionalProperties": False,
    }
    required = [name for name, a in args.items() if a.required]
    if required:
        schema["required"] = required
    return schema


AGENT_NOTE_PROPERTY: dict[str, Any] = {
    "type": "string",
    "maxLength": 500,
    "description": (
        "Optional: explain to the human approver why you need this call. "
        "Shown to them as unverified agent text."
    ),
}


def with_gateway_properties(
    schema: dict[str, Any], *, idempotency_key: bool = False
) -> dict[str, Any]:
    """Add the gateway-owned optional properties to a tool's object schema (in place).

    ``agent_note`` (and ``idempotency_key`` on MCP) are popped by the transport adapter
    before the pipeline sees the args, so they are not part of the tool's declared args.
    """
    props = schema.setdefault("properties", {})
    props["agent_note"] = dict(AGENT_NOTE_PROPERTY)
    if idempotency_key:
        props["idempotency_key"] = {"type": "string"}
    return schema


def input_schema(args: dict[str, ArgDefinition]) -> dict[str, Any]:
    """MCP ``inputSchema`` for a tool. Same converter, transport-facing name."""
    return args_to_json_schema(args)


def tool_annotations(tool: ToolDefinition) -> dict[str, bool]:
    """MCP tool annotations derived from the HTTP method and ``risk``."""
    method = tool.request.method if tool.request else ""
    read_only = method == "GET"
    return {
        "readOnlyHint": read_only,
        "destructiveHint": not read_only and (method == "DELETE" or tool.risk == "high"),
    }
