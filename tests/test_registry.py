"""Tests for agentpass.registry — ToolRegistry and build_registry."""

from __future__ import annotations

import re

import pytest

from agentpass.config import (
    ArgDefinition,
    AuthConfig,
    ConfigError,
    HealthCheckConfig,
    RequestDefinition,
    ResponseDefinition,
    ServiceConfig,
    ToolDefinition,
)
from agentpass.registry import ToolRegistry, build_registry

# --- Helpers ---


def _make_tool(
    name: str,
    service_name: str = "homeassistant",
    signature: str = "",
    args: dict | None = None,
    request: RequestDefinition | None = None,
    response: ResponseDefinition | None = None,
    description: str = "",
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        service_name=service_name,
        signature=signature,
        args=args or {},
        request=request,
        response=response,
        description=description,
    )


def _make_service_config(
    name: str,
    tools: list[ToolDefinition] | None = None,
) -> ServiceConfig:
    return ServiceConfig(
        name=name,
        url="http://localhost:8123",
        auth=AuthConfig(type="bearer", token="test-token"),
        health=HealthCheckConfig(),
        tools=tools or [],
    )


# --- Fixtures ---


@pytest.fixture()
def ha_tools():
    """A set of HA-like tool definitions."""
    return {
        "ha_get_state": _make_tool(
            name="ha_get_state",
            signature="{entity_id}",
            args={
                "entity_id": ArgDefinition(
                    required=True,
                    validate=r"^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)?$",
                ),
            },
            request=RequestDefinition(method="GET", path="/api/states/{entity_id}"),
        ),
        "ha_get_states": _make_tool(
            name="ha_get_states",
            signature="",
            request=RequestDefinition(method="GET", path="/api/states"),
            response=ResponseDefinition(wrap="states"),
        ),
        "ha_call_service": _make_tool(
            name="ha_call_service",
            signature="{domain}.{service}, {entity_id}",
            args={
                "domain": ArgDefinition(required=True, validate=r"^[a-z_][a-z0-9_]*$"),
                "service": ArgDefinition(required=True, validate=r"^[a-z_][a-z0-9_]*$"),
                "entity_id": ArgDefinition(
                    required=False,
                    validate=r"^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)?$",
                ),
            },
            request=RequestDefinition(
                method="POST",
                path="/api/services/{domain}/{service}",
                body_exclude=["domain", "service"],
            ),
            response=ResponseDefinition(wrap="result"),
        ),
    }


@pytest.fixture()
def registry(ha_tools):
    return ToolRegistry(ha_tools)


# --- ToolRegistry tests ---


class TestToolRegistryGetTool:
    def test_get_tool_returns_definition(self, registry):
        tool = registry.get_tool("ha_get_state")
        assert tool is not None
        assert tool.name == "ha_get_state"
        assert tool.signature == "{entity_id}"

    def test_get_tool_unknown_returns_none(self, registry):
        assert registry.get_tool("nonexistent_tool") is None


class TestToolRegistryGetServiceName:
    def test_get_service_name(self, registry):
        assert registry.get_service_name("ha_get_state") == "homeassistant"

    def test_get_service_name_unknown_returns_none(self, registry):
        assert registry.get_service_name("nonexistent_tool") is None


class TestToolRegistrySignatureParts:
    def test_get_signature_parts_call_service(self, registry):
        parts = registry.get_signature_parts(
            "ha_call_service",
            {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom"},
        )
        assert parts == ["light.turn_on", "light.bedroom"]

    def test_get_signature_parts_get_state(self, registry):
        parts = registry.get_signature_parts(
            "ha_get_state",
            {"entity_id": "sensor.temp"},
        )
        assert parts == ["sensor.temp"]

    def test_get_signature_parts_get_states(self, registry):
        parts = registry.get_signature_parts("ha_get_states", {})
        assert parts == []

    def test_get_signature_parts_unknown_tool(self, registry):
        parts = registry.get_signature_parts("unknown_tool", {"a": "1"})
        assert parts is None

    def test_get_signature_parts_missing_arg_is_absent(self, registry):
        parts = registry.get_signature_parts(
            "ha_call_service",
            {"domain": "light", "service": "turn_on"},
        )
        assert parts == ["light.turn_on"]


class TestToolRegistryArgValidators:
    def test_get_arg_validators(self, registry):
        validators = registry.get_arg_validators("ha_get_state")
        assert "entity_id" in validators
        assert isinstance(validators["entity_id"], re.Pattern)
        # Pattern should match valid HA identifiers
        assert validators["entity_id"].match("sensor.temperature")
        assert not validators["entity_id"].match("INVALID")

    def test_get_arg_validators_unknown_tool(self, registry):
        validators = registry.get_arg_validators("nonexistent")
        assert validators == {}


class TestToolRegistryRequiredArgs:
    def test_get_required_args(self, registry):
        required = registry.get_required_args("ha_call_service")
        assert required == {"domain", "service"}

    def test_get_required_args_unknown_tool(self, registry):
        required = registry.get_required_args("nonexistent")
        assert required == set()

    def test_get_required_args_single(self, registry):
        required = registry.get_required_args("ha_get_state")
        assert required == {"entity_id"}


class TestToolRegistryAllTools:
    def test_all_tools(self, registry, ha_tools):
        all_tools = registry.all_tools()
        assert len(all_tools) == len(ha_tools)
        names = {t.name for t in all_tools}
        assert names == set(ha_tools.keys())


# --- build_registry tests ---


class TestBuildRegistry:
    def test_build_registry_aggregates_services(self):
        ha_tool = _make_tool("ha_get_state", service_name="homeassistant")
        custom_tool = _make_tool("custom_action", service_name="custom_svc")

        services = {
            "homeassistant": _make_service_config("homeassistant", tools=[ha_tool]),
            "custom_svc": _make_service_config("custom_svc", tools=[custom_tool]),
        }
        registry = build_registry(services)

        assert registry.get_tool("ha_get_state") is not None
        assert registry.get_tool("custom_action") is not None
        assert registry.get_service_name("ha_get_state") == "homeassistant"
        assert registry.get_service_name("custom_action") == "custom_svc"
        assert len(registry.all_tools()) == 2

    def test_build_registry_duplicate_tool_raises(self):
        tool1 = _make_tool("ha_get_state", service_name="homeassistant")
        tool2 = _make_tool("ha_get_state", service_name="other_service")

        services = {
            "homeassistant": _make_service_config("homeassistant", tools=[tool1]),
            "other_service": _make_service_config("other_service", tools=[tool2]),
        }

        with pytest.raises(ConfigError, match=r"Duplicate tool name.*ha_get_state"):
            build_registry(services)

    def test_build_registry_empty_services(self):
        registry = build_registry({})
        assert len(registry.all_tools()) == 0

    def test_build_registry_service_with_no_tools(self):
        services = {
            "empty_svc": _make_service_config("empty_svc", tools=[]),
        }
        registry = build_registry(services)
        assert len(registry.all_tools()) == 0
