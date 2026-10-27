"""Tests for agentpass.engine — signature building, validation, permission evaluation."""

import pytest

from agentpass.config import (
    AuthConfig,
    PermissionRule,
    Permissions,
    ServiceConfig,
    load_tools_file,
)
from agentpass.engine import PermissionEngine, build_signature, validate_args
from agentpass.models import Decision
from agentpass.registry import build_registry


@pytest.fixture()
def ha_registry():
    """Build a ToolRegistry from the actual HA tools YAML file."""
    tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
    svc = ServiceConfig(
        name="homeassistant",
        url="http://ha",
        auth=AuthConfig(type="bearer", token="x"),
        tools=tools,
    )
    return build_registry({"homeassistant": svc})


class TestBuildSignature:
    def test_unknown_tool_sorted_keys(self):
        sig = build_signature("unknown_tool", {"b": "2", "a": "1"})
        assert sig == "unknown_tool(1, 2)"

    def test_unknown_tool_no_args(self):
        sig = build_signature("no_args_tool", {})
        assert sig == "no_args_tool"


class TestValidateArgs:
    def test_rejects_asterisk(self):
        with pytest.raises(ValueError, match="forbidden"):
            validate_args("ha_get_state", {"entity_id": "light.*"})

    def test_rejects_question_mark(self):
        with pytest.raises(ValueError, match="forbidden"):
            validate_args("ha_get_state", {"entity_id": "light.?"})

    def test_rejects_bracket(self):
        with pytest.raises(ValueError, match="forbidden"):
            validate_args("ha_get_state", {"entity_id": "light.[a]"})

    def test_rejects_parenthesis(self):
        with pytest.raises(ValueError, match="forbidden"):
            validate_args("ha_get_state", {"entity_id": "light.(x)"})

    def test_rejects_comma(self):
        with pytest.raises(ValueError, match="forbidden"):
            validate_args("ha_get_state", {"entity_id": "a,b"})

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError, match="forbidden"):
            validate_args("ha_get_state", {"entity_id": "light\x00hack"})

    def test_rejects_control_char(self):
        with pytest.raises(ValueError, match="forbidden"):
            validate_args("ha_get_state", {"entity_id": "light\x01"})

    def test_skips_non_string_values(self):
        # Should not raise — non-string values are skipped
        validate_args("some_tool", {"key": "valid", "number": 255})

    def test_non_ha_tool_still_rejects_forbidden_chars(self):
        with pytest.raises(ValueError, match="forbidden"):
            validate_args("custom_tool", {"key": "value*"})


class TestPermissionEngine:
    @staticmethod
    def _make_permissions(
        defaults: list[tuple[str, str]] | None = None,
        rules: list[tuple[str, str]] | None = None,
    ) -> Permissions:
        return Permissions(
            defaults=[PermissionRule(pattern=p, action=a) for p, a in (defaults or [])],
            rules=[PermissionRule(pattern=p, action=a) for p, a in (rules or [])],
        )

    def test_deny_rule_wins(self, ha_registry):
        perms = self._make_permissions(
            rules=[
                ("ha_call_service(lock.*)", "deny"),
                ("ha_call_service(lock.front_door)", "allow"),
            ],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate(
            "ha_call_service",
            {
                "domain": "lock",
                "service": "lock",
                "entity_id": "lock.front_door",
            },
        )
        assert result.decision == Decision.DENY

    def test_allow_rule_when_no_deny(self, ha_registry):
        perms = self._make_permissions(
            rules=[("ha_get_state(sensor.*)", "allow")],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate("ha_get_state", {"entity_id": "sensor.temp"})
        assert result.decision == Decision.ALLOW

    def test_ask_rule_when_no_deny_or_allow(self, ha_registry):
        perms = self._make_permissions(
            rules=[("ha_call_service(light.*)", "ask")],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate(
            "ha_call_service",
            {
                "domain": "light",
                "service": "turn_on",
                "entity_id": "light.bedroom",
            },
        )
        assert result.decision == Decision.ASK

    def test_falls_through_to_defaults(self, ha_registry):
        perms = self._make_permissions(
            defaults=[
                ("ha_get_*", "allow"),
                ("*", "ask"),
            ],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate("ha_get_state", {"entity_id": "sensor.temp"})
        assert result.decision == Decision.ALLOW

    def test_defaults_first_match_wins(self, ha_registry):
        perms = self._make_permissions(
            defaults=[
                ("ha_call_service*", "ask"),
                ("*", "deny"),
            ],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate(
            "ha_call_service",
            {
                "domain": "light",
                "service": "turn_on",
                "entity_id": "light.bedroom",
            },
        )
        assert result.decision == Decision.ASK

    def test_global_fallback_is_ask(self):
        perms = self._make_permissions()  # No rules, no defaults
        engine = PermissionEngine(perms)
        result = engine.evaluate("unknown_tool", {"key": "value"})
        assert result.decision == Decision.ASK

    def test_deny_overrides_more_specific_allow(self, ha_registry):
        # Broad deny + specific allow → deny wins
        perms = self._make_permissions(
            rules=[
                ("ha_call_service(lock.*)", "deny"),
                ("ha_call_service(lock.front_door, lock.front_door)", "allow"),
            ],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate(
            "ha_call_service",
            {
                "domain": "lock",
                "service": "front_door",
                "entity_id": "lock.front_door",
            },
        )
        assert result.decision == Decision.DENY

    def test_rules_checked_before_defaults(self, ha_registry):
        perms = self._make_permissions(
            defaults=[("ha_get_*", "ask")],
            rules=[("ha_get_state(sensor.*)", "allow")],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate("ha_get_state", {"entity_id": "sensor.temp"})
        assert result.decision == Decision.ALLOW

    def test_no_args_tool_matching(self, ha_registry):
        perms = self._make_permissions(
            defaults=[("ha_get_*", "allow")],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate("ha_get_states", {})
        assert result.decision == Decision.ALLOW

    def test_ha_fire_event_deny_default(self, ha_registry):
        perms = self._make_permissions(
            defaults=[("ha_fire_event(*)", "deny")],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate("ha_fire_event", {"event_type": "test_event"})
        assert result.decision == Decision.DENY


# --- Registry-aware tests ---


class TestBuildSignatureWithRegistry:
    """Tests for build_signature() when a ToolRegistry is provided."""

    def test_ha_call_service(self, ha_registry):
        sig = build_signature(
            "ha_call_service",
            {
                "domain": "light",
                "service": "turn_on",
                "entity_id": "light.bedroom",
            },
            registry=ha_registry,
        )
        assert sig == "ha_call_service(light.turn_on, light.bedroom)"

    def test_ha_get_state(self, ha_registry):
        sig = build_signature(
            "ha_get_state",
            {"entity_id": "sensor.temp"},
            registry=ha_registry,
        )
        assert sig == "ha_get_state(sensor.temp)"

    def test_ha_get_states(self, ha_registry):
        sig = build_signature("ha_get_states", {}, registry=ha_registry)
        assert sig == "ha_get_states"

    def test_ha_fire_event(self, ha_registry):
        sig = build_signature(
            "ha_fire_event",
            {"event_type": "my_event"},
            registry=ha_registry,
        )
        assert sig == "ha_fire_event(my_event)"

    def test_unknown_tool_falls_back_to_sorted_keys(self, ha_registry):
        """Tool not in registry uses sorted keys fallback."""
        sig = build_signature(
            "unknown_tool",
            {"b": "2", "a": "1"},
            registry=ha_registry,
        )
        assert sig == "unknown_tool(1, 2)"

    def test_ha_call_service_without_entity_id(self, ha_registry):
        sig = build_signature(
            "ha_call_service",
            {
                "domain": "homeassistant",
                "service": "restart",
            },
            registry=ha_registry,
        )
        assert sig == "ha_call_service(homeassistant.restart)"

    def test_ha_call_service_field_order_irrelevant(self, ha_registry):
        sig1 = build_signature(
            "ha_call_service",
            {
                "entity_id": "light.bedroom",
                "domain": "light",
                "service": "turn_on",
            },
            registry=ha_registry,
        )
        sig2 = build_signature(
            "ha_call_service",
            {
                "domain": "light",
                "service": "turn_on",
                "entity_id": "light.bedroom",
            },
            registry=ha_registry,
        )
        assert sig1 == sig2


class TestValidateArgsWithRegistry:
    """Tests for validate_args() when a ToolRegistry is provided."""

    def test_required_arg_missing_raises(self, ha_registry):
        with pytest.raises(ValueError, match="Missing required argument"):
            validate_args("ha_get_state", {}, registry=ha_registry)

    def test_required_arg_present_passes(self, ha_registry):
        # Should not raise
        validate_args(
            "ha_get_state",
            {"entity_id": "sensor.temp"},
            registry=ha_registry,
        )

    def test_arg_validation_pattern_rejects(self, ha_registry):
        with pytest.raises(ValueError, match="Invalid value for"):
            validate_args(
                "ha_get_state",
                {"entity_id": "UPPERCASE.NOT_VALID"},
                registry=ha_registry,
            )

    def test_arg_validation_pattern_accepts(self, ha_registry):
        # Should not raise — valid HA identifier format
        validate_args(
            "ha_get_state",
            {"entity_id": "sensor.living_room_temp"},
            registry=ha_registry,
        )

    def test_forbidden_chars_still_checked(self, ha_registry):
        """Even with registry, FORBIDDEN_CHARS_RE applies before registry validation."""
        with pytest.raises(ValueError, match="forbidden"):
            validate_args(
                "ha_get_state",
                {"entity_id": "sensor.*"},
                registry=ha_registry,
            )

    def test_optional_arg_missing_is_ok(self, ha_registry):
        """ha_call_service has optional entity_id — missing is fine."""
        validate_args(
            "ha_call_service",
            {"domain": "homeassistant", "service": "restart"},
            registry=ha_registry,
        )

    def test_undeclared_args_rejected(self, ha_registry):
        """Args not declared in the tool YAML are rejected."""
        with pytest.raises(ValueError, match="Unknown argument: color_mode"):
            validate_args(
                "ha_call_service",
                {
                    "domain": "light",
                    "service": "turn_on",
                    "entity_id": "light.bedroom",
                    "color_mode": "x",
                },
                registry=ha_registry,
            )


class TestPermissionEngineWithRegistry:
    """Tests for PermissionEngine when a ToolRegistry is provided."""

    @staticmethod
    def _make_permissions(
        defaults: list[tuple[str, str]] | None = None,
        rules: list[tuple[str, str]] | None = None,
    ) -> Permissions:
        return Permissions(
            defaults=[PermissionRule(pattern=p, action=a) for p, a in (defaults or [])],
            rules=[PermissionRule(pattern=p, action=a) for p, a in (rules or [])],
        )

    def test_evaluate_uses_registry_signature(self, ha_registry):
        """Engine with registry evaluates correctly using registry-built signature."""
        perms = self._make_permissions(
            rules=[("ha_get_state(sensor.*)", "allow")],
        )
        engine = PermissionEngine(perms, registry=ha_registry)
        result = engine.evaluate("ha_get_state", {"entity_id": "sensor.temp"})
        assert result.decision == Decision.ALLOW
