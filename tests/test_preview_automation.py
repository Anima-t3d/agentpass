"""Home Assistant automation definitions: the three tools and the ``automation`` renderer."""

from __future__ import annotations

import pytest

from agentpass.config import load_tools_file
from agentpass.engine import validate_args
from agentpass.preview import Preview, Unavailable
from agentpass.registry import ToolRegistry
from agentpass.services.http import GenericHTTPService, HTTPServiceError
from tests.preview_helpers import build, build_any

CONFIG = "/api/config/automation/config/{automation_id}"

CURRENT = {
    "id": "1700000000001",
    "alias": "Hall light at sunset",
    "description": "",
    "mode": "single",
    "triggers": [{"trigger": "sun", "event": "sunset"}],
    "conditions": [],
    "actions": [{"action": "light.turn_on", "target": {"entity_id": "light.hall"}}],
}


def _write(**changes) -> dict:
    args = {
        "automation_id": "1700000000001",
        "alias": "Hall light at sunset",
        "description": "",
        "mode": "single",
        "triggers": [{"trigger": "sun", "event": "sunset"}],
        "conditions": [],
        "actions": [{"action": "light.turn_on", "target": {"entity_id": "light.hall"}}],
    }
    args.update(changes)
    return {k: v for k, v in args.items() if v is not None}


def _tools() -> dict:
    return {t.name: t for t in load_tools_file("tools/homeassistant.yaml", "homeassistant")}


def _section(p: Preview, label: str):
    return next(s for s in p.sections if s.label == label)


async def _set(args, current=CURRENT) -> Preview:
    routes = {CONFIG: current} if not isinstance(current, type(None)) else {}
    return await build("homeassistant", "homeassistant", "ha_set_automation_config", args, routes)


# --- tool definitions ---


def test_the_three_tools_use_the_config_endpoint():
    tools = _tools()
    get, put, delete = (
        tools["ha_get_automation_config"],
        tools["ha_set_automation_config"],
        tools["ha_delete_automation_config"],
    )
    assert (get.request.method, put.request.method, delete.request.method) == (
        "GET",
        "POST",
        "DELETE",
    )
    for tool in (get, put, delete):
        assert tool.request.path == CONFIG
        assert tool.signature == "{automation_id}"
    assert put.risk == delete.risk == "high"
    assert put.preview.renderer == delete.preview.renderer == "automation"
    assert get.preview is None


def test_the_body_is_the_automation_without_its_id():
    put = _tools()["ha_set_automation_config"]
    body = GenericHTTPService._build_body(put, _write(max=3, mode="queued"))
    assert body == {
        "alias": "Hall light at sunset",
        "description": "",
        "mode": "queued",
        "max": 3,
        "triggers": [{"trigger": "sun", "event": "sunset"}],
        "conditions": [],
        "actions": [{"action": "light.turn_on", "target": {"entity_id": "light.hall"}}],
    }


def test_delete_sends_no_body():
    delete = _tools()["ha_delete_automation_config"]
    assert not delete.request.has_body_spec
    assert delete.request.method not in ("POST", "PUT", "PATCH")


@pytest.mark.parametrize("bad", ["../secrets", "a/b", "x" * 65, "", "id with space"])
def test_an_automation_id_is_one_plain_path_segment(bad):
    registry = ToolRegistry(_tools())
    with pytest.raises(ValueError):
        validate_args("ha_get_automation_config", {"automation_id": bad}, registry)


def test_write_needs_triggers_and_actions_as_lists_of_objects():
    registry = ToolRegistry(_tools())
    validate_args("ha_set_automation_config", _write(), registry)
    for broken in (
        {"actions": None},
        {"triggers": None},
        {"actions": ["light.turn_on"]},
        {"triggers": {"trigger": "sun"}},
        {"mode": "sometimes"},
    ):
        args = (
            _write(**broken)
            if None not in broken.values()
            else {k: v for k, v in _write().items() if k not in broken}
        )
        with pytest.raises(ValueError):
            validate_args("ha_set_automation_config", args, registry)


# --- the preview of a write ---


async def test_a_change_shows_a_diff_against_the_current_automation():
    porch = [{"action": "light.turn_on", "target": {"entity_id": "light.porch"}}]
    p = await _set(_write(actions=porch))
    assert p.title == "Change automation Hall light at sunset"
    diff = _section(p, "Changes")
    assert diff.kind == "diff"
    assert "-    entity_id: light.hall" in diff.data
    assert "+    entity_id: light.porch" in diff.data
    facts = dict(_section(p, "Automation").data)
    assert facts["ID"] == "1700000000001"
    assert facts["Mode"] == "changes an existing automation"
    assert facts["Lines"] == "+1 / -1"
    assert "Runs on its own whenever it triggers; its actions are not approved again" in p.warnings
    assert p.digest == p.compute_digest()


async def test_a_new_id_creates_an_automation_and_shows_all_of_it():
    p = await _set(_write(automation_id="porch_motion", alias="Porch motion"), current=None)
    assert p.title == "Create automation Porch motion"
    assert dict(_section(p, "Automation").data)["Mode"] == "creates a new automation"
    text = _section(p, "New automation").data
    assert "+alias: Porch motion" in text
    assert "+- trigger: sun" in text


async def test_the_old_singular_keys_are_compared_as_the_plural_ones():
    legacy = {k: v for k, v in CURRENT.items() if k not in ("triggers", "actions")}
    legacy["trigger"] = CURRENT["triggers"]
    legacy["action"] = CURRENT["actions"]
    p = await _set(_write(), current=legacy)
    assert "The new definition is identical to the current one: no change" in p.warnings
    assert not any(s.kind == "diff" for s in p.sections)


async def test_every_service_it_calls_is_listed_and_passkey_ones_are_warned():
    actions = [
        {"action": "light.turn_on", "target": {"entity_id": "light.hall"}},
        {
            "choose": [
                {
                    "conditions": [],
                    "sequence": [{"service": "lock.unlock", "target": {"entity_id": "lock.front"}}],
                }
            ]
        },
        {"action": "alarm_control_panel.alarm_disarm"},
        {"action": "cover.open_cover"},
        {"action": "homeassistant.restart"},
        {"action": "shell_command.wipe"},
        {"event": "my_event"},
    ]
    p = await _set(_write(actions=actions))
    calls = _section(p, "Calls").data
    assert calls == [
        "light.turn_on",
        "lock.unlock",
        "alarm_control_panel.alarm_disarm",
        "cover.open_cover",
        "homeassistant.restart",
        "shell_command.wipe",
        "event: my_event",
    ]
    for call in ("lock.unlock", "alarm_control_panel.alarm_disarm", "cover.open_cover"):
        text = f"Calls {call}, which needs a passkey when asked directly; here it runs without one"
        assert text in p.warnings
    assert "Calls homeassistant.restart" in p.warnings
    assert "Calls shell_command.wipe" in p.warnings
    assert "Fires event my_event, which can start other automations" in p.warnings
    assert "lock.unlock" in p.summary


async def test_templates_are_flagged():
    actions = [{"action": "{{ states('input_text.svc') }}"}]
    p = await _set(_write(actions=actions))
    assert "Uses templates: what they evaluate to is not shown" in p.warnings
    assert "templated: {{ states('input_text.svc') }}" in _section(p, "Calls").data


async def test_control_and_direction_characters_are_escaped():
    p = await _set(_write(alias="Night‮ lights"))
    assert "‮" not in p.title
    assert "‮" not in _section(p, "Changes").data


async def test_a_failed_lookup_says_so_and_still_shows_the_new_definition():
    p = await _set(_write(), current=HTTPServiceError("HTTP 500"))
    assert any(w.startswith("Current automation could not be read") for w in p.warnings)
    assert dict(_section(p, "Automation").data)["Mode"] == "unknown (lookup failed)"
    assert "+alias: Hall light at sunset" in _section(p, "New automation").data


# --- the preview of a delete ---


async def test_delete_shows_what_is_removed():
    p = await build(
        "homeassistant",
        "homeassistant",
        "ha_delete_automation_config",
        {"automation_id": "1700000000001"},
        {CONFIG: CURRENT},
    )
    assert p.title == "Delete automation Hall light at sunset"
    assert "-alias: Hall light at sunset" in _section(p, "Removed automation").data
    assert "Deletes the automation; this cannot be undone through the gateway" in p.warnings
    assert dict(_section(p, "Automation").data)["Mode"] == "deletes the automation"


async def test_delete_of_a_missing_automation_warns():
    p = await build_any(
        "homeassistant", "homeassistant", "ha_delete_automation_config", {"automation_id": "nope"}
    )
    assert isinstance(p, Preview) and not isinstance(p, Unavailable)
    assert p.title == "Delete automation nope"
    assert "Automation not found: Home Assistant will reject this" in p.warnings
