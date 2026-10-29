"""The entity_state renderer over the real tools/homeassistant.yaml and JSON fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from agentpass.config import load_tools_file
from agentpass.preview import Preview, PreviewService, Unavailable
from agentpass.registry import ToolRegistry
from agentpass.services.http import HTTPServiceError
from tests.test_preview import FakeLookupService

FIXTURES = Path(__file__).parent / "fixtures" / "ha"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _service(response=None, error=None) -> tuple[PreviewService, FakeLookupService]:
    tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
    registry = ToolRegistry({t.name: t for t in tools})
    svc = FakeLookupService(response)
    svc.error = error
    return PreviewService(registry, {"homeassistant": svc}), svc


async def _build(args, **kw) -> Preview:
    service, svc = _service(**kw)
    preview = await service.build("ha_call_service", args)
    assert isinstance(preview, Preview)
    preview.svc = svc  # type: ignore[attr-defined]
    return preview


async def test_unlock_front_door_shows_name_and_current_state():
    p = await _build(
        {"domain": "lock", "service": "unlock", "entity_id": "lock.front_door"},
        response=_fixture("lock_front_door"),
    )
    assert p.title == "UNLOCK Front door"
    assert p.summary == "UNLOCK Front door (lock.front_door), now: locked"
    device = dict(p.sections[0].data)
    assert device["Device"] == "Front door" and device["Entity"] == "lock.front_door"
    assert device["Current state"] == "locked" and device["Device class"] == "lock"
    assert dict(p.sections[1].data)["Service"] == "lock.unlock"
    assert p.warnings == [] and p.status == "ok"
    assert p.svc.lookups[0][1]["entity_id"] == "lock.front_door"  # type: ignore[attr-defined]
    assert p.digest == p.compute_digest()


async def test_service_data_is_listed():
    p = await _build(
        {"domain": "light", "service": "turn_on", "entity_id": "light.desk", "brightness": 128},
        response={"state": "off", "attributes": {"friendly_name": "Desk"}},
    )
    assert p.title == "turn on Desk"
    assert ["brightness", "128"] in next(s.data for s in p.sections if s.label == "Service data")


async def test_unknown_service_falls_back_to_the_raw_call():
    p = await _build(
        {"domain": "vacuum", "service": "start", "entity_id": "vacuum.rover"},
        response={"state": "docked", "attributes": {}},
    )
    assert p.title == "call vacuum.start on vacuum.rover"
    assert p.summary.endswith("(vacuum.rover), now: docked")


async def test_no_entity_warns_about_all_targets_and_skips_the_lookup():
    p = await _build({"domain": "light", "service": "turn_off"}, response=_fixture("light_hostile"))
    assert p.warnings == ["No entity specified: this acts on ALL matching targets"]
    assert p.lookups == [] and p.svc.lookups == []  # type: ignore[attr-defined]


async def test_restart_without_entity_names_the_whole_system():
    p = await _build({"domain": "homeassistant", "service": "restart"})
    assert p.title == "RESTART Home Assistant"
    assert p.warnings == ["Acts on the whole Home Assistant system"]


async def test_entity_not_found():
    p = await _build(
        {"domain": "lock", "service": "unlock", "entity_id": "lock.nope"},
        error=HTTPServiceError("HTTP 404"),
    )
    assert "Entity not found" in p.warnings[0]
    assert p.status == "ok" and [(n.id, n.status) for n in p.lookups] == [("state", "failed")]
    assert "now:" not in p.summary


async def test_lookup_failure_keeps_the_preview_without_state():
    p = await _build(
        {"domain": "lock", "service": "unlock", "entity_id": "lock.front_door"},
        error=TimeoutError(),
    )
    assert p.warnings == ["Current state unavailable (timeout)"]
    assert p.title == "UNLOCK lock.front_door"


async def test_script_contents_are_not_shown():
    p = await _build(
        {"domain": "script", "service": "turn_on", "entity_id": "script.goodnight"},
        response=_fixture("script_goodnight"),
    )
    assert p.sections[-1].label == "Not shown" and "contents are not shown" in p.sections[-1].data


async def test_hostile_friendly_name_stays_plain_text_and_bidi_is_escaped():
    p = await _build(
        {"domain": "light", "service": "turn_on", "entity_id": "light.desk"},
        response=_fixture("light_hostile"),
    )
    assert "<img src=x onerror=alert(1)>" in p.title  # plain string: the page escapes it
    assert "‮" not in json.dumps(p.to_dict(), ensure_ascii=False)
    assert "\\u202e" in p.title


async def test_fire_event_warns_about_automations():
    service, svc = _service()
    p = await service.build("ha_fire_event", {"event_type": "my.custom_event"})
    assert isinstance(p, Preview)
    assert p.title == "Fire event my.custom_event"
    assert "may trigger automations" in p.warnings[0].lower()
    assert svc.lookups == []


async def test_a_lookup_never_follows_into_an_execute():
    service, _ = _service(response=_fixture("lock_front_door"))
    p = await service.build(
        "ha_call_service", {"domain": "lock", "service": "unlock", "entity_id": "lock.front_door"}
    )
    assert not isinstance(p, Unavailable)
