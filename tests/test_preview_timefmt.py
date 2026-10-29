"""Lookup timestamps shown in approval.display_timezone with a relative age."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentpass.config import ConfigError, load_config, load_tools_file, parse_timezone
from agentpass.preview import Preview, PreviewService
from agentpass.preview.timefmt import TimeFormatter, age
from agentpass.registry import ToolRegistry
from tests.test_preview import FakeLookupService, _load

NOW = datetime(2026, 10, 29, 12, 12, 44, tzinfo=UTC)
RAW = "2026-10-29T08:12:44+00:00"


class TestFormatter:
    def test_zone_and_age_shown(self):
        fmt = TimeFormatter("Europe/Berlin", NOW)
        assert fmt.format(RAW) == "Thu 29 Oct 09:12 Europe/Berlin (4 h ago)"
        assert fmt.seen == [("Thu 29 Oct 09:12 Europe/Berlin (4 h ago)", RAW)]

    def test_default_utc_and_z_suffix(self):
        assert TimeFormatter("UTC", NOW).format("2026-10-29T08:12:44Z") == (
            "Thu 29 Oct 08:12 UTC (4 h ago)"
        )

    def test_offset_input_is_converted(self):
        out = TimeFormatter("Europe/Berlin", NOW).format("2026-10-29T08:12:44-05:00")
        assert out.startswith("Thu 29 Oct 14:12 Europe/Berlin")

    def test_other_year_includes_the_year(self):
        assert "2025" in TimeFormatter("UTC", NOW).format("2025-01-02T03:04:05Z")

    @pytest.mark.parametrize(
        "text", ["locked", "2026-10-29T08:12:44", "2026-10-29", "x2026-10-29T08:12:44Z", ""]
    )
    def test_non_timestamps_and_naive_times_are_left_alone(self, text):
        assert TimeFormatter("UTC", NOW).format(text) is None

    @pytest.mark.parametrize(
        ("seconds", "text"),
        [
            (10, "just now"),
            (120, "2 min ago"),
            (4 * 3600, "4 h ago"),
            (86400, "1 day ago"),
            (3 * 86400, "3 days ago"),
            (-7200, "in 2 h"),
        ],
    )
    def test_age(self, seconds, text):
        assert age(seconds) == text


class TestTimezoneConfig:
    def test_valid_and_invalid(self):
        assert parse_timezone("Europe/Berlin") == "Europe/Berlin"
        for bad in ("Mars/Base", "", 5, "/etc/localtime", "../UTC"):
            with pytest.raises(ConfigError, match="display_timezone"):
                parse_timezone(bad)

    def _config(self, tmp_path: Path, approval: str) -> str:
        (tmp_path / "svc.yaml").write_text("tools:\n  t:\n    request: {method: GET, path: /x}\n")
        path = tmp_path / "gateway.yaml"
        path.write_text(
            "gateway: {host: 127.0.0.1, port: 8205}\nagent: {token: t}\n"
            "messenger: {type: telegram, telegram: {token: t, chat_id: 1, allowed_users: [1]}}\n"
            "services:\n  svc: {url: 'http://x', auth: {type: none}, tools: svc.yaml}\n"
            "storage: {type: sqlite, path: ./a.db}\n" + approval
        )
        return str(path)

    def test_load_config_reads_it_and_defaults_to_utc(self, tmp_path):
        assert load_config(self._config(tmp_path, "")).display_timezone == "UTC"
        cfg = load_config(self._config(tmp_path, "approval: {display_timezone: Europe/Berlin}\n"))
        assert cfg.display_timezone == "Europe/Berlin"

    def test_unknown_zone_is_a_config_error(self, tmp_path):
        with pytest.raises(ConfigError, match="unknown time zone"):
            load_config(self._config(tmp_path, "approval: {display_timezone: Nope/Zone}\n"))
        with pytest.raises(ConfigError, match="unknown key"):
            load_config(self._config(tmp_path, "approval: {tz: UTC}\n"))

    def test_service_rejects_an_unknown_zone_at_start(self):
        with pytest.raises(Exception, match="Nope"):
            PreviewService(ToolRegistry({}), {}, display_timezone="Nope/Zone")


STATE = {
    "state": "locked",
    "last_changed": RAW,
    "attributes": {"friendly_name": "Front door"},
}


async def test_entity_state_last_changed_uses_the_display_zone_and_keeps_the_raw_value():
    tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
    registry = ToolRegistry({t.name: t for t in tools})
    svc = FakeLookupService(json.loads(Path("tests/fixtures/ha/lock_front_door.json").read_text()))
    service = PreviewService(registry, {"homeassistant": svc}, display_timezone="Europe/Berlin")
    p = await service.build(
        "ha_call_service", {"domain": "lock", "service": "unlock", "entity_id": "lock.front_door"}
    )
    assert isinstance(p, Preview)
    shown = dict(p.sections[0].data)["Last changed"]
    assert "09:12 Europe/Berlin" in shown and "ago" in shown
    assert p.lookups[0].raw_times == [f"last_changed: {RAW}"]


TEMPLATE = """
      lookups:
        - id: state
          path: "/api/states/{entity_id}"
      title: "Call"
      fields:
        - { label: Changed, value: "{state.last_changed}" }
        - { label: Entity, value: "{entity_id}" }
      warnings:
        - when: { value: "{state.last_changed}", equals: "%s" }
          text: "changed at {state.last_changed}"
"""


async def test_template_lookup_times_are_formatted_but_args_and_comparisons_stay_raw(tmp_path):

    tool = _load(tmp_path, TEMPLATE % RAW)
    registry = ToolRegistry({"ha_call_service": tool})
    svc = FakeLookupService(STATE)
    p = await PreviewService(registry, {"svc": svc}, display_timezone="Europe/Berlin").build(
        "ha_call_service", {"entity_id": "lock.front"}
    )
    assert isinstance(p, Preview)
    rows = dict(p.sections[0].data)
    assert "Europe/Berlin" in rows["Changed"] and rows["Changed"] != RAW
    assert rows["Entity"] == "lock.front"
    # the warning condition compared the raw value, its text shows the friendly one
    assert len(p.warnings) == 1 and "Europe/Berlin" in p.warnings[0]
    assert p.lookups[0].raw_times == [f"last_changed: {RAW}"]


async def test_confirm_text_stays_raw(tmp_path):
    spec = TEMPLATE.replace(
        'title: "Call"', 'title: "Call"\n      confirm_text: "{state.last_changed}"'
    )
    tool = _load(tmp_path, spec % RAW)
    svc = FakeLookupService(STATE)
    p = await PreviewService(ToolRegistry({"ha_call_service": tool}), {"svc": svc}).build(
        "ha_call_service", {"entity_id": "lock.front"}
    )
    assert isinstance(p, Preview) and p.confirm_text == RAW
