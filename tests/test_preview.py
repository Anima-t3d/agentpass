"""Approval previews: config block, sanitising helpers, model, PreviewService."""

from __future__ import annotations

import asyncio
import textwrap
from typing import Any

import pytest

from agentpass.config import ConfigError, load_tools_file
from agentpass.preview import (
    NOTE_LIMIT,
    Preview,
    PreviewService,
    Unavailable,
    escape_unsafe,
    preview_from_json,
    sanitize_note,
    strip_unsafe,
)
from agentpass.registry import ToolRegistry
from agentpass.services.base import ServiceHandler
from agentpass.services.http import HTTPServiceError

BASE = """
tools:
  ha_call_service:
    signature: "{entity_id}"
    args:
      entity_id: { required: true, validate: "[a-z_.]+" }
      brightness: { type: integer }
    request: { method: POST, path: "/c" }
    preview:
__PREVIEW__
"""

GOOD = """
      lookups:
        - id: state
          path: "/api/states/{entity_id}"
          on_error: unavailable
      title: "Call on {state.attributes.friendly_name}"
      summary: "{entity_id} is {state.state}"
      fields:
        - { label: "Device", value: "{state.attributes.friendly_name} ({entity_id})" }
        - { label: "Now", value: "{state.state}" }
      warnings:
        - when: { value: "{state.state}", equals: "unlocked" }
          text: "already unlocked"
"""


def _load(tmp_path, preview: str):
    path = tmp_path / "tools.yaml"
    path.write_text(
        BASE.replace("__PREVIEW__", textwrap.indent(textwrap.dedent(preview), "      "))
    )
    return load_tools_file(str(path), "svc")[0]


def _bad(tmp_path, preview: str, match: str):
    with pytest.raises(ConfigError, match=match):
        _load(tmp_path, preview)


class TestPreviewConfig:
    def test_good_block_parses(self, tmp_path):
        spec = _load(tmp_path, GOOD).preview
        assert spec is not None and spec.renderer == "template"
        assert [lk.id for lk in spec.lookups] == ["state"]
        assert spec.lookups[0].method == "GET" and spec.lookups[0].timeout == 2.0
        assert len(spec.fields) == 2 and spec.warnings[0].comparison == "equals"

    def test_tool_without_block_has_no_preview(self, tmp_path):
        path = tmp_path / "t.yaml"
        path.write_text("tools:\n  t:\n    request: {method: GET, path: /x}\n")
        assert load_tools_file(str(path), "s")[0].preview is None

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_lookup_must_be_get(self, tmp_path, method):
        block = GOOD.replace(
            'path: "/api/states', f'method: {method}\n          path: "/api/states'
        )
        _bad(tmp_path, block, "read-only")

    def test_head_is_allowed(self, tmp_path):
        block = GOOD.replace('path: "/api/states', 'method: HEAD\n          path: "/api/states')
        assert _load(tmp_path, block).preview.lookups[0].method == "HEAD"

    @pytest.mark.parametrize(
        "path", ["http://evil.example/x", "//evil.example/x", "api/states", "/a\\\\b"]
    )
    def test_lookup_host_is_fixed(self, tmp_path, path):
        block = GOOD.replace("/api/states/{entity_id}", path)
        _bad(tmp_path, block, "path")

    def test_lookup_path_arg_must_be_declared_and_required(self, tmp_path):
        _bad(tmp_path, GOOD.replace("/api/states/{entity_id}", "/s/{nope}"), "undeclared")
        _bad(tmp_path, GOOD.replace("/api/states/{entity_id}", "/s/{brightness}"), "required")

    def test_unknown_placeholder_root(self, tmp_path):
        _bad(tmp_path, GOOD.replace('"{state.state}" }', '"{ghost.state}" }', 1), "ghost")
        _bad(tmp_path, GOOD.replace('summary: "{entity_id} is', 'summary: "{nope} is'), "nope")

    def test_lookup_id_collides_with_arg(self, tmp_path):
        _bad(tmp_path, GOOD.replace("id: state", "id: entity_id"), "collides")

    def test_duplicate_lookup_id(self, tmp_path):
        dup = GOOD.replace(
            "      title:",
            '        - id: state\n          path: "/x"\n      title:',
        )
        _bad(tmp_path, dup, "duplicate")

    def test_limits(self, tmp_path):
        _bad(tmp_path, GOOD + "      max_chars: 0\n", "max_chars")
        _bad(tmp_path, GOOD + "      max_chars: 999999\n", "max_chars")
        _bad(tmp_path, GOOD.replace("on_error: unavailable", "on_error: explode"), "on_error")
        _bad(tmp_path, GOOD.replace("on_error: unavailable", "timeout: 60"), "timeout")
        many = "".join(f'        - id: l{i}\n          path: "/x"\n' for i in range(6))
        _bad(
            tmp_path,
            "      lookups:\n" + many + "      fields:\n        - {label: a, value: b}\n",
            "at most",
        )

    def test_template_needs_fields_and_known_keys(self, tmp_path):
        _bad(tmp_path, "      title: x\n", "at least one field")
        _bad(tmp_path, GOOD + "      colour: red\n", "unknown key")
        _bad(tmp_path, GOOD + "      renderer: nonsense\n", "unknown renderer")

    def test_bad_warning_comparison(self, tmp_path):
        bad = GOOD.replace("equals:", "matches:")
        _bad(tmp_path, bad, "exactly one of")

    def test_builtin_renderer_keeps_own_params(self, tmp_path):
        block = '      renderer: entity_state\n      entity: "{entity_id}"\n'
        spec = _load(tmp_path, block).preview
        assert spec.renderer == "entity_state" and spec.params == {"entity": "{entity_id}"}

    @pytest.mark.parametrize("name", ["agent_note", "idempotency_key"])
    def test_reserved_arg_names_rejected(self, tmp_path, name):
        path = tmp_path / "t.yaml"
        path.write_text(
            f"tools:\n  t:\n    args:\n      {name}: {{}}\n    request: {{method: GET, path: /x}}\n"
        )
        with pytest.raises(ConfigError, match="reserved"):
            load_tools_file(str(path), "s")


class TestSanitize:
    def test_escape_shows_bidi_and_control(self):
        out = escape_unsafe("a\u202eb\x00c\x1bd\nok\t")
        assert out == "a\\u202eb\\u0000c\\u001bd\nok\t"

    def test_strip_removes_everything_unsafe(self):
        assert strip_unsafe("a\u202eb\u200bc\x00d\ne") == "abcde"

    def test_note_rules(self):
        assert sanitize_note(None) is None
        assert sanitize_note("   \n\t ") is None
        assert sanitize_note("fix  the\nbug\u202e now") == "fix the bug now"
        long = sanitize_note("x" * 10000)
        assert long is not None and len(long) == NOTE_LIMIT and long.endswith("…")

    @pytest.mark.parametrize("bad", [5, ["a"], {"a": 1}, True])
    def test_note_must_be_string(self, bad):
        with pytest.raises(ValueError, match="string"):
            sanitize_note(bad)


class FakeLookupService(ServiceHandler):
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}
        self.lookups: list[tuple[str, dict]] = []
        self.delay = 0.0
        self.error: Exception | None = None

    async def execute(self, tool_name, args):
        raise AssertionError("a preview must never execute a tool")

    async def lookup(self, path, args, *, query=None, timeout=2.0, max_bytes=262144):
        self.lookups.append((path, dict(args)))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return self.responses

    async def health_check(self):
        return True

    async def close(self):
        pass


STATE = {"state": "locked", "attributes": {"friendly_name": "Front door"}}


def _service(tmp_path, preview: str = GOOD, response=None, **kw):
    registry = ToolRegistry({"ha_call_service": _load(tmp_path, preview)})
    svc = FakeLookupService(STATE if response is None else response)
    return PreviewService(registry, {"svc": svc}, **kw), svc


class TestPreviewService:
    async def test_template_with_lookup(self, tmp_path):
        service, svc = _service(tmp_path)
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert isinstance(p, Preview)
        assert p.title == "Call on Front door"
        assert p.summary == "lock.front is locked"
        assert p.sections[0].data == [["Device", "Front door (lock.front)"], ["Now", "locked"]]
        assert p.warnings == [] and p.status == "ok"
        assert [(n.id, n.status) for n in p.lookups] == [("state", "ok")]
        assert p.digest and p.digest == p.compute_digest()
        assert svc.lookups[0][0] == "/api/states/{entity_id}"

    async def test_warning_fires(self, tmp_path):
        service, _ = _service(tmp_path, response={**STATE, "state": "unlocked"})
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert p.warnings == ["already unlocked"]

    async def test_no_block_returns_none(self, tmp_path):
        service, _ = _service(tmp_path)
        assert await service.build("unknown_tool", {}) is None

    async def test_values_are_escaped_and_capped(self, tmp_path):
        evil = {"state": "x\u202e" + "y" * 5000, "attributes": {"friendly_name": "n\x00"}}
        service, _ = _service(tmp_path, response=evil)
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        now = dict(p.sections[0].data)["Now"]
        assert "\u202e" not in now and "\\u202e" in now
        assert len(now) <= 2000 and now.endswith("…")
        assert "\x00" not in p.title

    async def test_lookup_failure_is_unavailable_not_exception(self, tmp_path):
        service, svc = _service(tmp_path)
        svc.error = HTTPServiceError("HTTP 404")
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert isinstance(p, Unavailable)
        assert p.reason == "lookup state failed (HTTP 404)"
        assert p.status.startswith("unavailable:")

    async def test_on_error_omit_drops_fields_only(self, tmp_path):
        block = GOOD.replace("on_error: unavailable", "on_error: omit") + (
            '      confirm_text: "{entity_id}"\n'
        )
        block = block.replace(
            '        - { label: "Now", value: "{state.state}" }',
            '        - { label: "Now", value: "{state.state}" }\n'
            '        - { label: "Id", value: "{entity_id}" }',
        )
        service, svc = _service(tmp_path, block)
        svc.error = HTTPServiceError("HTTP 500")
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert isinstance(p, Preview)
        assert p.sections[0].data == [["Id", "lock.front"]]
        assert p.title == "ha_call_service"  # unresolved title falls back to the tool name
        assert p.lookups[0].status == "failed" and p.confirm_text == "lock.front"

    async def test_all_fields_unresolved_is_unavailable(self, tmp_path):
        service, svc = _service(tmp_path, GOOD.replace("on_error: unavailable", "on_error: omit"))
        svc.error = TimeoutError()
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert isinstance(p, Unavailable)

    async def test_overall_timeout(self, tmp_path):
        service, svc = _service(tmp_path, timeout=0.05)
        svc.delay = 5
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert p == Unavailable("timeout", p.built_at)

    async def test_lookup_timeout_is_a_lookup_failure(self, tmp_path):
        block = GOOD.replace("on_error: unavailable", "timeout: 0.05")
        service, svc = _service(tmp_path, block, timeout=5)
        svc.delay = 5
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert isinstance(p, Unavailable) and "timeout" in p.reason

    async def test_unexpected_error_is_contained(self, tmp_path):
        service, svc = _service(tmp_path)
        svc.error = RuntimeError("secret detail")
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert isinstance(p, Unavailable)
        assert "secret" not in p.reason

    async def test_service_without_lookup_support(self, tmp_path):
        class Plain(FakeLookupService):
            async def lookup(self, *a, **k):
                return await ServiceHandler.lookup(self, *a, **k)

        registry = ToolRegistry({"ha_call_service": _load(tmp_path, GOOD)})
        service = PreviewService(registry, {"svc": Plain()})
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert isinstance(p, Unavailable) and "not supported" in p.reason

    async def test_builtin_renderer_not_yet_available(self, tmp_path):
        block = "      renderer: email\n"
        service, _ = _service(tmp_path, block)
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert isinstance(p, Unavailable) and p.reason == "renderer not available"

    async def test_oversized_preview_is_truncated_and_labelled(self, tmp_path):
        big = {"state": "s" * 1900, "attributes": {"friendly_name": "n"}}
        service, _ = _service(tmp_path, response=big, max_bytes=1000)
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert p.truncated and p.status == "partial" and "preview is partial" in p.warnings
        assert p.sections == []

    async def test_a_preview_never_issues_non_get_work(self, tmp_path):
        service, svc = _service(tmp_path)
        await service.build("ha_call_service", {"entity_id": "lock.front"})
        assert len(svc.lookups) == 1  # execute() would have raised


class TestModel:
    async def test_roundtrip_and_digest_changes(self, tmp_path):
        service, _ = _service(tmp_path)
        p = await service.build("ha_call_service", {"entity_id": "lock.front"})
        back = preview_from_json(__import__("json").dumps(p.to_dict()))
        assert back == p
        other = Preview.from_dict(p.to_dict())
        other.title = "changed"
        assert other.compute_digest() != p.digest

    def test_unavailable_roundtrip_and_garbage(self):
        u = Unavailable("timeout", "2026-01-01T00:00:00Z")
        import json

        assert preview_from_json(json.dumps(u.to_dict())) == u
        assert preview_from_json("not json") is None
        assert preview_from_json(None) is None
        assert preview_from_json('{"x": 1}') is None
