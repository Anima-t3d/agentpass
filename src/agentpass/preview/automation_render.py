"""The ``automation`` renderer: ``ha_set_automation_config`` and ``ha_delete_automation_config``.

The new definition is the validated args; the current one comes from a trusted lookup of
``GET /api/config/automation/config/{automation_id}`` (lookup id ``current``). Both are shown
as YAML, the way Home Assistant's own editor shows them, and diffed.

An automation runs on its own whenever it triggers, so a write is approved once for every
later run. The preview lists every service the automation calls and warns about the ones a
direct call would need a passkey for.
"""

from __future__ import annotations

from typing import Any

import yaml

from agentpass.config import ToolDefinition
from agentpass.preview.diff_render import DEFAULT_MAX_DIFF_CHARS, DEFAULT_MAX_LINES, _diff_lines
from agentpass.preview.model import LookupNote, Preview, Section
from agentpass.preview.renderers import _cap, _lookup_note, _text

# Key order of Home Assistant's editor; anything else follows in its own order.
_ORDER = ("alias", "description", "mode", "max", "variables", "triggers", "conditions", "actions")
_LEGACY = {"trigger": "triggers", "condition": "conditions", "action": "actions"}
# Domains whose direct calls need a passkey (policy floor); inside an automation they do not.
_PASSKEY_DOMAINS = ("lock", "alarm_control_panel", "cover")
# Calls worth a warning of their own: whole-system, add-ons, shell and outbound requests.
_NOTABLE_DOMAINS = ("homeassistant", "hassio", "shell_command", "rest_command", "python_script")
_RUNS_ALONE = "Runs on its own whenever it triggers; its actions are not approved again"


def _normalised(config: dict[str, Any]) -> dict[str, Any]:
    """The definition without its id, with the old singular keys renamed, in editor order."""
    data = {_LEGACY.get(k, k): v for k, v in config.items() if k != "id"}
    ordered = {k: data[k] for k in _ORDER if k in data}
    ordered.update({k: v for k, v in data.items() if k not in ordered})
    return ordered


def _yaml(config: dict[str, Any]) -> str:
    return yaml.safe_dump(config, sort_keys=False, allow_unicode=True, default_flow_style=False)


def _is_template(value: str) -> bool:
    return "{{" in value or "{%" in value


def _walk(node: Any, calls: list[str], flags: dict[str, bool]) -> None:
    """Collect service calls and fired events from actions, in order, recursively."""
    if isinstance(node, dict):
        for key in ("action", "service"):
            value = node.get(key)
            if isinstance(value, str):
                calls.append(f"templated: {value}" if _is_template(value) else value)
        event = node.get("event")
        if isinstance(event, str) and ("action" not in node and "trigger" not in node):
            calls.append(f"event: {event}")
        for value in node.values():
            _walk(value, calls, flags)
    elif isinstance(node, list):
        for item in node:
            _walk(item, calls, flags)
    elif isinstance(node, str) and _is_template(node):
        flags["template"] = True


def _call_warnings(calls: list[str], flags: dict[str, bool]) -> list[str]:
    out: list[str] = []
    for call in calls:
        if call.startswith("event: "):
            out.append(f"Fires event {call[7:]}, which can start other automations")
        elif call.startswith("templated: "):
            out.append("Calls a service named by a template: which one is not shown")
        elif call.split(".", 1)[0] in _PASSKEY_DOMAINS:
            out.append(
                f"Calls {call}, which needs a passkey when asked directly; here it runs without one"
            )
        elif call.split(".", 1)[0] in _NOTABLE_DOMAINS:
            out.append(f"Calls {call}")
    if flags.get("template"):
        out.append("Uses templates: what they evaluate to is not shown")
    return out


def render_automation(
    definition: ToolDefinition,
    values: dict[str, Any],
    notes: list[LookupNote],
    *,
    params: dict[str, Any],
    max_chars: int,
    built_at: str,
) -> Preview:
    deleting = definition.request is not None and definition.request.method == "DELETE"
    max_lines = int(params.get("max_lines", DEFAULT_MAX_LINES))
    max_diff_chars = int(params.get("max_diff_chars", DEFAULT_MAX_DIFF_CHARS))
    automation_id = _text(values.get("automation_id", ""), 100)
    warnings: list[str] = []

    note = _lookup_note(notes, "current")
    current = values.get("current") if isinstance(values.get("current"), dict) else None
    missing = note is not None and note.status == "failed" and note.detail == "HTTP 404"
    unreadable = note is not None and note.status == "failed" and not missing
    if unreadable:
        warnings.append(f"Current automation could not be read ({_text(note.detail, 80)})")
    old = _normalised(current) if current is not None else None

    if deleting:
        new = None
        mode = "deletes the automation"
        label, verb = "Removed automation", "Delete"
        warnings.insert(0, "Deletes the automation; this cannot be undone through the gateway")
        if missing:
            warnings.append("Automation not found: Home Assistant will reject this")
    else:
        new = _normalised({k: v for k, v in values.items() if k in _ORDER})
        if old is not None:
            mode, label, verb = "changes an existing automation", "Changes", "Change"
        elif missing:
            mode, label, verb = "creates a new automation", "New automation", "Create"
        else:
            mode, label, verb = "unknown (lookup failed)", "New automation", "Write"
        warnings.insert(0, _RUNS_ALONE)

    name_from = new if new is not None else old
    alias = name_from.get("alias") if name_from else None
    name = _text(alias if isinstance(alias, str) and alias else automation_id, max_chars)

    sections: list[Section] = []
    added = removed = 0
    truncated = False
    shown = new if new is not None else old
    calls: list[str] = []
    flags: dict[str, bool] = {}
    if shown is not None:
        # Calls come from the actions only; a legacy trigger also has an "event" key
        _walk(shown.get("actions", []), calls, flags)
        _walk({k: v for k, v in shown.items() if k != "actions"}, [], flags)
    calls = list(dict.fromkeys(_text(c, max_chars) for c in calls))
    if not deleting:
        warnings.extend(_call_warnings(calls, flags))

    before = _yaml(old) if old is not None and (deleting or label == "Changes") else ""
    after = _yaml(new) if new is not None else ""
    identical = not deleting and old is not None and old == new
    if identical:
        warnings.append("The new definition is identical to the current one: no change")
    elif before or after:
        text, added, removed, truncated = _diff_lines(
            before, after, "automation", max_lines, max_diff_chars
        )
        sections.append(Section("diff", label, text))

    facts = [["Name", name], ["ID", automation_id], ["Mode", mode]]
    if sections:
        facts.append(["Lines", f"+{added} / -{removed}"])
    head = [Section("kv", "Automation", facts)]
    if calls:
        head.append(Section("list", "Calls", calls))

    title = f"{verb} automation {name}"
    summary = title
    if sections:
        summary += f": +{added} -{removed}"
    guarded = [c for c in calls if c.split(".", 1)[0] in _PASSKEY_DOMAINS]
    if guarded and not deleting:
        summary += f"; calls {', '.join(guarded)}"
    return Preview(
        title=_cap(title),
        summary=_cap(summary),
        built_at=built_at,
        sections=head + sections,
        warnings=list(dict.fromkeys(warnings)),
        lookups=notes,
        truncated=truncated,
    )
