"""Built-in preview renderers (docs/APPROVAL-PREVIEWS.md section 3).

Each is a pure function over the validated args and the lookup results: no network, no
HTML. Every agent-derived or device-derived string goes through ``escape_unsafe`` and a
length cap before it lands in a section.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from agentpass.config import ToolDefinition
from agentpass.preview.model import LookupNote, Preview, Section
from agentpass.preview.sanitize import escape_unsafe
from agentpass.preview.timefmt import TimeFormatter

SUMMARY_LIMIT = 300

# (domain, service) -> (effect, subject suffix). Upper case marks effects that open, release or
# restart something; the rest are routine.
_HA_EFFECTS: dict[tuple[str, str], str] = {
    ("lock", "unlock"): "UNLOCK",
    ("lock", "lock"): "lock",
    ("lock", "open"): "OPEN",
    ("cover", "open_cover"): "OPEN",
    ("cover", "close_cover"): "close",
    ("cover", "stop_cover"): "stop",
    ("alarm_control_panel", "alarm_disarm"): "DISARM",
    ("alarm_control_panel", "alarm_arm_away"): "arm (away)",
    ("alarm_control_panel", "alarm_arm_home"): "arm (home)",
    ("alarm_control_panel", "alarm_arm_night"): "arm (night)",
    ("light", "turn_on"): "turn on",
    ("light", "turn_off"): "turn off",
    ("switch", "turn_on"): "turn on",
    ("switch", "turn_off"): "turn off",
    ("climate", "set_temperature"): "set the temperature of",
    ("script", "turn_on"): "run",
    ("homeassistant", "restart"): "RESTART",
    ("homeassistant", "stop"): "STOP",
}
_WHOLE_SYSTEM = {("homeassistant", "restart"), ("homeassistant", "stop")}
_OPAQUE_DOMAINS = {"script", "scene"}  # what these do is not exposed over the REST API


def _text(value: Any, limit: int) -> str:
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = escape_unsafe(str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _lookup_note(notes: list[LookupNote], lookup_id: str) -> LookupNote | None:
    return next((n for n in notes if n.id == lookup_id), None)


def _cap(text: str) -> str:
    return text if len(text) <= SUMMARY_LIMIT else text[: SUMMARY_LIMIT - 1] + "…"


def render_entity_state(
    definition: ToolDefinition,
    values: dict[str, Any],
    notes: list[LookupNote],
    *,
    max_chars: int,
    built_at: str,
    times: TimeFormatter | None = None,
) -> Preview:
    """``ha_call_service`` and ``ha_fire_event``: which device, what state, what effect.

    The lookup id is ``state`` (``GET /api/states/{entity_id}``). It may be absent (no
    entity, or the lookup failed): the preview then says so instead of guessing.
    """
    if "event_type" in values and "domain" not in values:
        return _render_event(definition, values, notes, max_chars, built_at)
    domain, service = str(values.get("domain", "")), str(values.get("service", ""))
    entity = values.get("entity_id")
    state = values.get("state") if isinstance(values.get("state"), dict) else None
    note = _lookup_note(notes, "state")
    attrs = state.get("attributes") if state and isinstance(state.get("attributes"), dict) else {}
    friendly = attrs.get("friendly_name") if isinstance(attrs.get("friendly_name"), str) else None
    current = state.get("state") if state and state.get("state") is not None else None

    call = _text(f"{domain}.{service}", max_chars)
    effect = _HA_EFFECTS.get((domain, service))
    whole_system = (domain, service) in _WHOLE_SYSTEM
    warnings: list[str] = []
    if entity is None:
        subject = "Home Assistant" if whole_system else "ALL matching targets"
        warnings.append(
            "Acts on the whole Home Assistant system"
            if whole_system
            else "No entity specified: this acts on ALL matching targets"
        )
    else:
        subject = _text(friendly or entity, max_chars)
        if note is not None and note.status == "failed":
            if note.detail == "HTTP 404":
                warnings.append("Entity not found: Home Assistant will reject or ignore this call")
            else:
                warnings.append(f"Current state unavailable ({_text(note.detail, 80)})")

    verb = effect or f"call {call} on"
    if effect is None and entity is None:
        title = f"Call {call}: no entity specified"
    else:
        title = f"{verb} {subject}"
    summary = f"{verb} {subject}"
    if entity is not None:
        summary += f" ({_text(entity, max_chars)})"
        if current is not None:
            summary += f", now: {_text(current, max_chars)}"

    device: list[list[str]] = []
    if entity is not None:
        device.append(["Device", subject])
        device.append(["Entity", _text(entity, max_chars)])
        if current is not None:
            device.append(["Current state", _text(current, max_chars)])
        for key, label in (("device_class", "Device class"),):
            if attrs.get(key):
                device.append([label, _text(attrs[key], max_chars)])
        if state and state.get("last_changed"):
            changed = str(state["last_changed"])
            shown = times.format(changed) if times is not None else None
            device.append(["Last changed", _text(shown or changed, max_chars)])
    sections = []
    if device:
        sections.append(Section("kv", "Device", device))
    sections.append(Section("kv", "Action", [["Service", call], ["Effect", _cap(summary)]]))
    data = [
        [_text(k, max_chars), _text(v, max_chars)]
        for k, v in values.items()
        if k not in ("domain", "service", "entity_id", "state") and v is not None
    ]
    if data:
        sections.append(Section("kv", "Service data", data))
    if domain in _OPAQUE_DOMAINS or (domain, service) == ("automation", "trigger"):
        sections.append(
            Section("text", "Not shown", f"Runs {domain} {subject}; its contents are not shown.")
        )
    return Preview(
        title=_cap(title),
        summary=_cap(summary),
        built_at=built_at,
        sections=sections,
        warnings=warnings,
        lookups=notes,
    )


def _render_event(
    definition: ToolDefinition,
    values: dict[str, Any],
    notes: list[LookupNote],
    max_chars: int,
    built_at: str,
) -> Preview:
    event = _text(values["event_type"], max_chars)
    data = {k: v for k, v in values.items() if k != "event_type" and v is not None}
    body = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) if data else "(none)"
    title = f"Fire event {event}"
    return Preview(
        title=_cap(title),
        summary=_cap(f"{title}; may trigger automations"),
        built_at=built_at,
        sections=[
            Section("kv", "Event", [["Type", event]]),
            Section("text", "Event data", _text(body, max_chars)),
        ],
        warnings=["May trigger automations listening for this event; what they do is not shown"],
        lookups=notes,
    )


def _age_days(raw: Any, built_at: str) -> float | None:
    try:
        then = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        now = datetime.fromisoformat(built_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if then.tzinfo is None or now.tzinfo is None:
        return None
    return (now - then).total_seconds() / 86400


def render_resource_summary(
    values: dict[str, Any],
    notes: list[LookupNote],
    *,
    max_chars: int,
    built_at: str,
    times: TimeFormatter | None = None,
) -> Preview:
    """``gh_delete_repo``: what deleting a repository removes (section 4.4).

    Lookups: ``repo`` (``GET /repos/{owner}/{repo}``) and ``prs`` (an issue search for open
    pull requests, read from ``total_count``). Either may be missing; the preview then says
    what it could not look up instead of guessing.
    """
    owner, name = _text(values.get("owner", ""), 100), _text(values.get("repo", ""), 100)
    full = f"{owner}/{name}"
    repo = values.get("repo_info") if isinstance(values.get("repo_info"), dict) else None
    prs = values.get("prs") if isinstance(values.get("prs"), dict) else None
    repo_note = _lookup_note(notes, "repo_info")
    warnings: list[str] = []

    effect = (
        f"PERMANENTLY DELETES {full}. Code, issues, pull requests, wiki, releases and stars "
        "are removed. Forks are not deleted. This cannot be undone through the gateway."
    )
    sections = [Section("text", "Effect", effect)]
    facts: list[list[str]] = []
    summary = f"PERMANENTLY DELETE {full}"
    if repo is None:
        if repo_note is not None and repo_note.detail == "HTTP 404":
            warnings.append("Repository not found: GitHub will reject this, or the name is wrong")
        else:
            reason = _text(repo_note.detail, 80) if repo_note is not None else "no lookup"
            warnings.append(f"Repository details unavailable ({reason}); only the name is shown")
    else:
        visibility = repo.get("visibility") or ("private" if repo.get("private") else "public")
        stars = repo.get("stargazers_count")
        pushed = repo.get("pushed_at")
        age = _age_days(pushed, built_at)
        facts.append(["Repository", _text(repo.get("full_name") or full, max_chars)])
        facts.append(["Visibility", _text(visibility, 40)])
        facts.append(["Archived", "yes" if repo.get("archived") else "no"])
        parent = repo.get("parent")
        facts.append(
            [
                "Fork",
                f"yes, of {_text(parent.get('full_name', '?'), 100)}"
                if repo.get("fork") and isinstance(parent, dict)
                else ("yes" if repo.get("fork") else "no"),
            ]
        )
        facts.append(["Default branch", _text(repo.get("default_branch", "?"), 100)])
        for label, key in (("Last push", "pushed_at"), ("Created", "created_at")):
            if repo.get(key):
                raw = str(repo[key])
                shown = times.format(raw) if times is not None else None
                facts.append([label, _text(shown or raw, max_chars)])
        for label, key in (("Stars", "stargazers_count"), ("Forks", "forks_count")):
            if repo.get(key) is not None:
                facts.append([label, _text(repo[key], 20)])
        if repo.get("open_issues_count") is not None:
            facts.append(["Open issues and PRs", _text(repo["open_issues_count"], 20)])
        if prs is not None and isinstance(prs.get("total_count"), int):
            facts.append(["Open pull requests", str(prs["total_count"])])
        if repo.get("size") is not None:
            facts.append(["Size", f"{_text(repo['size'], 20)} KiB"])
        facts.append(["GitHub Pages", "yes" if repo.get("has_pages") else "no"])
        facts.append(["Wiki", "yes" if repo.get("has_wiki") else "no"])

        if visibility == "public" and isinstance(stars, int) and stars >= 10:
            warnings.append(f"Public repository with {stars} stars")
        if age is not None and age <= 30:
            warnings.append("Pushed to within the last 30 days")
        if not repo.get("archived"):
            warnings.append("Not archived")
        if prs is not None and isinstance(prs.get("total_count"), int) and prs["total_count"] > 0:
            warnings.append(f"{prs['total_count']} open pull request(s) will be lost")
        bits = [_text(visibility, 40)]
        if isinstance(stars, int):
            bits.append(f"{stars} stars")
        if age is not None:
            bits.append(f"last push {int(age)} days ago" if age >= 1 else "pushed today")
        summary += f" ({', '.join(bits)})"
    if facts:
        sections.append(Section("kv", "Repository", facts))
    return Preview(
        title=_cap(f"Delete repository {full}"),
        summary=_cap(summary),
        built_at=built_at,
        sections=sections,
        warnings=warnings,
        lookups=notes,
    )
