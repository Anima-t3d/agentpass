"""PreviewService: build the trusted preview for one approval (docs/APPROVAL-PREVIEWS.md).

Runs once per pending request, before fan-out. The trusted text comes only from the
validated args and from read-only GET lookups the gateway makes itself, through the
tool's own service. A failure of any kind returns ``Unavailable(reason)``: it never
raises, never blocks the request past its timeout and never approves anything.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentpass.config import PreviewSpec, PreviewWarning, ToolDefinition
from agentpass.preview.model import LookupNote, Preview, Section, Unavailable
from agentpass.preview.renderers import render_entity_state
from agentpass.preview.sanitize import escape_unsafe
from agentpass.services.http import HTTPServiceError

if TYPE_CHECKING:
    from agentpass.registry import ToolRegistry
    from agentpass.services.base import ServiceHandler

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 3.0  # whole build, seconds
DEFAULT_MAX_BYTES = 64 * 1024  # serialized preview
SUMMARY_LIMIT = 300
LOOKUP_MAX_BYTES = 256 * 1024
IMPLEMENTED_RENDERERS = frozenset({"template", "entity_state"})

_REF_RE = re.compile(r"\{(\w+)((?:\.[\w-]+)*)\}")
_MISSING = object()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lookup_in(data: Any, path: str) -> Any:
    """Follow ``.a.b.0`` through dicts and lists; anything absent is ``_MISSING``."""
    for part in [p for p in path.split(".") if p]:
        if isinstance(data, dict) and part in data:
            data = data[part]
        elif isinstance(data, list) and part.isdigit() and int(part) < len(data):
            data = data[int(part)]
        else:
            return _MISSING
    return data


def _as_text(value: Any) -> str | object:
    if value is None:
        return _MISSING
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


class _Context:
    """The values a template may reference: validated args and successful lookups."""

    def __init__(self, values: dict[str, Any], max_chars: int) -> None:
        self._values = values
        self._max = max_chars

    def render(self, template: str) -> str | None:
        """Substitute ``{ref}``; ``None`` if any reference has no value.

        Output is plain text: control and bidi characters are escaped, each value is
        capped at ``max_chars``. The template itself is written by the operator.
        """
        failed = False

        def sub(m: re.Match[str]) -> str:
            nonlocal failed
            root = m.group(1)
            raw = _lookup_in(self._values[root], m.group(2)) if root in self._values else _MISSING
            text = _as_text(raw) if raw is not _MISSING else _MISSING
            if text is _MISSING:
                failed = True
                return ""
            assert isinstance(text, str)
            text = escape_unsafe(text)
            return text if len(text) <= self._max else text[: self._max - 1] + "…"

        out = _REF_RE.sub(sub, template)
        return None if failed else out

    def value(self, template: str) -> str | None:
        return self.render(template)


def _warning_fires(w: PreviewWarning, ctx: _Context) -> bool:
    value = ctx.value(w.value)
    if value is None:
        return False
    if w.comparison == "equals":
        return value == w.operand
    if w.comparison == "in":
        return value in w.operand
    if w.comparison == "not_in":
        return value not in w.operand
    return not value.endswith(w.operand)  # endswith_not


def _refs_present(lookup: Any, args: dict[str, Any]) -> bool:
    templates = [lookup.path, *(lookup.query or {}).values()]
    return all(args.get(ref) is not None for t in templates for ref in re.findall(r"\{(\w+)\}", t))


def _failure_reason(exc: BaseException) -> str:
    """A short, content-free reason for a failed lookup."""
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, HTTPServiceError):
        return str(exc)[:80]
    if isinstance(exc, LookupError):
        return "not supported"
    return "error"


class PreviewService:
    """Builds previews. ``services`` are the live handlers, keyed by service name."""

    def __init__(
        self,
        registry: ToolRegistry,
        services: dict[str, ServiceHandler],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self._registry = registry
        self._services = services
        self._timeout = timeout
        self._max_bytes = max_bytes

    def has_preview(self, tool: str) -> bool:
        definition = self._registry.get_tool(tool)
        return definition is not None and definition.preview is not None

    async def build(self, tool: str, args: dict[str, Any]) -> Preview | Unavailable | None:
        """The preview for ``tool(args)``, ``Unavailable`` on failure, ``None`` if undeclared."""
        definition = self._registry.get_tool(tool)
        if definition is None or definition.preview is None:
            return None
        try:
            return await asyncio.wait_for(self._build(definition, args), self._timeout)
        except TimeoutError:
            logger.warning("Preview for %s timed out", tool)
            return Unavailable("timeout", _now())
        except Exception:
            logger.exception("Preview for %s failed", tool)  # no args or content in the message
            return Unavailable("error", _now())

    async def _build(
        self, definition: ToolDefinition, args: dict[str, Any]
    ) -> Preview | Unavailable:
        spec = definition.preview
        assert spec is not None
        if spec.renderer not in IMPLEMENTED_RENDERERS:
            return Unavailable("renderer not available", _now())
        values: dict[str, Any] = dict(self._registry.apply_defaults(definition.name, args))
        notes, failure = await self._run_lookups(definition, spec, values)
        if failure is not None:
            return Unavailable(failure, _now())
        if spec.renderer == "entity_state":
            preview = render_entity_state(
                definition, values, notes, max_chars=spec.max_chars, built_at=_now()
            )
            if spec.confirm_text:
                preview.confirm_text = _Context(values, spec.max_chars).render(spec.confirm_text)
            return self._fit(preview).seal()
        return self._render(definition, spec, values, notes)

    async def _run_lookups(
        self, definition: ToolDefinition, spec: PreviewSpec, values: dict[str, Any]
    ) -> tuple[list[LookupNote], str | None]:
        """Run the lookups concurrently; fills ``values`` with the successful ones."""
        if not spec.lookups:
            return [], None
        service = self._services.get(definition.service_name)
        if service is None:
            return [], "service not configured"
        args = dict(values)
        # A lookup that needs an optional arg the agent left out is skipped, not failed
        runnable = [lk for lk in spec.lookups if _refs_present(lk, args)]
        if not runnable:
            return [], None

        async def one(lk: Any) -> Any:
            return await asyncio.wait_for(
                service.lookup(
                    lk.path,
                    args,
                    query=lk.query,
                    timeout=lk.timeout,
                    max_bytes=LOOKUP_MAX_BYTES,
                ),
                lk.timeout + 0.5,
            )

        results = await asyncio.gather(*(one(lk) for lk in runnable), return_exceptions=True)
        notes: list[LookupNote] = []
        failure: str | None = None
        for lk, result in zip(runnable, results, strict=True):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, BaseException):
                reason = _failure_reason(result)
                logger.info("Preview lookup %s of %s failed: %s", lk.id, definition.name, reason)
                notes.append(LookupNote(lk.id, "failed", reason, _now()))
                if lk.on_error == "unavailable" and failure is None:
                    failure = f"lookup {lk.id} failed ({reason})"
            else:
                values[lk.id] = result
                notes.append(LookupNote(lk.id, "ok", "", _now()))
        return notes, failure

    def _render(
        self,
        definition: ToolDefinition,
        spec: PreviewSpec,
        values: dict[str, Any],
        notes: list[LookupNote],
    ) -> Preview | Unavailable:
        ctx = _Context(values, spec.max_chars)
        rows = []
        for f in spec.fields:
            label, value = ctx.render(f.label), ctx.render(f.value)
            if label is not None and value is not None:
                rows.append([label, value])
        if spec.fields and not rows:
            return Unavailable("no fields could be rendered", _now())
        title = (ctx.render(spec.title) if spec.title else None) or definition.name
        summary = (ctx.render(spec.summary) if spec.summary else None) or title
        if len(summary) > SUMMARY_LIMIT:
            summary = summary[: SUMMARY_LIMIT - 1] + "…"
        preview = Preview(
            title=title,
            summary=summary,
            built_at=_now(),
            sections=[Section("kv", "Details", rows)] if rows else [],
            warnings=[
                ctx.render(w.text) or w.text for w in spec.warnings if _warning_fires(w, ctx)
            ],
            lookups=notes,
            confirm_text=ctx.render(spec.confirm_text) if spec.confirm_text else None,
        )
        return self._fit(preview).seal()

    def _fit(self, preview: Preview) -> Preview:
        """Keep the serialized preview under the size cap; truncation is always labelled."""

        def size() -> int:
            return len(json.dumps(preview.to_dict(), ensure_ascii=False).encode())

        while size() > self._max_bytes and preview.sections:
            preview.sections.pop()
            preview.truncated = True
        if preview.truncated:
            preview.warnings.append("preview is partial")
        return preview
