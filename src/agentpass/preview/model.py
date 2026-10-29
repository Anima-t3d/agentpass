"""Approval preview data model (docs/APPROVAL-PREVIEWS.md section 1).

Everything here is plain data: strings and structured kinds, never HTML. The page
that draws a preview owns the one escaping point.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

PREVIEW_VERSION = 1
SECTION_KINDS = ("kv", "text", "diff", "list", "table")

SectionKind = Literal["kv", "text", "diff", "list", "table"]


@dataclass
class Section:
    """One block of a preview. ``data`` depends on ``kind`` and holds plain strings.

    ``kv``: list of ``[label, value]``; ``text`` and ``diff``: a string; ``list``: list of
    strings; ``table``: list of rows (lists of strings).
    """

    kind: SectionKind
    label: str
    data: Any


@dataclass
class LookupNote:
    """What a lookup fetched: ``status`` is ``ok`` or ``failed``."""

    id: str
    status: str
    detail: str = ""  # failure reason or "HTTP 404"; never response content
    at: str = ""  # ISO-8601 UTC
    raw_times: list[str] = field(default_factory=list)  # "path: raw value" of rewritten times


@dataclass
class Preview:
    """What the gateway built for the approver: trusted, gateway-made text."""

    title: str
    summary: str
    built_at: str
    sections: list[Section] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lookups: list[LookupNote] = field(default_factory=list)
    confirm_text: str | None = None
    truncated: bool = False
    version: int = PREVIEW_VERSION
    digest: str = ""

    @property
    def status(self) -> str:
        return "partial" if self.truncated else "ok"

    def compute_digest(self) -> str:
        """SHA-256 over the canonical JSON of every field except the digest."""
        body = asdict(self)
        body.pop("digest")
        raw = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def seal(self) -> Preview:
        self.digest = self.compute_digest()
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Preview:
        return cls(
            title=raw["title"],
            summary=raw["summary"],
            built_at=raw["built_at"],
            sections=[Section(s["kind"], s["label"], s["data"]) for s in raw.get("sections", [])],
            warnings=list(raw.get("warnings", [])),
            lookups=[LookupNote(**n) for n in raw.get("lookups", [])],
            confirm_text=raw.get("confirm_text"),
            truncated=bool(raw.get("truncated", False)),
            version=int(raw.get("version", PREVIEW_VERSION)),
            digest=raw.get("digest", ""),
        )


@dataclass
class Unavailable:
    """The preview could not be built. The approver still sees the raw args."""

    reason: str
    built_at: str = ""

    @property
    def status(self) -> str:
        return f"unavailable:{self.reason}"

    @property
    def title(self) -> str:
        return ""

    @property
    def digest(self) -> str:
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {"unavailable": self.reason, "built_at": self.built_at}


def preview_from_json(raw: str | None) -> Preview | Unavailable | None:
    """Read a stored ``pending_requests.preview_json``; anything unreadable is ``None``."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if "unavailable" in data:
            return Unavailable(str(data["unavailable"]), data.get("built_at", ""))
        return Preview.from_dict(data)
    except (ValueError, KeyError, TypeError):
        return None
