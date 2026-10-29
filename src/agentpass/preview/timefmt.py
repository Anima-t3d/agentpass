"""Show lookup timestamps in the operator's zone with a relative age (design section 6a)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

# ISO-8601 with an explicit offset: a naive time has no instant to convert
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})")


def age(delta_seconds: float) -> str:
    """``4 h ago``, ``in 3 min``, ``just now``."""
    s = abs(int(delta_seconds))
    if s < 45:
        return "just now"
    if s < 3600:
        text = f"{max(1, round(s / 60))} min"
    elif s < 86400:
        text = f"{round(s / 3600)} h"
    else:
        days = round(s / 86400)
        text = f"{days} day{'s' if days != 1 else ''}"
    return f"{text} ago" if delta_seconds >= 0 else f"in {text}"


class TimeFormatter:
    """Rewrites ISO timestamps to ``Thu 29 Oct 16:12 Europe/Berlin (4 h ago)``.

    The zone name is always printed. ``seen`` collects ``(shown, raw)`` pairs so the raw
    value can stay visible in the lookup details.
    """

    def __init__(self, zone: str = "UTC", now: datetime | None = None) -> None:
        self.zone_name = zone
        self._zone = ZoneInfo(zone)
        self._now = now
        self.seen: list[tuple[str, str]] = []

    def format(self, raw: str) -> str | None:
        """The display form of ``raw``, or ``None`` if it is not a timestamp with an offset."""
        if not _ISO.fullmatch(raw):
            return None
        try:
            moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        if moment.tzinfo is None:
            return None
        now = self._now or datetime.now(UTC)
        local = moment.astimezone(self._zone)
        fmt = (
            "%a %d %b %H:%M"
            if local.year == now.astimezone(self._zone).year
            else "%a %d %b %Y %H:%M"
        )
        shown = f"{local.strftime(fmt)} {self.zone_name} ({age((now - moment).total_seconds())})"
        self.seen.append((shown, raw))
        return shown
