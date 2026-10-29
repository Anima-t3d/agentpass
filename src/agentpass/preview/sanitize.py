"""Escape and strip helpers for agent-derived text (docs/APPROVAL-PREVIEWS.md sections 5, 9)."""

from __future__ import annotations

from typing import Any

NOTE_LIMIT = 500

# Bidi controls and invisible characters that can reorder or hide text
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
_INVISIBLE = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x2028, 0x2029}


def _unsafe(ch: str, keep_whitespace: bool) -> bool:
    cp = ord(ch)
    if keep_whitespace and ch in "\n\t":
        return False
    return cp < 0x20 or 0x7F <= cp < 0xA0 or cp in _BIDI or cp in _INVISIBLE


def escape_unsafe(text: str) -> str:
    """Show control and bidi characters as ``\\uXXXX`` instead of acting on them.

    Newline and tab stay. Used for agent-derived values inside a trusted preview.
    """
    return "".join(f"\\u{ord(c):04x}" if _unsafe(c, True) else c for c in text)


def strip_unsafe(text: str) -> str:
    """Remove every control and bidi character, newlines included."""
    return "".join(c for c in text if not _unsafe(c, False))


def sanitize_note(value: Any) -> str | None:
    """Clean the agent's note: plain text, one line, at most ``NOTE_LIMIT`` characters.

    Raises ``ValueError`` for a non-string. Empty or whitespace-only becomes ``None``.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("agent_note must be a string")
    text = strip_unsafe(" ".join(value.split()))  # str.split also splits on U+2028/2029
    if not text:
        return None
    if len(text) > NOTE_LIMIT:
        text = text[: NOTE_LIMIT - 1].rstrip() + "…"
    return text
