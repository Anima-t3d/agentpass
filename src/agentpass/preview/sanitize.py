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


def clip_escaped(text: str, limit: int, ellipsis: str = "") -> str:
    """Escape like ``escape_unsafe`` and keep the result within ``limit`` characters.

    Escaping lengthens a character (``\\u202e``), so characters are escaped one by one and
    dropped from the end once the limit is reached: no escape sequence is ever cut in half.
    When anything was dropped and ``ellipsis`` is given, it ends the result (inside the limit).
    """
    pieces = [escape_unsafe(c) for c in text]
    if sum(map(len, pieces)) <= limit:
        return "".join(pieces)
    out: list[str] = []
    size = 0
    for piece in pieces:
        if size + len(piece) > limit - len(ellipsis):
            break
        out.append(piece)
        size += len(piece)
    return "".join(out) + ellipsis


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
