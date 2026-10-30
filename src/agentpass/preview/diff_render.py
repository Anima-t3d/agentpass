"""The ``diff`` renderer: ``gh_put_contents`` (docs/APPROVAL-PREVIEWS.md section 4.3).

New content is the ``content`` arg (signed); the current file comes from a trusted lookup of
``GET /repos/{owner}/{repo}/contents/{path}?ref={branch}``. The signed ``sha`` is compared to
the looked-up blob sha: GitHub itself rejects a stale base, so a stale diff fails safe.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
from typing import Any

from agentpass.preview.model import LookupNote, Preview, Section, Unavailable
from agentpass.preview.renderers import _cap, _lookup_note, _text
from agentpass.preview.sanitize import escape_unsafe

DEFAULT_MAX_BYTES = 256 * 1024  # larger files: sizes and shas only
DEFAULT_MAX_LINES = 400
DEFAULT_MAX_DIFF_CHARS = 40_000
MESSAGE_LIMIT = 5000
_DEFAULT_BRANCHES = ("main", "master")


def _decode(data: str) -> bytes | None:
    try:
        return base64.b64decode("".join(data.split()), validate=True)
    except (binascii.Error, ValueError):
        return None


def _is_text(data: bytes) -> str | None:
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _path_warnings(path: str) -> list[str]:
    out: list[str] = []
    segments = path.split("/")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path) or escape_unsafe(path) != path:
        out.append("The path contains control or direction characters (shown escaped)")
    if ".." in segments:
        out.append("The path contains a '..' segment")
    if path.startswith(".github/workflows/"):
        out.append("Changes CI: this file is under .github/workflows/")
    if path == ".gitmodules" or path.endswith("/.gitmodules"):
        out.append("Changes .gitmodules (submodule sources)")
    elif any(s.startswith(".") and s not in ("", ".", "..") for s in segments):
        out.append("The path is in a hidden (dot) file or directory")
    return out


def _diff_lines(old: str, new: str, path: str, max_lines: int, max_chars: int):
    """``(shown diff text, added, removed, truncated)``."""
    a, b = old.split("\n"), new.split("\n")
    out: list[str] = []
    added = removed = 0
    for line in difflib.unified_diff(a, b, f"a/{path}", f"b/{path}", n=3, lineterm=""):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
        out.append(line)
    shown: list[str] = []
    chars = 0
    for line in out:
        chars += len(line) + 1
        if len(shown) >= max_lines or chars > max_chars:
            break
        shown.append(line)
    hidden = len(out) - len(shown)
    text = escape_unsafe("\n".join(shown))
    truncated = hidden > 0
    if truncated:
        text += f"\n… {hidden:,} more diff line{'s' if hidden != 1 else ''} not shown"
    return text, added, removed, truncated


def render_diff(
    values: dict[str, Any],
    notes: list[LookupNote],
    *,
    params: dict[str, Any],
    max_chars: int,
    built_at: str,
) -> Preview | Unavailable:
    new_bytes = _decode(str(values.get("content", "")))
    if new_bytes is None:
        return Unavailable("content is not valid base64", built_at)
    owner, repo = str(values.get("owner", "")), str(values.get("repo", ""))
    branch, path = str(values.get("branch", "")), str(values.get("path", ""))
    message = str(values.get("message", ""))
    agent_sha = values.get("sha")
    max_bytes = int(params.get("max_bytes", DEFAULT_MAX_BYTES))
    max_lines = int(params.get("max_lines", DEFAULT_MAX_LINES))
    max_diff_chars = int(params.get("max_diff_chars", DEFAULT_MAX_DIFF_CHARS))

    warnings = _path_warnings(path)
    truncated = False
    shown_path = _text(path, max_chars)
    where = f"{_text(owner, 100)}/{_text(repo, 100)}"

    # Default branch: the repo lookup if we have it, else the usual names
    repo_info = values.get("repo_info") if isinstance(values.get("repo_info"), dict) else None
    default_branch = repo_info.get("default_branch") if repo_info else None
    if (default_branch and branch == default_branch) or (
        not default_branch and branch in _DEFAULT_BRANCHES
    ):
        warnings.append("Writes directly to the default branch")

    # The current file
    contents_note = _lookup_note(notes, "contents")
    current = values.get("contents")
    mode = "unknown"
    old_bytes: bytes | None = None
    old_sha = ""
    old_size: int | None = None
    withheld = False
    if contents_note is not None and contents_note.status == "failed":
        if contents_note.detail == "HTTP 404":
            mode = "new"
        elif contents_note.detail == "response too large":
            mode, withheld = "modify", True
        else:
            warnings.append(
                f"Current file could not be read ({_text(contents_note.detail, 80)}): "
                "diff not shown"
            )
    elif isinstance(current, list):
        warnings.append("The path is a directory: GitHub will reject this write")
    elif isinstance(current, dict):
        if current.get("type") not in (None, "file"):
            warnings.append(f"The path is a {_text(current.get('type'), 40)}, not a file")
        else:
            mode = "modify"
            old_sha = str(current.get("sha", ""))
            size = current.get("size")
            old_size = size if isinstance(size, int) else None
            encoded = current.get("content")
            if (
                current.get("encoding") == "base64"
                and isinstance(encoded, str)
                and encoded
                and (old_size is None or old_size <= max_bytes)
            ):
                old_bytes = _decode(encoded)
            else:
                withheld = True

    # Base sha binding
    base: str
    if mode == "modify" and old_sha:
        if agent_sha is None:
            base = "No base sha was sent for an existing file"
            warnings.append("No base sha for an existing file: GitHub will reject this (422)")
        elif agent_sha == old_sha:
            base = "Diff is against the version the agent based its change on"
        else:
            base = "File changed since the agent read it"
            warnings.append(
                "File changed since the agent read it. Executing would be rejected by GitHub (409)"
            )
    elif mode == "new":
        base = "New file"
        if agent_sha is not None:
            warnings.append(
                "A base sha was sent but the file does not exist: GitHub will reject it"
            )
    else:
        base = "Unknown"

    sections: list[Section] = []
    added = removed = 0
    new_text = _is_text(new_bytes)
    old_text = _is_text(old_bytes) if old_bytes is not None else ""
    identical = old_bytes is not None and old_bytes == new_bytes
    if identical:
        mode = "identical"

    sizes = [["New size", f"{len(new_bytes):,} bytes"]]
    if old_size is not None:
        sizes.insert(0, ["Current size", f"{old_size:,} bytes"])
    diff_shown = False
    if mode == "new" and new_text is not None:
        text, added, removed, cut = _diff_lines("", new_text, path, max_lines, max_diff_chars)
        sections.append(Section("diff", "New file content", text))
        truncated |= cut
        diff_shown = True
    elif mode in ("modify", "identical") and old_bytes is not None:
        if identical:
            pass
        elif new_text is None or old_text is None:
            warnings.append("Binary content: no diff shown")
        else:
            text, added, removed, cut = _diff_lines(
                old_text, new_text, path, max_lines, max_diff_chars
            )
            sections.append(Section("diff", "Changes", text))
            truncated |= cut
            diff_shown = True
    elif mode == "modify" and withheld:
        warnings.append("Diff not shown (current file too large)")
    elif mode == "new" and new_text is None:
        warnings.append("Binary content: no diff shown")
    if mode == "identical":
        warnings.append("The new content is identical to the current file: no change")
    if not diff_shown and not identical:
        if old_bytes is not None:
            sizes.append(["Current sha256", hashlib.sha256(old_bytes).hexdigest()])
        sizes.append(["New sha256", hashlib.sha256(new_bytes).hexdigest()])
    if old_sha:
        sizes.append(["Current blob sha", _text(old_sha, 64)])

    label = {
        "new": "Create",
        "modify": "Change",
        "identical": "Rewrite unchanged",
        "unknown": "Write",
    }[mode]
    counts = f"+{added} / -{removed}" if diff_shown else "not computed"
    change = [
        ["Repository", where],
        ["Branch", _text(branch, max_chars)],
        ["Path", shown_path],
        ["Mode", {"new": "new file", "modify": "modifies existing file",
                  "identical": "no change", "unknown": "unknown (lookup failed)"}[mode]],
        ["Lines", counts],
        ["Base", base],
        *sizes,
    ]  # fmt: skip
    head = [
        Section("kv", "Change", change),
        Section("text", "Commit message", _text(message, MESSAGE_LIMIT)),
    ]
    title = f"{label} {shown_path} on {where}@{_text(branch, 60)}"
    summary = f"{label.lower()} {shown_path} on {where}@{_text(branch, 60)}"
    if diff_shown:
        summary += f": +{added} -{removed}"
    return Preview(
        title=_cap(title),
        summary=_cap(summary),
        built_at=built_at,
        sections=head + sections,
        warnings=list(dict.fromkeys(warnings)),
        lookups=notes,
        truncated=truncated,
    )
