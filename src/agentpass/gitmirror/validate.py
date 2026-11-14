"""Input validation, allowlist and path safety for the git mirror helper (stdlib only)."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?")
_REPO = re.compile(r"(?!\.{1,2}$)[A-Za-z0-9._-]+")
_BRANCH = re.compile(r"[A-Za-z0-9._/-]+")
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_FIELDS = ("owner", "repo", "branch", "sha")
_IGNORED_KEYS = frozenset({"op", "kind"})


class HelperError(Exception):
    """A fixed-code helper failure; str(err) is exactly the code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FetchRequest:
    owner: str
    repo: str
    branch: str
    sha: str


def _branch_ok(b: str) -> bool:
    return (
        len(b) <= 255
        and _BRANCH.fullmatch(b) is not None
        and not b.startswith(("-", "/"))
        and not b.endswith(("/", ".lock"))
        and ".." not in b
        and "//" not in b
        and "@{" not in b
        and not any(part.startswith(".") for part in b.split("/"))
    )


def parse_request(raw: dict) -> FetchRequest:
    if not isinstance(raw, dict):
        raise HelperError("invalid_request")
    if set(raw) - _IGNORED_KEYS - set(_FIELDS):
        raise HelperError("invalid_request")
    vals: dict[str, str] = {}
    for key in _FIELDS:
        v = raw.get(key)
        if not isinstance(v, str):
            raise HelperError("invalid_request")
        vals[key] = v
    if not (
        len(vals["owner"]) <= 39
        and _OWNER.fullmatch(vals["owner"])
        and len(vals["repo"]) <= 100
        and _REPO.fullmatch(vals["repo"])
        and _branch_ok(vals["branch"])
        and _SHA.fullmatch(vals["sha"])
    ):
        raise HelperError("invalid_request")
    return FetchRequest(**vals)


def load_allowlist(path: Path) -> frozenset[str]:
    entries = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line)
    return frozenset(entries)


def check_allowed(req: FetchRequest, allowlist: frozenset[str]) -> None:
    if f"{req.owner}/{req.repo}" not in allowlist:
        raise HelperError("not_allowed")


def repo_path(root: Path, req: FetchRequest) -> Path:
    """root/owner/repo.git; never creates anything."""
    if not (root / req.owner).is_dir():
        raise HelperError("not_configured")
    return root / req.owner / f"{req.repo}.git"


def check_path_safe(path: Path, trusted_uids: frozenset[int]) -> None:
    """Every existing component from / down must be a non-symlink owned by a trusted uid
    and not group/other-writable (a root-owned sticky dir may be other-writable)."""
    if not path.is_absolute():
        raise HelperError("unsafe_path")
    current = Path(path.anchor)
    parts = [current]
    for name in path.parts[1:]:
        current = current / name
        parts.append(current)
    for comp in parts:
        try:
            st = os.lstat(comp)
        except FileNotFoundError:
            break
        except OSError:
            raise HelperError("unsafe_path") from None
        if stat.S_ISLNK(st.st_mode) or st.st_uid not in trusted_uids:
            raise HelperError("unsafe_path")
        writable = st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        if writable and not (st.st_uid == 0 and st.st_mode & stat.S_ISVTX):
            raise HelperError("unsafe_path")
