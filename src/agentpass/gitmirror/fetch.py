"""Fetch one branch into a bare mirror at an owner-approved sha (runs as agentgit).

The GitHub token only ever travels in the git child's environment as a
GIT_CONFIG_VALUE_n http.extraHeader; never in argv, a URL, a config file, a
result or a log line. git's stderr is inspected and journaled (scrubbed), never
returned.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from agentpass.gitmirror.validate import FetchRequest, HelperError, check_path_safe

INCOMING = "refs/agentgit/incoming"


def github_url(req: FetchRequest) -> str:
    return f"https://github.com/{req.owner}/{req.repo}.git"


@dataclass(frozen=True, kw_only=True)
class FetchSettings:
    token: str
    home: Path
    timeout_s: float = 600
    max_bytes: int = 2147483648
    remote_url: Callable[[FetchRequest], str] = github_url
    allowed_protocols: tuple[str, ...] = ("https",)
    trusted_uids: frozenset[int]
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run

    def __repr__(self) -> str:  # never let the token reach a traceback or log via repr
        return f"FetchSettings(home={self.home!r}, token=<{len(self.token)} chars>)"


def _basic(token: str) -> str:
    return base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")


def git_env(settings: FetchSettings) -> dict[str, str]:
    """The complete environment for every git child; nothing is inherited."""
    config = [("protocol.allow", "never")]
    config += [(f"protocol.{p}.allow", "always") for p in settings.allowed_protocols]
    config += [
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("fetch.recurseSubmodules", "false"),
        ("transfer.fsckObjects", "true"),
        ("fetch.fsckObjects", "true"),
    ]
    if settings.token:
        config.append(("http.extraHeader", f"Authorization: Basic {_basic(settings.token)}"))
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(settings.home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GCM_INTERACTIVE": "never",
        "LC_ALL": "C",
        "GIT_CONFIG_COUNT": str(len(config)),
    }
    for i, (key, value) in enumerate(config):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


_HTTP_AUTH = re.compile(r"returned error: 40[13]\b")


def _classify(stderr: str) -> str:
    if "couldn't find remote ref" in stderr:
        return "not_found"
    if (
        "Authentication failed" in stderr
        or "could not read Username" in stderr
        or _HTTP_AUTH.search(stderr)
    ):
        return "auth_failed"
    if "Repository not found" in stderr:
        return "not_found"
    return "internal"


def _scrub(text: str, settings: FetchSettings) -> str:
    if settings.token:
        text = text.replace(_basic(settings.token), "***").replace(settings.token, "***")
    return text


def _journal(what: str, proc: subprocess.CompletedProcess, settings: FetchSettings) -> None:
    stderr = _scrub(proc.stderr or "", settings).strip()
    print(f"agentgit: git {what} failed (exit {proc.returncode}): {stderr}", file=sys.stderr)


def _git(
    settings: FetchSettings, *args: str, timeout: float | None = None
) -> subprocess.CompletedProcess:
    try:
        return settings.run(
            ["git", *args],
            env=git_env(settings),
            cwd=settings.home,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=settings.timeout_s if timeout is None else timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HelperError("timeout") from None


def _git_ok(settings: FetchSettings, what: str, *args: str) -> subprocess.CompletedProcess:
    proc = _git(settings, *args)
    if proc.returncode != 0:
        _journal(what, proc, settings)
        raise HelperError("internal")
    return proc


def _size(repo: Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(repo):  # does not descend into symlinked dirs
        for name in files:
            st = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def _lock(repo: Path) -> int:
    path = repo.parent / f".{repo.name}.lock"
    flags = os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o640)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise HelperError("unsafe_path") from None
        raise
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise HelperError("busy") from None
    except BaseException:
        os.close(fd)
        raise
    return fd


def fetch(req: FetchRequest, repo: Path, settings: FetchSettings) -> dict:
    started = time.monotonic()
    fd = _lock(repo)
    try:
        return _fetch_locked(req, repo, settings, started)
    finally:
        os.close(fd)  # closing the only descriptor releases the flock


def _fetch_locked(req: FetchRequest, repo: Path, settings: FetchSettings, started: float) -> dict:
    trusted = settings.trusted_uids
    check_path_safe(repo.parent, trusted)
    check_path_safe(settings.home, trusted)
    if os.path.lexists(repo):
        check_path_safe(repo, trusted)
        check_path_safe(repo / "config", trusted)
    else:
        _git_ok(settings, "init", "init", "--bare", "--quiet", "--", str(repo))

    before = _size(repo)
    branch_ref = f"refs/heads/{req.branch}"
    proc = _git(
        settings,
        "-C",
        str(repo),
        "fetch",
        "--no-tags",
        "--no-write-fetch-head",
        "--quiet",
        "--",
        settings.remote_url(req),
        f"+{branch_ref}:{INCOMING}",
    )
    if proc.returncode != 0:
        _journal("fetch", proc, settings)
        raise HelperError(_classify(proc.stderr or ""))

    got = _git_ok(settings, "rev-parse", "-C", str(repo), "rev-parse", "--verify", INCOMING)
    if got.stdout.strip() != req.sha:
        _git_ok(settings, "update-ref", "-C", str(repo), "update-ref", "-d", INCOMING)
        raise HelperError("branch_moved")

    after = _size(repo)
    if after > settings.max_bytes:
        _git_ok(settings, "update-ref", "-C", str(repo), "update-ref", "-d", INCOMING)
        _git_ok(settings, "gc", "-C", str(repo), "gc", "--prune=now", "--quiet")
        raise HelperError("too_large")

    _git_ok(settings, "update-ref", "-C", str(repo), "update-ref", branch_ref, req.sha)
    _git_ok(settings, "update-ref", "-C", str(repo), "update-ref", "-d", INCOMING)
    return {
        "mirror_path": str(repo),
        "ref": branch_ref,
        "sha": req.sha,
        "fetched_bytes": max(0, after - before),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
