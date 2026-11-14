"""GitHub API lookups that feed the owner's approval preview (stdlib only).

Runs inside the privileged helper with a read-only token. Errors are fixed
codes only; response bodies and the token never reach exceptions or logs.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol

from agentpass.gitmirror.fetch import FetchSettings, git_env
from agentpass.gitmirror.validate import FetchRequest, HelperError

API_BASE = "https://api.github.com"
_TIMEOUT_S = 4
_MAX_BODY = 1024 * 1024
_HEADLINE_MAX = 200
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_UNKNOWN = {"state": "unknown", "previous": None, "summary": "history check unavailable"}


class GitHubApi(Protocol):
    def get(self, path: str) -> dict: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None  # surfaces the 3xx as HTTPError -> internal; the token never follows


class GitHubHttpApi:
    """Production client. Never follows redirects; token only in a header."""

    def __init__(self, token: str, opener: urllib.request.OpenerDirector | None = None) -> None:
        self._token = token
        self._opener = opener or urllib.request.build_opener(_NoRedirect)

    def __repr__(self) -> str:
        return f"GitHubHttpApi(token=<{len(self._token)} chars>)"

    def get(self, path: str) -> dict:
        req = urllib.request.Request(
            API_BASE + path,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        code = "internal"
        try:
            with self._opener.open(req, timeout=_TIMEOUT_S) as resp:
                body = resp.read(_MAX_BODY + 1)
            if len(body) <= _MAX_BODY:
                doc = json.loads(body)
                if isinstance(doc, dict):
                    return doc
        except urllib.error.HTTPError as e:
            code = {401: "auth_failed", 403: "auth_failed", 404: "not_found"}.get(
                e.code, "internal"
            )
        except Exception:
            pass
        raise HelperError(code) from None


def _repo_path(req: FetchRequest) -> str:
    return f"/repos/{req.owner}/{req.repo}"


def lookup_commit(req: FetchRequest, api: GitHubApi) -> dict:
    base = _repo_path(req)
    doc = api.get(f"{base}/commits/{req.sha}")
    branch = api.get(f"{base}/branches/{req.branch}")
    try:
        commit = doc["commit"]
        headline = str(commit["message"]).split("\n", 1)[0][:_HEADLINE_MAX]
        author = str(commit["author"]["name"])
        date = str(commit["committer"]["date"])
        tip = branch["commit"]["sha"]
    except (KeyError, TypeError):
        raise HelperError("internal") from None
    return {
        "headline": headline,
        "author": author,
        "date": date,
        "is_tip": "yes" if tip == req.sha else "no",
    }


def _mirror_sha(req: FetchRequest, repo: Path, settings: FetchSettings) -> str | None:
    if not repo.is_dir():
        return None
    proc = settings.run(
        [
            "git",
            f"--git-dir={repo}",
            "rev-parse",
            "--verify",
            "--quiet",
            f"refs/heads/{req.branch}",
        ],
        env=git_env(settings),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode == 1:  # --quiet: ref does not exist
        return None
    if proc.returncode != 0:
        raise HelperError("internal")
    sha = proc.stdout.strip()
    if not _SHA.fullmatch(sha):
        raise HelperError("internal")
    return sha


def lookup_relation(req: FetchRequest, repo: Path, api: GitHubApi, settings: FetchSettings) -> dict:
    try:
        previous = _mirror_sha(req, repo, settings)
        if previous is None:
            return {"state": "new", "previous": None, "summary": "first fetch of this branch"}
        if previous == req.sha:
            return {"state": "same", "previous": previous, "summary": "already at this commit"}
        cmp = api.get(f"{_repo_path(req)}/compare/{previous}...{req.sha}")
        status, ahead, behind = cmp["status"], int(cmp["ahead_by"]), int(cmp["behind_by"])
        if status == "ahead":
            return {
                "state": "fast-forward",
                "previous": previous,
                "summary": f"{ahead} new commits",
            }
        if status in ("diverged", "behind"):
            return {
                "state": "rewritten",
                "previous": previous,
                "summary": f"history rewritten: {behind} commits dropped, {ahead} new",
            }
    except Exception:
        pass
    return dict(_UNKNOWN)
