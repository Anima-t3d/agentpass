from __future__ import annotations

import os
import subprocess
import urllib.error
from pathlib import Path

import pytest

from agentpass.gitmirror import lookup
from agentpass.gitmirror.fetch import FetchSettings
from agentpass.gitmirror.lookup import GitHubHttpApi, lookup_commit, lookup_relation
from agentpass.gitmirror.validate import FetchRequest, HelperError

SHA = "a" * 40
PREV = "b" * 40
REQ = FetchRequest("octo", "hello", "main", SHA)
UNKNOWN = {"state": "unknown", "previous": None, "summary": "history check unavailable"}


class FakeApi:
    def __init__(self, data: dict[str, object]) -> None:
        self.data = data
        self.calls: list[str] = []

    def get(self, path: str) -> dict:
        self.calls.append(path)
        v = self.data[path]
        if isinstance(v, Exception):
            raise v
        return v  # type: ignore[return-value]


def commit_doc(message: str = "fix: thing\n\nbody", name: str = "Ada") -> dict:
    return {
        "commit": {
            "message": message,
            "author": {"name": name},
            "committer": {"date": "2026-01-02T03:04:05Z"},
        }
    }


def api_for_commit(tip: str, **kw: str) -> FakeApi:
    return FakeApi(
        {
            f"/repos/octo/hello/commits/{SHA}": commit_doc(**kw),
            "/repos/octo/hello/branches/main": {"commit": {"sha": tip}},
        }
    )


def test_commit_fields_and_tip_yes() -> None:
    out = lookup_commit(REQ, api_for_commit(SHA))
    assert out == {
        "headline": "fix: thing",
        "author": "Ada",
        "date": "2026-01-02T03:04:05Z",
        "is_tip": "yes",
    }


def test_commit_not_tip() -> None:
    assert lookup_commit(REQ, api_for_commit(PREV))["is_tip"] == "no"


def test_headline_truncated() -> None:
    out = lookup_commit(REQ, api_for_commit(SHA, message="x" * 500))
    assert out["headline"] == "x" * 200


def test_commit_auth_failed_propagates() -> None:
    api = FakeApi({f"/repos/octo/hello/commits/{SHA}": HelperError("auth_failed")})
    with pytest.raises(HelperError) as ei:
        lookup_commit(REQ, api)
    assert ei.value.code == "auth_failed"


def test_commit_malformed_is_internal() -> None:
    api = FakeApi(
        {
            f"/repos/octo/hello/commits/{SHA}": {"commit": {}},
            "/repos/octo/hello/branches/main": {"commit": {"sha": SHA}},
        }
    )
    with pytest.raises(HelperError) as ei:
        lookup_commit(REQ, api)
    assert ei.value.code == "internal"


# ---- relation -------------------------------------------------------------

_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def settings(tmp_path: Path, **kw: object) -> FetchSettings:
    return FetchSettings(
        token="tok",
        home=tmp_path,
        trusted_uids=frozenset({0, os.getuid()}),
        **kw,  # type: ignore[arg-type]
    )


def mirror_with(tmp_path: Path, branch: str = "main") -> tuple[Path, str]:
    repo = tmp_path / "m.git"
    subprocess.run(["git", "init", "-q", "--bare", str(repo)], check=True, env=_ENV)
    tree = subprocess.run(
        ["git", "--git-dir", str(repo), "hash-object", "-t", "tree", "-w", "--stdin"],
        input="",
        check=True,
        env=_ENV,
        capture_output=True,
        text=True,
    ).stdout.strip()
    sha = subprocess.run(
        ["git", "--git-dir", str(repo), "commit-tree", tree, "-m", "c"],
        check=True,
        env=_ENV,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "--git-dir", str(repo), "update-ref", f"refs/heads/{branch}", sha],
        check=True,
        env=_ENV,
    )
    return repo, sha


def test_new_when_repo_missing(tmp_path: Path) -> None:
    out = lookup_relation(REQ, tmp_path / "nope.git", FakeApi({}), settings(tmp_path))
    assert out == {"state": "new", "previous": None, "summary": "first fetch of this branch"}


def test_new_when_branch_missing(tmp_path: Path) -> None:
    repo, _ = mirror_with(tmp_path, branch="other")
    out = lookup_relation(REQ, repo, FakeApi({}), settings(tmp_path))
    assert out["state"] == "new"


def test_same(tmp_path: Path) -> None:
    repo, sha = mirror_with(tmp_path)
    req = FetchRequest("octo", "hello", "main", sha)
    out = lookup_relation(req, repo, FakeApi({}), settings(tmp_path))
    assert out == {"state": "same", "previous": sha, "summary": "already at this commit"}


def relation(tmp_path: Path, compare: object) -> tuple[dict, str, FakeApi]:
    repo, prev = mirror_with(tmp_path)
    api = FakeApi({f"/repos/octo/hello/compare/{prev}...{SHA}": compare})
    return lookup_relation(REQ, repo, api, settings(tmp_path)), prev, api


def test_fast_forward(tmp_path: Path) -> None:
    out, prev, _ = relation(tmp_path, {"status": "ahead", "ahead_by": 4, "behind_by": 0})
    assert out == {"state": "fast-forward", "previous": prev, "summary": "4 new commits"}


@pytest.mark.parametrize("status", ["diverged", "behind"])
def test_rewritten(tmp_path: Path, status: str) -> None:
    out, prev, _ = relation(tmp_path, {"status": status, "ahead_by": 5, "behind_by": 3})
    assert out == {
        "state": "rewritten",
        "previous": prev,
        "summary": "history rewritten: 3 commits dropped, 5 new",
    }


def test_compare_raises_is_unknown_with_previous(tmp_path: Path) -> None:
    out, prev, _ = relation(tmp_path, HelperError("internal"))
    assert out == UNKNOWN | {"previous": prev}  # the mirror ref was read: show it


def test_compare_odd_status_is_unknown_with_previous(tmp_path: Path) -> None:
    out, prev, _ = relation(tmp_path, {"status": "identical", "ahead_by": 0, "behind_by": 0})
    assert out == UNKNOWN | {"previous": prev}


def test_compare_malformed_is_unknown_with_previous(tmp_path: Path) -> None:
    out, prev, _ = relation(tmp_path, {"status": "ahead"})
    assert out == UNKNOWN | {"previous": prev}


def test_rev_parse_failure_is_unknown(tmp_path: Path) -> None:
    repo, _ = mirror_with(tmp_path)

    def boom(*a: object, **k: object) -> None:
        raise OSError("no git")

    out = lookup_relation(REQ, repo, FakeApi({}), settings(tmp_path, run=boom))
    assert out == UNKNOWN


def test_keyboard_interrupt_not_swallowed(tmp_path: Path) -> None:
    repo, _ = mirror_with(tmp_path)

    def stop(*a: object, **k: object) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        lookup_relation(REQ, repo, FakeApi({}), settings(tmp_path, run=stop))


def test_rev_parse_uses_git_env_and_branch(tmp_path: Path) -> None:
    repo, _ = mirror_with(tmp_path)
    seen: dict[str, object] = {}

    def spy(cmd: list[str], **kw: object) -> subprocess.CompletedProcess:
        seen["cmd"], seen["env"] = cmd, kw.get("env")
        return subprocess.CompletedProcess(cmd, 1, "", "")

    out = lookup_relation(REQ, repo, FakeApi({}), settings(tmp_path, run=spy))
    assert out["state"] == "new"
    assert seen["cmd"] == [
        "git",
        f"--git-dir={repo}",
        "rev-parse",
        "--verify",
        "--quiet",
        "refs/heads/main",
    ]
    assert isinstance(seen["env"], dict) and seen["env"]["GIT_CONFIG_NOSYSTEM"] == "1"


# ---- production client (no network: urlopen is faked) ----------------------


class Resp:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body, self.status = body, status

    def read(self, n: int = -1) -> bytes:
        return self.body if n < 0 else self.body[:n]

    def __enter__(self) -> Resp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


class FakeOpener:
    def __init__(self, result: object) -> None:
        self.result, self.requests, self.timeouts = result, [], []

    def open(self, req: object, timeout: float | None = None) -> Resp:
        self.requests.append(req)
        self.timeouts.append(timeout)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


def client(result: object) -> tuple[GitHubHttpApi, FakeOpener]:
    op = FakeOpener(result)
    return GitHubHttpApi("tok_SECRET", opener=op), op  # type: ignore[arg-type]


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/x", code, "msg tok_SECRET", {}, None)  # type: ignore[arg-type]


def test_client_request_shape() -> None:
    api, op = client(Resp(b'{"a": 1}'))
    assert api.get("/repos/o/r/commits/abc") == {"a": 1}
    req = op.requests[0]
    assert req.full_url == "https://api.github.com/repos/o/r/commits/abc"
    h = {k.lower(): v for k, v in req.header_items()}
    assert h["authorization"] == "Bearer tok_SECRET"
    assert h["accept"] == "application/vnd.github+json"
    assert h["x-github-api-version"] == "2022-11-28"
    assert "tok_SECRET" not in req.full_url
    assert op.timeouts == [4]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (401, "auth_failed"),
        (403, "auth_failed"),
        (404, "not_found"),
        (500, "internal"),
        (302, "internal"),
    ],
)
def test_client_http_errors(code: int, expected: str) -> None:
    api, _ = client(http_error(code))
    with pytest.raises(HelperError) as ei:
        api.get("/x")
    assert ei.value.code == expected
    assert "tok_SECRET" not in repr(ei.value) and ei.value.__cause__ is None


@pytest.mark.parametrize(
    "result",
    [
        OSError("tok_SECRET"),
        TimeoutError(),
        Resp(b"x" * (1024 * 1024 + 1)),
        Resp(b"not json"),
        Resp(b"[1]"),
    ],
)
def test_client_other_failures_internal(result: object) -> None:
    api, _ = client(result)
    with pytest.raises(HelperError) as ei:
        api.get("/x")
    assert ei.value.code == "internal"
    assert ei.value.__cause__ is None


def test_client_refuses_redirects() -> None:
    handler = lookup._NoRedirect()
    import urllib.request

    req = urllib.request.Request("https://api.github.com/x")
    assert handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/") is None  # type: ignore[arg-type]


def test_client_repr_hides_token() -> None:
    api, _ = client(Resp(b"{}"))
    assert "tok_SECRET" not in repr(api)
