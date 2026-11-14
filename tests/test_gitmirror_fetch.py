from __future__ import annotations

import base64
import fcntl
import os
import subprocess
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from agentpass.gitmirror.fetch import FetchSettings, fetch, git_env
from agentpass.gitmirror.validate import FetchRequest, HelperError

TRUSTED = frozenset({0, os.getuid()})
TOKEN = "tok_SECRET"
TOKEN_B64 = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()

_FIXTURE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "LC_ALL": "C",
}


def g(cwd: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", *args], cwd=cwd, env=_FIXTURE_ENV, check=True, capture_output=True, text=True
    )
    return out.stdout.strip()


def commit(upstream: Path, name: str) -> str:
    (upstream / name).write_text(name)
    g(upstream, "add", name)
    g(upstream, "commit", "-q", "-m", name)
    return g(upstream, "rev-parse", "HEAD")


@pytest.fixture(autouse=True)
def _umask() -> Iterator[None]:
    # The production helper runs with a restrictive umask; a dev 0002 umask would make
    # git create group-writable mirror dirs that the path-safety check rightly refuses.
    old = os.umask(0o022)
    yield
    os.umask(old)


@pytest.fixture
def upstream(tmp_path: Path) -> Path:
    up = tmp_path / "upstream"
    up.mkdir()
    g(up, "init", "-q", "-b", "main")
    commit(up, "one")
    commit(up, "two")
    g(up, "checkout", "-q", "-b", "feat/x")
    commit(up, "three")
    g(up, "checkout", "-q", "main")
    return up


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "mirror"
    root.mkdir(mode=0o755)
    owner = root / "octo"
    owner.mkdir(mode=0o755)
    return owner / "hello.git"


@pytest.fixture
def settings(tmp_path: Path, upstream: Path) -> FetchSettings:
    home = tmp_path / "home"
    home.mkdir(mode=0o755)
    return FetchSettings(
        token=TOKEN,
        home=home,
        remote_url=lambda r: str(upstream),
        allowed_protocols=("file",),
        trusted_uids=TRUSTED,
    )


class Recorder:
    def __init__(self, fake: dict[str, subprocess.CompletedProcess] | None = None) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.fake = fake or {}

    def __call__(self, argv: list[str], **kw: object) -> subprocess.CompletedProcess:
        self.calls.append((list(argv), dict(kw)))
        for word, result in self.fake.items():
            if word in argv:
                return subprocess.CompletedProcess(argv, result.returncode, "", result.stderr)
        return subprocess.run(argv, **kw)


def req_for(upstream: Path, branch: str = "main", sha: str | None = None) -> FetchRequest:
    return FetchRequest("octo", "hello", branch, sha or g(upstream, "rev-parse", branch))


def ref(repo: Path, name: str) -> str | None:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", name],
        env=_FIXTURE_ENV,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip() or None


def test_first_fetch_creates_bare_mirror_at_sha(upstream, repo, settings) -> None:
    r = req_for(upstream)
    out = fetch(r, repo, settings)
    assert out["mirror_path"] == str(repo)
    assert out["ref"] == "refs/heads/main"
    assert out["sha"] == r.sha
    assert out["fetched_bytes"] > 0
    assert isinstance(out["duration_ms"], int) and out["duration_ms"] >= 0
    assert g(repo, "rev-parse", "--is-bare-repository") == "true"
    assert ref(repo, "refs/heads/main") == r.sha
    assert ref(repo, "refs/agentgit/incoming") is None
    assert g(repo, "log", "--format=%s", "main").splitlines() == ["two", "one"]


def test_fetch_slash_branch(upstream, repo, settings) -> None:
    r = req_for(upstream, "feat/x")
    out = fetch(r, repo, settings)
    assert out["ref"] == "refs/heads/feat/x"
    assert ref(repo, "refs/heads/feat/x") == r.sha


def test_second_fetch_updates_existing_mirror(upstream, repo, settings) -> None:
    fetch(req_for(upstream), repo, settings)
    new = commit(upstream, "four")
    out = fetch(req_for(upstream, sha=new), repo, settings)
    assert ref(repo, "refs/heads/main") == new
    assert out["fetched_bytes"] >= 0


def test_branch_moved_leaves_ref_untouched(upstream, repo, settings) -> None:
    old_old = g(upstream, "rev-parse", "main~1")
    old = g(upstream, "rev-parse", "main")
    fetch(req_for(upstream), repo, settings)
    commit(upstream, "four")
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream, sha=old_old), repo, settings)
    assert e.value.code == "branch_moved"
    assert ref(repo, "refs/heads/main") == old
    assert ref(repo, "refs/agentgit/incoming") is None


def test_rewritten_history_is_accepted(upstream, repo, settings) -> None:
    fetch(req_for(upstream), repo, settings)
    g(upstream, "reset", "-q", "--hard", "main~1")
    new = commit(upstream, "rewritten")
    fetch(req_for(upstream, sha=new), repo, settings)
    assert ref(repo, "refs/heads/main") == new


def test_token_not_in_argv_or_config(upstream, repo, settings) -> None:
    rec = Recorder()
    fetch(req_for(upstream), repo, replace(settings, run=rec))
    assert rec.calls
    for argv, kw in rec.calls:
        assert argv[0] == "git"
        assert not any(TOKEN in a or TOKEN_B64 in a for a in argv)
        assert kw["cwd"] == settings.home
        assert kw.get("shell", False) is False
        env = kw["env"]
        holders = [k for k, v in env.items() if TOKEN_B64 in v]
        assert len(holders) == 1 and holders[0].startswith("GIT_CONFIG_VALUE_")
        assert not any(TOKEN in v for v in env.values())
    for p in repo.rglob("*"):
        if p.is_file() and not p.is_symlink():
            data = p.read_bytes()
            assert TOKEN.encode() not in data, p
            assert TOKEN_B64.encode() not in data, p


def _expected_keys(n: int) -> set[str]:
    base = {
        "PATH",
        "HOME",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
        "GIT_ASKPASS",
        "GCM_INTERACTIVE",
        "LC_ALL",
        "GIT_CONFIG_COUNT",
    }
    for i in range(n):
        base |= {f"GIT_CONFIG_KEY_{i}", f"GIT_CONFIG_VALUE_{i}"}
    return base


def _config_pairs(env: dict[str, str]) -> list[tuple[str, str]]:
    n = int(env["GIT_CONFIG_COUNT"])
    return [(env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"]) for i in range(n)]


def test_env_is_closed(monkeypatch, settings) -> None:
    monkeypatch.setenv("GIT_DIR", "/x")
    monkeypatch.setenv("GIT_SSH_COMMAND", "evil")
    s = replace(settings, allowed_protocols=("https",))
    env = git_env(s)
    assert set(env) == _expected_keys(11)
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == str(settings.home)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ASKPASS"] == "/bin/false"
    assert env["GCM_INTERACTIVE"] == "never"
    assert env["LC_ALL"] == "C"
    assert _config_pairs(env) == [
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("fetch.recurseSubmodules", "false"),
        ("transfer.fsckObjects", "true"),
        ("fetch.fsckObjects", "true"),
        ("gc.auto", "0"),
        ("maintenance.auto", "false"),
        ("http.followRedirects", "false"),
        ("http.extraHeader", f"Authorization: Basic {TOKEN_B64}"),
    ]


def test_env_without_token_has_no_auth_header(settings) -> None:
    env = git_env(replace(settings, token=""))
    assert set(env) == _expected_keys(10)
    assert _config_pairs(env) == [
        ("protocol.allow", "never"),
        ("protocol.file.allow", "always"),
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("fetch.recurseSubmodules", "false"),
        ("transfer.fsckObjects", "true"),
        ("fetch.fsckObjects", "true"),
        ("gc.auto", "0"),
        ("maintenance.auto", "false"),
        ("http.followRedirects", "false"),
    ]
    assert not any(TOKEN in v or TOKEN_B64 in v for v in env.values())
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def _fail(stderr: str, rc: int = 128) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], rc, "", stderr)


def test_timeout_maps_to_timeout(upstream, repo, settings) -> None:
    def run(argv, **kw):
        if "fetch" in argv:
            assert 0 < kw["timeout"] <= settings.timeout_s
            raise subprocess.TimeoutExpired(argv, kw["timeout"])
        return subprocess.run(argv, **kw)

    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, run=run))
    assert e.value.code == "timeout"
    assert e.value.__cause__ is None and e.value.__suppress_context__


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


def test_one_total_budget_across_git_calls(upstream, repo, settings, monkeypatch) -> None:
    """Each git call gets only what is left of timeout_s; an exhausted budget is timeout."""
    import agentpass.gitmirror.fetch as fetch_mod

    clock = FakeClock()
    monkeypatch.setattr(fetch_mod, "time", clock)
    timeouts: list[float] = []

    def run(argv, **kw):
        timeouts.append(kw["timeout"])
        out = subprocess.run(argv, **kw)
        clock.now += 40  # every git call takes 40 s of the 100 s budget
        return out

    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, timeout_s=100, run=run))
    assert e.value.code == "timeout"
    assert timeouts == [100, 60, 20]  # init, fetch, rev-parse; update-ref has no budget left
    assert ref(repo, "refs/heads/main") is None


@pytest.mark.parametrize(
    "stderr",
    [
        "fatal: Authentication failed for 'https://github.com/octo/hello.git/'",
        "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
        "fatal: unable to access '...': The requested URL returned error: 403",
        "fatal: unable to access '...': The requested URL returned error: 401",
    ],
)
def test_auth_failure_maps_to_auth_failed(upstream, repo, settings, stderr) -> None:
    rec = Recorder({"fetch": _fail(stderr)})
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, token="", run=rec))
    assert e.value.code == "auth_failed"
    fetch_argv, fetch_kw = next((a, kw) for a, kw in rec.calls if "fetch" in a)
    assert "--no-auto-maintenance" in fetch_argv
    assert fetch_kw["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert fetch_kw.get("stdin") == subprocess.DEVNULL


def test_repository_not_found_maps_to_not_found(upstream, repo, settings) -> None:
    rec = Recorder({"fetch": _fail("remote: Repository not found.\nfatal: repository not found")})
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, run=rec))
    assert e.value.code == "not_found"


def test_unknown_branch_is_not_found(upstream, repo, settings) -> None:
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream, "nope", sha="b" * 40), repo, settings)
    assert e.value.code == "not_found"
    assert ref(repo, "refs/heads/nope") is None


def test_size_cap(upstream, repo, settings) -> None:
    old = g(upstream, "rev-parse", "main")
    fetch(req_for(upstream), repo, settings)
    new = commit(upstream, "four")
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream, sha=new), repo, replace(settings, max_bytes=1))
    assert e.value.code == "too_large"
    assert ref(repo, "refs/heads/main") == old
    assert ref(repo, "refs/agentgit/incoming") is None


def test_size_cap_on_first_fetch_leaves_no_branch(upstream, repo, settings) -> None:
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, max_bytes=1))
    assert e.value.code == "too_large"
    assert ref(repo, "refs/heads/main") is None
    assert ref(repo, "refs/agentgit/incoming") is None


def test_concurrent_fetch_returns_busy(upstream, repo, settings) -> None:
    rec = Recorder()
    lock = repo.parent / f".{repo.name}.lock"
    fd = os.open(lock, os.O_CREAT | os.O_WRONLY, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(HelperError) as e:
            fetch(req_for(upstream), repo, replace(settings, run=rec))
        assert e.value.code == "busy"
        assert rec.calls == []
    finally:
        os.close(fd)
    # lock released by the holder -> fetch proceeds
    fetch(req_for(upstream), repo, replace(settings, run=rec))
    assert rec.calls


def test_lock_released_after_failure(upstream, repo, settings) -> None:
    with pytest.raises(HelperError):
        fetch(req_for(upstream, "nope", sha="b" * 40), repo, settings)
    fd = os.open(repo.parent / f".{repo.name}.lock", os.O_WRONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # would raise if still held
    finally:
        os.close(fd)


def test_lock_file_symlink_refused(upstream, repo, settings, tmp_path) -> None:
    target = tmp_path / "elsewhere"
    (repo.parent / f".{repo.name}.lock").symlink_to(target)
    rec = Recorder()
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, run=rec))
    assert e.value.code == "unsafe_path"
    assert rec.calls == [] and not target.exists()


def test_unsafe_mirror_parent(upstream, repo, settings) -> None:
    repo.parent.chmod(0o775)
    rec = Recorder()
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, run=rec))
    assert e.value.code == "unsafe_path"
    assert rec.calls == []
    # checked before the lock file is opened: nothing is created in an unsafe directory
    assert not (repo.parent / f".{repo.name}.lock").exists()


def test_lock_file_opened_nonblocking(upstream, repo, settings, monkeypatch) -> None:
    """O_NONBLOCK: a FIFO planted at the lock path cannot hang the helper in open()."""
    seen: list[int] = []
    real_open = os.open

    def spy(path, flags, *a, **kw):
        if str(path).endswith(f".{repo.name}.lock"):
            seen.append(flags)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", spy)
    fetch(req_for(upstream), repo, settings)
    assert seen and all(f & os.O_NONBLOCK and f & os.O_NOFOLLOW for f in seen)


def test_unsafe_existing_repo_config(upstream, repo, settings) -> None:
    fetch(req_for(upstream), repo, settings)
    (repo / "config").chmod(0o666)
    rec = Recorder()
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, run=rec))
    assert e.value.code == "unsafe_path"
    assert rec.calls == []


def test_unsafe_home(upstream, repo, settings) -> None:
    settings.home.chmod(0o777)
    rec = Recorder()
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, run=rec))
    assert e.value.code == "unsafe_path"
    assert rec.calls == []


def test_error_text_never_contains_stderr(upstream, repo, settings, capsys) -> None:
    stderr = f"fatal: weird failure {TOKEN} Authorization: Basic {TOKEN_B64}"
    rec = Recorder({"fetch": _fail(stderr)})
    with pytest.raises(HelperError) as e:
        fetch(req_for(upstream), repo, replace(settings, run=rec))
    err = e.value
    assert err.code == "internal"
    assert str(err) == "internal"
    assert err.args == ("internal",)
    assert err.__cause__ is None
    logged = capsys.readouterr()
    assert "weird failure" in logged.err  # stderr goes to the journal ...
    assert TOKEN not in logged.err and TOKEN_B64 not in logged.err  # ... scrubbed
    assert "***" in logged.err
    assert TOKEN not in logged.out and "weird" not in logged.out


def test_settings_repr_hides_token(settings) -> None:
    assert TOKEN not in repr(settings) and TOKEN_B64 not in repr(settings)
