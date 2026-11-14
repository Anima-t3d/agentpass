from __future__ import annotations

import io
import json
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agentpass.gitmirror import helper
from agentpass.gitmirror.fetch import FetchSettings
from agentpass.gitmirror.helper import serve
from agentpass.gitmirror.validate import HelperError
from tests.test_gitmirror_fetch import TOKEN, TOKEN_B64, TRUSTED, commit, g


class FakeApi:
    def __init__(self, docs: dict[str, dict] | None = None) -> None:
        self.docs = docs or {}

    def get(self, path: str) -> dict:
        return self.docs[path]


@pytest.fixture(autouse=True)
def _umask() -> Iterator[None]:
    old = os.umask(0o022)
    yield
    os.umask(old)


@pytest.fixture
def env(tmp_path: Path) -> dict[str, Any]:
    up = tmp_path / "upstream"
    up.mkdir()
    g(up, "init", "-q", "-b", "main")
    tip = commit(up, "one")
    root = tmp_path / "mirror"
    root.mkdir(mode=0o755)
    (root / "octo").mkdir(mode=0o755)
    home = tmp_path / "home"
    home.mkdir(mode=0o755)
    allow = tmp_path / "repos"
    allow.write_text("# comment\nocto/hello\n")
    settings = FetchSettings(
        token=TOKEN,
        home=home,
        remote_url=lambda r: str(up),
        allowed_protocols=("file",),
        trusted_uids=TRUSTED,
    )
    return {"settings": settings, "allow": allow, "root": root, "tip": tip}


def raw_call(env: dict[str, Any], raw: bytes, api: Any = None) -> bytes:
    out = io.BytesIO()
    serve(io.BytesIO(raw), out, env["settings"], env["allow"], env["root"], api=api or FakeApi())
    return out.getvalue()


def call(env: dict[str, Any], request: Any, api: Any = None) -> dict:
    raw = request if isinstance(request, bytes) else json.dumps(request).encode() + b"\n"
    data = raw_call(env, raw, api)
    assert data.endswith(b"\n") and data.count(b"\n") == 1
    return json.loads(data)


def body(env: dict[str, Any], op: str = "fetch", **kw: str) -> dict:
    d = {"op": op, "owner": "octo", "repo": "hello", "branch": "main", "sha": env["tip"]}
    d.update(kw)
    return d


def test_ping(env):
    assert call(env, {"op": "ping"}) == {"ok": True}


def test_response_is_compact(env):
    assert raw_call(env, b'{"op":"ping"}\n') == b'{"ok":true}\n'


def test_fetch_happy_path(env):
    res = call(env, body(env))
    assert res["ok"] is True
    assert res["result"]["sha"] == env["tip"]
    assert res["result"]["ref"] == "refs/heads/main"
    got = subprocess.run(
        ["git", "-C", res["result"]["mirror_path"], "rev-parse", "refs/heads/main"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert got == env["tip"]


def test_not_allowed(env):
    assert call(env, body(env, repo="other")) == {"ok": False, "error": "not_allowed"}


def test_not_configured(env):
    env["allow"].write_text("nobody/hello\n")
    assert call(env, body(env, owner="nobody")) == {"ok": False, "error": "not_configured"}


@pytest.mark.parametrize(
    "req",
    [{"op": "rm"}, {"op": "lookup", "kind": "x"}, {"op": "fetch"}, [1], {"op": 1}, {}],
)
def test_invalid_requests(env, req):
    assert call(env, req) == {"ok": False, "error": "invalid_request"}


def test_unknown_op_with_valid_fields(env):
    assert call(env, body(env, op="rm"))["error"] == "invalid_request"


def test_oversize_line(env):
    line = b'{"op":"ping","x":"' + b"a" * 5000 + b'"}\n'
    assert call(env, line)["error"] == "invalid_request"


def test_size_boundary(env):
    ping = b'{"op":"ping"}'
    assert call(env, ping + b" " * (4096 - len(ping)) + b"\n") == {"ok": True}
    assert call(env, ping + b" " * (4097 - len(ping)) + b"\n")["error"] == "invalid_request"
    # no newline at all, over the limit
    assert call(env, ping + b" " * 5000)["error"] == "invalid_request"


@pytest.mark.parametrize("raw", [b"not json\n", b"", b"\n", b"\xff\xfe\n", b'{"op":"ping"'])
def test_non_json(env, raw):
    assert call(env, raw) == {"ok": False, "error": "invalid_request"}


def test_internal_error_hides_details(env, capsys, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError(f"secret detail {TOKEN} {TOKEN_B64}")

    monkeypatch.setattr(helper, "fetch", boom)
    data = raw_call(env, json.dumps(body(env)).encode() + b"\n")
    assert json.loads(data) == {"ok": False, "error": "internal"}
    assert b"secret" not in data
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert TOKEN not in err and TOKEN_B64 not in err


def test_helper_error_code_passes_through(env, monkeypatch):
    def raiser(*a, **k):
        raise HelperError("busy")

    monkeypatch.setattr(helper, "fetch", raiser)
    assert call(env, body(env)) == {"ok": False, "error": "busy"}


def test_lookup_commit(env):
    base = "/repos/octo/hello"
    api = FakeApi(
        {
            f"{base}/commits/{env['tip']}": {
                "commit": {
                    "message": "head\n\nbody",
                    "author": {"name": "A"},
                    "committer": {"date": "2026-01-01T00:00:00Z"},
                }
            },
            f"{base}/branches/main": {"commit": {"sha": env["tip"]}},
        }
    )
    res = call(env, body(env, "lookup", kind="commit"), api=api)
    assert res["ok"] and res["result"]["headline"] == "head"
    assert res["result"]["is_tip"] == "yes"


def test_lookup_relation_new(env):
    res = call(env, body(env, "lookup", kind="relation"))
    assert res["ok"] and res["result"]["state"] == "new"


@pytest.mark.parametrize("kind", ["commit", "relation"])
def test_lookup_checks_allowlist(env, kind):
    res = call(env, body(env, "lookup", kind=kind, repo="other"))
    assert res == {"ok": False, "error": "not_allowed"}


def test_lookup_relation_checks_not_configured(env):
    env["allow"].write_text("nobody/hello\n")
    res = call(env, body(env, "lookup", kind="relation", owner="nobody"))
    assert res == {"ok": False, "error": "not_configured"}


def test_load_token(tmp_path, monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    assert helper.load_token() == ""
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert helper.load_token() == ""
    (tmp_path / "github-token").write_text("  abc\n")
    assert helper.load_token() == "abc"
    (tmp_path / "github-token").write_text("\n")
    assert helper.load_token() == ""


def _serve_on_socket(env, server, **kw):
    f = server.makefile("rwb", buffering=0)
    serve(f, f, env["settings"], env["allow"], env["root"], api=FakeApi(), **kw)
    f.close()


def test_silent_peer_times_out(env):
    import socket
    import time

    client, server = socket.socketpair()
    with client, server:
        start = time.monotonic()
        _serve_on_socket(env, server, read_timeout_s=0.3)
        assert time.monotonic() - start < 3
        assert json.loads(client.recv(1000)) == {"ok": False, "error": "timeout"}


def test_partial_line_times_out(env):
    import socket

    client, server = socket.socketpair()
    with client, server:
        client.sendall(b'{"op":"pi')
        _serve_on_socket(env, server, read_timeout_s=0.3)
        assert json.loads(client.recv(1000))["error"] == "timeout"


def test_closed_peer_does_not_hang(env):
    import socket

    client, server = socket.socketpair()
    with server:
        client.close()
        _serve_on_socket(env, server, read_timeout_s=0.3)  # EOF -> invalid_request, write may fail


def test_timeout_with_unwritable_peer_exits_quietly(env):
    import socket

    client, server = socket.socketpair()
    with server:
        client.close()
        f = server.makefile("rwb", buffering=0)
        server.shutdown(socket.SHUT_RDWR)
        serve(f, f, env["settings"], env["allow"], env["root"], read_timeout_s=0.2)


def test_socket_end_to_end(env):
    import socket

    client, server = socket.socketpair()
    with client, server:
        client.sendall(json.dumps(body(env)).encode() + b"\n")
        _serve_on_socket(env, server, read_timeout_s=5)
        res = json.loads(client.recv(100000))
        assert res["ok"] is True and res["result"]["sha"] == env["tip"]


def test_socket_oversize(env):
    import socket

    client, server = socket.socketpair()
    with client, server:
        client.sendall(b"a" * 5000)
        _serve_on_socket(env, server, read_timeout_s=5)
        assert json.loads(client.recv(1000))["error"] == "invalid_request"
