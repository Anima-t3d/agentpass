"""Tests for the in-gateway git-mirror service (talks to the helper socket)."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

import agentpass.gitmirror.plugin as plugin_mod
from agentpass.__main__ import _load_plugin_service
from agentpass.config import AuthConfig, ConfigError, ServiceConfig, ToolDefinition
from agentpass.executor import ExecutionError
from agentpass.gitmirror.plugin import GitMirrorService

SHA = "a" * 40
ARGS = {"owner": "octo", "repo": "demo", "branch": "main", "sha": SHA}

MESSAGES = {
    "branch_moved": "branch moved since approval; read the tip again and retry",
    "not_allowed": "repository is not on the mirror allowlist",
    "not_configured": "repository has no mirror directory; ask the owner",
    "busy": "a fetch of this repository is already running",
    "too_large": "repository exceeds the mirror size cap",
    "timeout": "fetch timed out",
    "auth_failed": "mirror token rejected; ask the owner",
    "not_found": "repository or branch not found",
    "unsafe_path": "mirror path is not safe; ask the owner",
    "invalid_request": "invalid request",
    "internal": "mirror helper failed",
}

Responder = Callable[[dict], Awaitable[bytes | None]]


def _cfg(url: str, handler_class: str = "") -> ServiceConfig:
    return ServiceConfig(
        name="git_mirror",
        url=url,
        auth=AuthConfig(type="none"),
        handler="python",
        handler_class=handler_class,
        tools=[ToolDefinition(name="gh_mirror_fetch", service_name="git_mirror")],
    )


def _line(obj: dict) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode()


class FakeHelper:
    """A unix-socket server speaking the helper's one-line protocol."""

    def __init__(self, path: Path, respond: Responder) -> None:
        self.path = path
        self.respond = respond
        self.requests: list[dict] = []
        self.raw: list[bytes] = []
        self.server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await reader.readline()
            self.raw.append(raw)
            req = json.loads(raw)
            self.requests.append(req)
            out = await self.respond(req)
            if out is not None:
                writer.write(out)
                await writer.drain()
        finally:
            writer.close()

    async def __aenter__(self) -> FakeHelper:
        self.server = await asyncio.start_unix_server(self._handle, path=str(self.path))
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


def _reply(obj: dict) -> Responder:
    async def respond(req: dict) -> bytes:
        return _line(obj)

    return respond


@pytest.fixture
def sock(tmp_path: Path) -> Path:
    return tmp_path / "h.sock"


def _svc(sock: Path) -> GitMirrorService:
    return GitMirrorService(_cfg(f"unix://{sock}"), [])


# --- config ---------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["http://localhost/x", "unix://relative/path", "unix://", "/run/agentgit/helper.sock", ""],
)
def test_url_must_be_absolute_unix(url: str) -> None:
    with pytest.raises(ConfigError):
        GitMirrorService(_cfg(url), [])


def test_url_accepts_absolute_unix() -> None:
    svc = GitMirrorService(_cfg("unix:///run/agentgit/helper.sock"), [])
    assert svc.socket_path == "/run/agentgit/helper.sock"


def test_load_plugin_service_loads_it(sock: Path) -> None:
    svc = _load_plugin_service(
        _cfg(f"unix://{sock}", "agentpass.gitmirror.plugin:GitMirrorService")
    )
    assert isinstance(svc, GitMirrorService)


# --- execute --------------------------------------------------------------


async def test_execute_happy_path_returns_result(sock: Path) -> None:
    result = {"sha": SHA, "ref": "refs/heads/main", "size": 123}
    async with FakeHelper(sock, _reply({"ok": True, "result": result})) as helper:
        out = await _svc(sock).execute("gh_mirror_fetch", {**ARGS, "extra": "x"})
    assert out == result
    assert helper.requests == [{"op": "fetch", **ARGS}]
    assert helper.raw[0] == _line({"op": "fetch", **ARGS})


@pytest.mark.parametrize("code", sorted(MESSAGES))
async def test_execute_error_codes_map_to_fixed_messages(sock: Path, code: str) -> None:
    async with FakeHelper(sock, _reply({"ok": False, "error": code})):
        with pytest.raises(ExecutionError) as ei:
            await _svc(sock).execute("gh_mirror_fetch", ARGS)
    assert str(ei.value) == MESSAGES[code]
    assert ei.value.public is True  # fixed text: kept in polled (stored) results


async def test_execute_unknown_code_is_internal(sock: Path) -> None:
    async with FakeHelper(sock, _reply({"ok": False, "error": "secret ghp_token stderr"})):
        with pytest.raises(ExecutionError) as ei:
            await _svc(sock).execute("gh_mirror_fetch", ARGS)
    assert str(ei.value) == "mirror helper failed"


@pytest.mark.parametrize(
    "reply",
    [
        None,  # closed without a reply
        b"not json\n",
        b"[1,2]\n",
        b'{"ok":true}\n',  # ok without a result dict
        b'{"ok":true,"result":"str"}\n',
        b'{"ok":"yes","result":{}}\n',
        b'{"ok":true,"result":{}',  # no newline, truncated
    ],
)
async def test_execute_malformed_reply_is_internal(sock: Path, reply: bytes | None) -> None:
    async def respond(req: dict) -> bytes | None:
        return reply

    async with FakeHelper(sock, respond):
        with pytest.raises(ExecutionError) as ei:
            await _svc(sock).execute("gh_mirror_fetch", ARGS)
    assert str(ei.value) == "mirror helper failed"


async def test_execute_deeply_nested_reply_is_internal(sock: Path) -> None:
    depth = 100_000  # json.loads raises RecursionError, well under MAX_REPLY

    async def respond(req: dict) -> bytes:
        return b'{"ok":true,"result":' + b"[" * depth + b"]" * depth + b"}\n"

    async with FakeHelper(sock, respond):
        with pytest.raises(ExecutionError) as ei:
            await _svc(sock).execute("gh_mirror_fetch", ARGS)
    assert str(ei.value) == "mirror helper failed"


async def test_lookup_deeply_nested_reply_is_internal(sock: Path) -> None:
    depth = 100_000

    async def respond(req: dict) -> bytes:
        return b'{"ok":true,"result":' + b"[" * depth + b"]" * depth + b"}\n"

    async with FakeHelper(sock, respond):
        with pytest.raises(LookupError) as ei:
            await _svc(sock).lookup("/commit", ARGS)
    assert ei.value.args == ("internal",)


async def test_execute_socket_missing_is_internal_without_os_text(sock: Path) -> None:
    with pytest.raises(ExecutionError) as ei:
        await _svc(sock).execute("gh_mirror_fetch", ARGS)
    assert str(ei.value) == "mirror helper failed"
    assert str(sock) not in str(ei.value)


async def test_execute_oversized_reply_is_internal(sock: Path) -> None:
    async def respond(req: dict) -> bytes:
        return b'{"ok":true,"result":{"x":"' + b"a" * (2 * 1024 * 1024) + b'"}}\n'

    async with FakeHelper(sock, respond):
        with pytest.raises(ExecutionError) as ei:
            await _svc(sock).execute("gh_mirror_fetch", ARGS)
    assert str(ei.value) == "mirror helper failed"


async def test_execute_deadline_is_internal(sock: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugin_mod, "FETCH_TIMEOUT_S", 0.2)

    async def respond(req: dict) -> bytes:
        await asyncio.sleep(1)
        return _line({"ok": True, "result": {}})

    async with FakeHelper(sock, respond):
        with pytest.raises(ExecutionError) as ei:
            await _svc(sock).execute("gh_mirror_fetch", ARGS)
    assert str(ei.value) == "mirror helper failed"


def test_fetch_timeout_default() -> None:
    assert plugin_mod.FETCH_TIMEOUT_S == 690


async def test_execute_other_tool_is_value_error(sock: Path) -> None:
    with pytest.raises(ValueError):
        await _svc(sock).execute("gh_other", ARGS)


# --- lookup ---------------------------------------------------------------


async def test_lookup_commit_returns_result(sock: Path) -> None:
    result = {"sha": SHA, "headline": "fix", "tip": SHA}
    async with FakeHelper(sock, _reply({"ok": True, "result": result})) as helper:
        out = await _svc(sock).lookup("/commit", {**ARGS, "junk": 1})
    assert out == result
    assert helper.requests == [{"op": "lookup", "kind": "commit", **ARGS}]


async def test_lookup_relation_sends_kind(sock: Path) -> None:
    result = {"state": "new", "previous": None, "summary": "first fetch of this branch"}
    async with FakeHelper(sock, _reply({"ok": True, "result": result})) as helper:
        out = await _svc(sock).lookup("/relation", ARGS)
    assert out == result
    assert helper.requests[0]["kind"] == "relation"


@pytest.mark.parametrize("code", ["not_allowed", "not_found", "internal"])
async def test_lookup_error_raises_lookup_error_with_code(sock: Path, code: str) -> None:
    async with FakeHelper(sock, _reply({"ok": False, "error": code})):
        with pytest.raises(LookupError) as ei:
            await _svc(sock).lookup("/commit", ARGS)
    assert ei.value.args == (code,)


async def test_lookup_unknown_code_is_internal(sock: Path) -> None:
    async with FakeHelper(sock, _reply({"ok": False, "error": "leaky text"})):
        with pytest.raises(LookupError) as ei:
            await _svc(sock).lookup("/commit", ARGS)
    assert ei.value.args == ("internal",)


@pytest.mark.parametrize(
    "path",
    ["", "commit", "relation", "/commits", "/fetch", "//commit", "/../commit", "/commit/x"],
)
async def test_lookup_invalid_path(sock: Path, path: str) -> None:
    async with FakeHelper(sock, _reply({"ok": True, "result": {}})) as helper:
        with pytest.raises(LookupError) as ei:
            await _svc(sock).lookup(path, ARGS)
    assert ei.value.args == ("invalid_request",)
    assert helper.requests == []


async def test_lookup_socket_missing_is_internal(sock: Path) -> None:
    with pytest.raises(LookupError) as ei:
        await _svc(sock).lookup("/commit", ARGS)
    assert ei.value.args == ("internal",)


async def test_lookup_honours_timeout(sock: Path) -> None:
    async def respond(req: dict) -> bytes:
        await asyncio.sleep(1)
        return _line({"ok": True, "result": {}})

    async with FakeHelper(sock, respond):
        start = time.monotonic()
        with pytest.raises(LookupError) as ei:
            await _svc(sock).lookup("/commit", ARGS, timeout=0.2)
        assert time.monotonic() - start < 2
    assert ei.value.args == ("internal",)


async def test_slow_fetch_does_not_block_lookup(sock: Path) -> None:
    async def respond(req: dict) -> bytes:
        if req["op"] == "fetch":
            await asyncio.sleep(2)
            return _line({"ok": True, "result": {"done": True}})
        return _line({"ok": True, "result": {"looked": True}})

    svc = _svc(sock)
    async with FakeHelper(sock, respond):
        fetch = asyncio.create_task(svc.execute("gh_mirror_fetch", ARGS))
        await asyncio.sleep(0.05)
        start = time.monotonic()
        assert await svc.lookup("/commit", ARGS) == {"looked": True}
        assert time.monotonic() - start < 0.5
        assert not fetch.done()
        assert await fetch == {"done": True}


# --- health / close ---------------------------------------------------------


async def test_health_check_true_on_ping(sock: Path) -> None:
    async with FakeHelper(sock, _reply({"ok": True})) as helper:
        assert await _svc(sock).health_check() is True
    assert helper.requests == [{"op": "ping"}]


async def test_health_check_false_when_socket_missing(sock: Path) -> None:
    assert await _svc(sock).health_check() is False


async def test_health_check_false_on_error_reply(sock: Path) -> None:
    async with FakeHelper(sock, _reply({"ok": False, "error": "internal"})):
        assert await _svc(sock).health_check() is False


async def test_close_is_noop(sock: Path) -> None:
    await _svc(sock).close()


# --- never runs git ----------------------------------------------------------


def test_plugin_never_runs_git() -> None:
    assert "subprocess" not in vars(plugin_mod)
    source = inspect.getsource(plugin_mod)
    for banned in ("subprocess", "os.system", "create_subprocess", "os.exec", "os.spawn", "popen"):
        assert banned not in source.lower(), banned
