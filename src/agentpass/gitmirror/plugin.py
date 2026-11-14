"""AgentPass service that fetches into the git mirror through the helper socket.

Runs inside the gateway. It never runs git and never sees the token: every
operation is one JSON line to the helper's Unix socket and one JSON line back.
Only fixed error codes and fixed messages ever leave this module.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agentpass.config import ConfigError, ServiceConfig, ToolDefinition
from agentpass.executor import ExecutionError
from agentpass.services.base import ServiceHandler

FETCH_TOOL = "gh_mirror_fetch"
FETCH_TIMEOUT_S = 660.0  # helper fetch timeout (600 s) plus slack
HEALTH_TIMEOUT_S = 5.0
MAX_REPLY = 1024 * 1024
_FIELDS = ("owner", "repo", "branch", "sha")
_LOOKUP_PATHS = {"/commit": "commit", "/relation": "relation"}  # preview path -> helper kind
_UNIX_PREFIX = "unix://"

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


class _HelperFailed(Exception):
    """The helper answered with an error code (always one of ``MESSAGES``)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code if code in MESSAGES else "internal"


class GitMirrorService(ServiceHandler):
    """Talks to the git-mirror helper over its Unix socket."""

    def __init__(self, config: ServiceConfig, tools: list[ToolDefinition]) -> None:
        url = config.url or ""
        path = url[len(_UNIX_PREFIX) :] if url.startswith(_UNIX_PREFIX) else ""
        if not path.startswith("/") or len(path) < 2:
            raise ConfigError(
                f"Service '{config.name}': url must be unix:///absolute/path, got {url!r}"
            )
        self.socket_path = path
        self.tools = tools

    async def _call(self, request: dict[str, Any], timeout: float) -> Any:
        """Send one request line and return ``result`` (or ``None``) from an ok reply.

        Raises ``_HelperFailed`` for helper error codes and for any transport or
        protocol failure (as ``internal``); never carries OS or reply text.
        """
        try:
            return await asyncio.wait_for(self._exchange(request), timeout)
        except _HelperFailed:
            raise
        except (
            OSError,  # socket missing, refused, reset
            TimeoutError,  # deadline
            ValueError,  # bad JSON or UTF-8
            RecursionError,  # deeply nested JSON
            asyncio.IncompleteReadError,  # closed before a full line
            asyncio.LimitOverrunError,  # reply over MAX_REPLY
        ) as e:
            raise _HelperFailed("internal") from e

    async def _exchange(self, request: dict[str, Any]) -> Any:
        reader, writer = await asyncio.open_unix_connection(self.socket_path, limit=MAX_REPLY)
        try:
            writer.write((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
            await writer.drain()
            line = await reader.readuntil(b"\n")
        finally:
            writer.close()
        reply = json.loads(line.decode("utf-8"))
        if not isinstance(reply, dict):
            raise _HelperFailed("internal")
        if reply.get("ok") is True:
            return reply.get("result")
        if reply.get("ok") is False:
            code = reply.get("error")
            raise _HelperFailed(code if isinstance(code, str) else "internal")
        raise _HelperFailed("internal")

    async def execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool_name != FETCH_TOOL:
            raise ValueError(f"Unknown tool for git mirror service: {tool_name}")
        request = {"op": "fetch", **{k: args.get(k) for k in _FIELDS}}
        try:
            result = await self._call(request, FETCH_TIMEOUT_S)
        except _HelperFailed as e:
            raise ExecutionError(MESSAGES[e.code], public=True) from None
        if not isinstance(result, dict):
            raise ExecutionError(MESSAGES["internal"], public=True)
        return result

    async def lookup(
        self,
        path: str,
        args: dict[str, Any],
        *,
        query: dict[str, str] | None = None,
        timeout: float = 2.0,
        max_bytes: int = 262144,
    ) -> Any:
        kind = _LOOKUP_PATHS.get(path)
        if kind is None:
            raise LookupError("invalid_request")
        request = {"op": "lookup", "kind": kind, **{k: args.get(k) for k in _FIELDS}}
        try:
            result = await self._call(request, timeout)
        except _HelperFailed as e:
            raise LookupError(e.code) from None
        if not isinstance(result, dict):
            raise LookupError("internal")
        return result

    async def health_check(self) -> bool:
        try:
            await self._call({"op": "ping"}, HEALTH_TIMEOUT_S)
        except _HelperFailed:
            return False
        return True

    async def close(self) -> None:
        return None
