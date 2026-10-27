"""Agent SDK for agentpass — core protocol + auto-reconnection."""

from __future__ import annotations

import asyncio
import contextlib
import json

import websockets
from websockets.asyncio.client import unix_connect

# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


UNIX_SCHEME = "unix://"


def socket_url(path: str) -> str:
    """The client URL for a Unix socket path (``--socket PATH``)."""
    return f"{UNIX_SCHEME}{path}"


async def _open(url: str) -> websockets.ClientConnection:
    """Open the WebSocket; ``unix:///path/to.sock`` connects over a Unix socket (plaintext)."""
    if url.startswith(UNIX_SCHEME):
        path = url[len(UNIX_SCHEME) :]
        if not path.startswith("/"):
            raise OSError(f"unix URL needs an absolute socket path: {url!r}")
        return await unix_connect(path, "ws://localhost/")
    return await websockets.connect(url)


class AgentPassError(Exception):
    """Base error for agentpass SDK."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class AgentPassDenied(AgentPassError):
    """Tool request was denied (by policy or by user). Codes: -32001, -32003."""


class AgentPassTimeout(AgentPassError):
    """Approval request timed out. Code: -32002."""


class AgentPassConnectionError(AgentPassError):
    """Connection or authentication failure."""


# ---------------------------------------------------------------------------
# AgentPassClient
# ---------------------------------------------------------------------------


class AgentPassClient:
    """Async client SDK for the agentpass WebSocket gateway.

    Usage::

        async with AgentPassClient("wss://gateway:8443", token) as client:
            result = await client.tool_request("ha_get_state", entity_id="sensor.temp")
    """

    def __init__(
        self,
        url: str,
        token: str,
        *,
        max_retries: int | None = None,
    ) -> None:
        self.url = url
        self.token = token
        self._max_retries = max_retries
        self._ws: websockets.WebSocketClientProtocol | None = None
        self._request_counter = 0
        self._pending: dict[int, asyncio.Future] = {}  # request_id -> Future
        self._reader_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._connected = asyncio.Event()
        self._closed = False

    # -- public API ----------------------------------------------------------

    async def connect(self) -> None:
        """Connect to gateway and authenticate."""
        self._ws = await _open(self.url)
        await self._authenticate()
        self._connected.set()
        self._reader_task = asyncio.create_task(self._read_loop())

    async def tool_request(self, tool: str, **args: object) -> dict:
        """Send tool request, await result. Raises typed errors."""
        request_id = self._next_id()
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future

        # Wait for connection if currently reconnecting
        if not self._connected.is_set():
            await self._connected.wait()
        if self._closed:
            raise AgentPassConnectionError(-1, "Client is closed")

        await self._ws.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "tool_request",
                    "params": {"tool": tool, "args": args},
                    "id": request_id,
                }
            )
        )

        result = await future
        return result.get("data")

    async def list_tools(self, timeout: float = 10) -> list:
        """Retrieve available tools from the gateway."""
        request_id = self._next_id()
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future

        if not self._connected.is_set():
            await self._connected.wait()

        await self._ws.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "list_tools",
                    "params": {},
                    "id": request_id,
                }
            )
        )

        result = await asyncio.wait_for(future, timeout=timeout)
        return result.get("tools", [])

    async def get_pending_results(self) -> list:
        """Retrieve results for requests resolved while disconnected."""
        request_id = self._next_id()
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future

        await self._ws.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "get_pending_results",
                    "params": {},
                    "id": request_id,
                }
            )
        )

        response = await future
        results = response.get("results", [])
        self._resolve_offline_results(results)
        return results

    async def close(self) -> None:
        """Disconnect from gateway."""
        self._closed = True
        self._connected.set()  # Wake up anything waiting to send
        if self._reader_task is not None and not self._reader_task.done():
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
        if self._reconnect_task is not None and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reconnect_task
        if self._ws is not None:
            await self._ws.close()
            self._ws = None

    # -- context manager -----------------------------------------------------

    async def __aenter__(self) -> AgentPassClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # -- internals -----------------------------------------------------------

    def _next_id(self) -> int:
        self._request_counter += 1
        return self._request_counter

    async def _authenticate(self) -> None:
        """Send auth, validate response."""
        await self._ws.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "auth",
                    "params": {"token": self.token},
                    "id": "auth-1",
                }
            )
        )
        raw = await self._ws.recv()
        msg = json.loads(raw)
        if "error" in msg:
            err = msg["error"]
            raise AgentPassConnectionError(
                err.get("code", -1),
                err.get("message", "Auth failed"),
            )
        result = msg.get("result", {})
        if result.get("status") != "authenticated":
            raise AgentPassConnectionError(-1, "Unexpected auth response")

    async def _read_loop(self) -> None:
        """Background task: read responses and dispatch to pending futures."""
        try:
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue  # Skip malformed messages

                msg_id = msg.get("id")
                if msg_id is None:
                    continue

                # Convert string IDs back to int for matching
                if isinstance(msg_id, str) and msg_id.isdigit():
                    msg_id = int(msg_id)

                future = self._pending.pop(msg_id, None)
                if future is None or future.done():
                    continue

                if "error" in msg:
                    err = msg["error"]
                    code = err.get("code", -1)
                    message = err.get("message", "Unknown error")
                    if code in (-32001, -32003):
                        future.set_exception(AgentPassDenied(code, message))
                    elif code == -32002:
                        future.set_exception(AgentPassTimeout(code, message))
                    else:
                        future.set_exception(AgentPassError(code, message))
                else:
                    future.set_result(msg.get("result", {}))
        except websockets.exceptions.ConnectionClosed:
            if not self._closed:
                self._connected.clear()
                self._reconnect_task = asyncio.create_task(self._reconnect())
        except asyncio.CancelledError:
            pass

    def _resolve_offline_results(self, results: list) -> None:
        """Resolve pending futures whose request_id appears in offline results."""
        for item in results:
            rid = item.get("request_id")
            if rid is None:
                continue

            # The server returns raw DB rows where "result" is a JSON string
            result_str = item.get("result")
            if isinstance(result_str, str):
                try:
                    parsed = json.loads(result_str)
                except json.JSONDecodeError:
                    continue
            elif isinstance(result_str, dict):
                parsed = result_str
            else:
                continue

            status = parsed.get("status")
            data = parsed.get("data")

            # Try both string and int forms of the request_id
            for key in (
                rid,
                int(rid) if isinstance(rid, str) and rid.isdigit() else rid,
            ):
                future = self._pending.pop(key, None)
                if future is not None and not future.done():
                    if status == "executed":
                        future.set_result(data)
                    elif status == "denied":
                        future.set_exception(
                            AgentPassDenied(-32001, data if isinstance(data, str) else "Denied")
                        )
                    elif status == "error":
                        future.set_exception(
                            AgentPassError(
                                -32004, data if isinstance(data, str) else "Execution failed"
                            )
                        )

    async def _backoff_sleep(self, delay: float) -> None:
        """Sleep for the given delay. Override in tests to skip real waits."""
        await asyncio.sleep(delay)

    async def _reconnect(self) -> None:
        """Reconnect with exponential backoff."""
        delay = 1.0
        max_delay = 30.0
        attempts = 0

        while not self._closed:
            if self._max_retries is not None and attempts >= self._max_retries:
                # Fail all pending futures
                for future in self._pending.values():
                    if not future.done():
                        future.set_exception(AgentPassConnectionError(-1, "Connection lost"))
                self._pending.clear()
                return

            attempts += 1
            try:
                await self._backoff_sleep(delay)
                if self._closed:
                    return
                self._ws = await _open(self.url)
                await self._authenticate()
                self._connected.set()
                # Auto-fetch pending results
                await self._fetch_pending_on_reconnect()
                # Restart reader loop
                self._reader_task = asyncio.create_task(self._read_loop())
                return  # Successfully reconnected
            except (
                OSError,
                websockets.exceptions.WebSocketException,
                AgentPassConnectionError,
            ):
                delay = min(delay * 2, max_delay)

    async def _fetch_pending_on_reconnect(self) -> None:
        """Fetch pending results after reconnection, resolving offline futures."""
        if not self._pending:
            return
        request_id = self._next_id()
        await self._ws.send(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "get_pending_results",
                    "params": {},
                    "id": request_id,
                }
            )
        )
        raw = await self._ws.recv()
        msg = json.loads(raw)
        if "error" not in msg:
            results = msg.get("result", {}).get("results", [])
            self._resolve_offline_results(results)
