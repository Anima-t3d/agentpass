"""Response bodies that arrive in several network chunks are read in full."""

from __future__ import annotations

import asyncio
import json
import textwrap

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from agentpass.config import AuthConfig, ServiceConfig, load_tools_file
from agentpass.services.http import GenericHTTPService, HTTPServiceError

# Larger than one read of the stream buffer, like a 40 kB file from GitHub's contents API
BODY = json.dumps({"content": "x" * 200_000, "encoding": "base64"}).encode()


async def _chunked(request: web.Request) -> web.StreamResponse:
    resp = web.StreamResponse(headers={"Content-Type": "application/json"})
    await resp.prepare(request)
    for i in range(0, len(BODY), 4096):
        await resp.write(BODY[i : i + 4096])
        await asyncio.sleep(0)  # let each piece reach the client on its own
    await resp.write_eof()
    return resp


@pytest.fixture
async def server():
    app = web.Application()
    app.router.add_get("/x", _chunked)
    srv = TestServer(app)
    await srv.start_server()
    yield srv
    await srv.close()


def _service(tmp_path, url: str, max_bytes: int) -> GenericHTTPService:
    path = tmp_path / "tools.yaml"
    path.write_text(
        textwrap.dedent(
            f"""
            tools:
              t:
                request: {{ method: GET, path: /x }}
                response: {{ max_bytes: {max_bytes} }}
            """
        )
    )
    tools = load_tools_file(str(path), "svc")
    cfg = ServiceConfig(name="svc", url=url, auth=AuthConfig(type="bearer", token="x"), tools=tools)
    return GenericHTTPService(cfg)


async def test_a_call_reads_a_chunked_body_in_full(tmp_path, server):
    svc = _service(tmp_path, str(server.make_url("")).rstrip("/"), 1_048_576)
    try:
        out = await svc.execute("t", {})
    finally:
        await svc.close()
    assert out["content"] == "x" * 200_000


async def test_a_chunked_body_over_the_cap_is_too_large(tmp_path, server):
    svc = _service(tmp_path, str(server.make_url("")).rstrip("/"), 100_000)
    try:
        with pytest.raises(HTTPServiceError, match="too large"):
            await svc.execute("t", {})
    finally:
        await svc.close()


async def test_a_preview_lookup_reads_a_chunked_body_in_full(tmp_path, server):
    svc = _service(tmp_path, str(server.make_url("")).rstrip("/"), 1_048_576)
    try:
        out = await svc.lookup("/x", {}, max_bytes=1_048_576, timeout=5)
    finally:
        await svc.close()
    assert out["content"] == "x" * 200_000
