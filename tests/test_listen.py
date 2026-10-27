"""Unix socket listener: config, socket creation, round trip, TCP, check-config.

The group boundary itself (a user outside agentpass-clients being refused) cannot be
exercised without root: it needs a second user and a group they are not in. What is proven
here is everything on this side of it: the socket is created 0660, the configured group is
applied with chown (and a group the service user is not in is refused, fail closed), stale
sockets go, and the kernel enforces the mode bits at connect.
"""

from __future__ import annotations

import grp
import json
import os
import stat
import tempfile
import textwrap
from argparse import Namespace
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import UnixConnector, web
from websockets.asyncio.server import serve as ws_serve
from websockets.asyncio.server import unix_serve

from agentpass.__main__ import parse_args
from agentpass.approval import ApprovalCoordinator
from agentpass.check import check
from agentpass.cli import gateway_url
from agentpass.client import AgentPassClient, AgentPassDenied, socket_url
from agentpass.config import ConfigError, load_config
from agentpass.db import Database
from agentpass.engine import Evaluation, PermissionEngine
from agentpass.executor import Executor
from agentpass.listen import SocketSetupError, bind_group_socket, remove_socket
from agentpass.mcp import McpServer
from agentpass.models import Decision
from agentpass.server import GatewayServer

TOKEN = "listen-test-token"


@pytest.fixture()
def sockdir():
    # AF_UNIX paths are limited to ~108 bytes; pytest's tmp_path can exceed that
    with tempfile.TemporaryDirectory(prefix="agp") as d:
        yield Path(d)


def my_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


def foreign_group() -> str | None:
    """A group the current user is not a member of, or None (root can chown anything)."""
    mine = {os.getgid(), *os.getgroups()}
    for g in grp.getgrall():
        if g.gr_gid not in mine:
            return g.gr_name
    return None


def make_gateway() -> GatewayServer:
    engine = MagicMock(spec=PermissionEngine)
    engine.evaluate.return_value = Evaluation(Decision.ALLOW)
    executor = AsyncMock(spec=Executor)
    executor.execute.return_value = {"brightness": 100}
    return GatewayServer(
        agent_token=TOKEN,
        engine=engine,
        executor=executor,
        coordinator=ApprovalCoordinator(AsyncMock(spec=Database), []),
        db=AsyncMock(spec=Database),
    )


# --- Config ------------------------------------------------------------------------------


def write_config(tmp_path, gateway: str, listen: str = "") -> str:
    (tmp_path / "tools.yaml").write_text("tools: {}\n")
    text = f"""\
gateway:
{textwrap.indent(gateway, "  ")}
{listen}
agent: {{token: tok}}
messenger: {{type: telegram, telegram: {{token: t, chat_id: 1, allowed_users: [1]}}}}
services:
  svc: {{url: "http://localhost", auth: {{type: bearer, token: t}}, tools: tools.yaml}}
storage: {{type: sqlite, path: ./d.db}}
"""
    (tmp_path / "gateway.yaml").write_text(text)
    return str(tmp_path / "gateway.yaml")


def test_listen_defaults_to_the_service_socket(tmp_path):
    cfg = load_config(write_config(tmp_path, "health_port: 8210", "listen: {}"))
    assert cfg.listen.socket == "/run/agentpass/agent.sock"
    assert cfg.listen.group == "agentpass-clients"
    assert cfg.listen.tcp is None


def test_socket_plus_loopback_tcp(tmp_path):
    listen = "listen:\n  tcp: {host: 127.0.0.1, port: 8205}"
    cfg = load_config(write_config(tmp_path, "health_port: 8210", listen))
    assert cfg.listen.socket and cfg.listen.tcp.port == 8205


@pytest.mark.parametrize("host", ["0.0.0.0", "'::'", "''", "'0:0:0:0:0:0:0:0'"])
def test_wildcard_tcp_is_refused(tmp_path, host):
    listen = f"listen:\n  tcp: {{host: {host}, port: 8205}}"
    with pytest.raises(ConfigError, match="allow_wildcard"):
        load_config(write_config(tmp_path, "health_port: 8210", listen))


def test_wildcard_needs_explicit_opt_in(tmp_path):
    listen = "listen:\n  tcp: {host: 0.0.0.0, port: 8205, allow_wildcard: true}"
    cfg = load_config(write_config(tmp_path, "health_port: 8210", listen))
    assert cfg.listen.tcp.allow_wildcard


def test_legacy_gateway_wildcard_is_refused_too(tmp_path):
    with pytest.raises(ConfigError, match="allow_wildcard"):
        load_config(write_config(tmp_path, "host: 0.0.0.0\nport: 8443"))
    cfg = load_config(write_config(tmp_path, "host: 127.0.0.1\nport: 8443"))
    assert cfg.listen.socket is None and cfg.listen.tcp.port == 8443  # legacy: TCP only


@pytest.mark.parametrize(
    ("listen", "match"),
    [
        ("listen: {socket: null}", "socket or a tcp"),
        ("listen: {socket: relative.sock}", "absolute"),
        ("listen: {bogus: 1}", "unknown listen key"),
        ("listen: {tcp: {host: 127.0.0.1}}", "port"),
    ],
)
def test_bad_listen_blocks(tmp_path, listen, match):
    with pytest.raises(ConfigError, match=match):
        load_config(write_config(tmp_path, "health_port: 8210", listen))


# --- Socket creation ---------------------------------------------------------------------


def test_socket_is_created_0660_with_the_configured_group(sockdir):
    path = str(sockdir / "run" / "agent.sock")  # parent is created when missing
    sock = bind_group_socket(path, my_group())
    try:
        st = os.stat(path)
        assert stat.S_ISSOCK(st.st_mode)
        assert stat.S_IMODE(st.st_mode) == 0o660
        assert st.st_gid == os.getgid()
    finally:
        sock.close()


def test_group_the_service_user_is_not_in_is_refused(sockdir):
    group = foreign_group()
    if group is None or os.geteuid() == 0:
        pytest.skip("needs a non-root user and a group they are not a member of")
    path = str(sockdir / "agent.sock")
    with pytest.raises(SocketSetupError, match="must be a member"):
        bind_group_socket(path, group)
    assert not os.path.exists(path)  # fail closed: no socket left behind


def test_unknown_group_is_refused(sockdir):
    with pytest.raises(SocketSetupError, match="does not exist"):
        bind_group_socket(str(sockdir / "agent.sock"), "no-such-group-agentpass")


def test_stale_socket_is_removed_on_start(sockdir):
    path = str(sockdir / "agent.sock")
    bind_group_socket(path, my_group()).close()  # leaves the file behind, nobody listening
    assert os.path.exists(path)
    bind_group_socket(path, my_group()).close()  # no "address in use"


def test_live_socket_and_regular_files_are_never_removed(sockdir):
    path = str(sockdir / "agent.sock")
    first = bind_group_socket(path, my_group())
    first.listen()
    try:
        with pytest.raises(SocketSetupError, match="already in use"):
            bind_group_socket(path, my_group())
    finally:
        first.close()
    other = sockdir / "notasocket"
    other.write_text("keep me")
    with pytest.raises(SocketSetupError, match="not a socket"):
        bind_group_socket(str(other), my_group())
    assert other.read_text() == "keep me"


def test_remove_socket_is_quiet_when_missing(sockdir):
    remove_socket(str(sockdir / "gone.sock"))


# --- Round trip, both transports through one handler -------------------------------------


async def test_socket_round_trip_without_tls_or_insecure(sockdir):
    path = str(sockdir / "agent.sock")
    server = make_gateway()
    sock = bind_group_socket(path, my_group())
    async with unix_serve(server.handle_connection, sock=sock):
        async with AgentPassClient(socket_url(path), TOKEN, max_retries=0) as client:
            result = await client.tool_request("ha_get_state", entity_id="sensor.t")
        assert result == {"brightness": 100}
        with pytest.raises(Exception, match=r"(?i)auth|token|invalid"):
            async with AgentPassClient(socket_url(path), "wrong-token", max_retries=0):
                pass


async def test_kernel_enforces_the_mode_at_connect(sockdir):
    """NOT the group boundary (needs root): owner bits stripped means connect is refused."""
    if os.geteuid() == 0:
        pytest.skip("root bypasses socket permissions")
    path = str(sockdir / "agent.sock")
    server = make_gateway()
    sock = bind_group_socket(path, my_group())
    async with unix_serve(server.handle_connection, sock=sock):
        os.chmod(path, 0o000)
        with pytest.raises(PermissionError):
            async with AgentPassClient(socket_url(path), TOKEN, max_retries=0):
                pass
        os.chmod(path, 0o660)
        async with AgentPassClient(socket_url(path), TOKEN, max_retries=0):
            pass


async def test_tcp_still_works_alongside_the_socket(sockdir):
    path = str(sockdir / "agent.sock")
    server = make_gateway()
    sock = bind_group_socket(path, my_group())
    async with (
        unix_serve(server.handle_connection, sock=sock),
        ws_serve(server.handle_connection, "127.0.0.1", 0) as tcp,
    ):
        port = tcp.sockets[0].getsockname()[1]
        for url in (f"ws://127.0.0.1:{port}", socket_url(path)):
            async with AgentPassClient(url, TOKEN, max_retries=0) as client:
                assert await client.tool_request("ha_get_state") == {"brightness": 100}


async def test_denied_over_the_socket_is_a_normal_denial(sockdir):
    path = str(sockdir / "agent.sock")
    server = make_gateway()
    server._engine.evaluate.return_value = Evaluation(Decision.DENY)
    sock = bind_group_socket(path, my_group())
    async with (
        unix_serve(server.handle_connection, sock=sock),
        AgentPassClient(socket_url(path), TOKEN, max_retries=0) as client,
    ):
        with pytest.raises(AgentPassDenied):
            await client.tool_request("ha_get_state")


async def test_mcp_frontend_over_a_group_socket(sockdir):
    path = str(sockdir / "mcp.sock")
    mcp = McpServer(
        pipeline=MagicMock(),
        agents=MagicMock(authenticate=MagicMock(return_value=None)),
        registry=MagicMock(),
        db=MagicMock(),
    )
    runner = web.AppRunner(mcp.build_app())
    await runner.setup()
    await web.SockSite(runner, bind_group_socket(path, my_group())).start()
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o660
        async with UnixConnector(path=path) as conn:
            import aiohttp

            async with aiohttp.ClientSession(connector=conn) as http:
                resp = await http.post(
                    "http://gateway/mcp",
                    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
                    headers={"Authorization": "Bearer agp_nobody_wrongwrongwrongwrong"},
                )
                assert resp.status == 401  # reached the MCP app, which refused the token
    finally:
        await runner.cleanup()


# --- Client / CLI ------------------------------------------------------------------------


def test_socket_flag_builds_a_unix_url():
    ns = Namespace(url="ws://x:1", socket="/run/agentpass/agent.sock")
    assert gateway_url(ns) == "unix:///run/agentpass/agent.sock"
    assert gateway_url(Namespace(url="ws://x:1", socket="")) == "ws://x:1"
    assert gateway_url(Namespace(url="ws://x:1")) == "ws://x:1"


@pytest.mark.parametrize("cmd", ["request", "tools", "pending"])
def test_socket_flag_is_accepted_by_client_commands(cmd):
    argv = [cmd, *(["ha_get_state"] if cmd == "request" else []), "--socket", "/s.sock"]
    assert parse_args(argv).socket == "/s.sock"


async def test_relative_unix_url_is_rejected():
    with pytest.raises(OSError, match="absolute"):
        await AgentPassClient("unix://relative.sock", TOKEN, max_retries=0).connect()


# --- check-config ------------------------------------------------------------------------


def run_check(tmp_path, gateway: str, listen: str):
    cfg = write_config(tmp_path, gateway, listen)
    perms = tmp_path / "permissions.yaml"
    perms.write_text("defaults: []\nrules: []\n")
    return check(cfg, str(perms), env={})


def test_check_warns_on_tcp_without_socket(tmp_path):
    report = run_check(
        tmp_path, "health_port: 8210", "listen: {socket: null, tcp: {host: 127.0.0.1, port: 8205}}"
    )
    assert "tcp-without-socket" in [f.code for f in report.warnings]


def test_check_reports_the_wildcard_refusal(tmp_path):
    report = run_check(tmp_path, "health_port: 8210", "listen: {tcp: {host: 0.0.0.0, port: 8205}}")
    assert any("allow_wildcard" in f.message for f in report.errors)


def test_check_warns_when_wildcard_is_allowed_and_when_group_is_missing(tmp_path):
    listen = (
        "listen: {group: no-such-group-agentpass, "
        "tcp: {host: 0.0.0.0, port: 8205, allow_wildcard: true}}"
    )
    report = run_check(tmp_path, "health_port: 8210", listen)
    codes = [f.code for f in report.warnings]
    assert "wildcard-listen" in codes and "listen-group-missing" in codes


def test_check_is_quiet_for_the_socket_default(tmp_path):
    report = run_check(
        tmp_path, "health_port: 8210", f"listen: {{group: {my_group()}, admin_group: {my_group()}}}"
    )
    assert report.errors == [] and report.warnings == []
