"""Audit dashboard on the admin socket.

Group enforcement against other users (an agent user, nobody) needs root and belongs in
a deployment verification step; here: mode, group (gid), routing, auth and check-config.
"""

from __future__ import annotations

import grp
import os
import stat
import tempfile
import textwrap
from pathlib import Path

import aiohttp
import pytest
from aiohttp import UnixConnector, web
from aiohttp.test_utils import TestClient, TestServer

from agentpass.check import check
from agentpass.config import ConfigError, load_config
from agentpass.dashboard import build_dashboard_app
from agentpass.db import Database
from agentpass.listen import bind_group_socket
from agentpass.models import AuditEntry

ADMIN = "admin-token-for-tests"
AGENT_TOKEN = "agp_hermes_agent-token-for-tests"
SECRET_RESULT = "SECRET-GMAIL-BODY"


def my_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


@pytest.fixture()
def sockdir():
    with tempfile.TemporaryDirectory(prefix="agp") as d:
        yield Path(d)


@pytest.fixture()
async def db(tmp_path):
    database = Database(str(tmp_path / "t.db"))
    await database.initialize()
    await database.log_audit(
        AuditEntry(
            request_id="r1",
            tool_name="gmail_read",
            args={"id": "1"},
            signature="gmail_read, 1",
            decision="allow",
            resolution="executed",
            resolved_by="policy",
            execution_result=SECRET_RESULT,
            agent_id="other",
        )
    )
    yield database
    await database.close()


# --- admin socket: mode, group, serving ---------------------------------------------------


async def test_admin_socket_mode_group_and_dashboard(db, sockdir):
    path = str(sockdir / "run" / "admin.sock")
    sock = bind_group_socket(path, my_group())
    st = os.stat(path)
    assert stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o660
    assert st.st_gid == grp.getgrnam(my_group()).gr_gid == os.getgid()

    runner = web.AppRunner(build_dashboard_app(db))
    await runner.setup()
    try:
        await web.SockSite(runner, sock).start()
        async with aiohttp.ClientSession(connector=UnixConnector(path=path)) as session:
            resp = await session.get("http://x/audit/api/log")
            assert resp.status == 200
            assert (await resp.json())["entries"][0]["execution_result"] == SECRET_RESULT
    finally:
        await runner.cleanup()


# --- TCP opt-in is bearer-protected; the agent token never works ---------------------------


@pytest.fixture()
async def tcp_client(db):
    async with TestClient(TestServer(build_dashboard_app(db, ADMIN))) as c:
        yield c


@pytest.mark.parametrize("path", ["/audit/", "/audit/api/log", "/audit/api/stats"])
async def test_agent_token_and_no_token_are_refused(tcp_client, path):
    assert (await tcp_client.get(path)).status == 401
    for header in (f"Bearer {AGENT_TOKEN}", "Bearer ", "Basic abc", ADMIN):
        resp = await tcp_client.get(path, headers={"Authorization": header})
        assert resp.status == 401
        assert SECRET_RESULT not in await resp.text()


@pytest.mark.parametrize("path", ["/audit/", "/audit/api/log", "/audit/api/stats"])
async def test_admin_token_is_accepted(tcp_client, path):
    resp = await tcp_client.get(path, headers={"Authorization": f"Bearer {ADMIN}"})
    assert resp.status == 200


def test_empty_admin_token_is_refused_at_build(db):
    with pytest.raises(ValueError):
        build_dashboard_app(db, "")


# --- healthz carries no audit data ---------------------------------------------------------


async def test_healthz_app_has_no_audit_routes():
    # __main__ builds the health app with /healthz only; mirror it and probe the audit paths
    app = web.Application()

    async def healthz(request):
        return web.json_response({"status": "healthy"})

    app.router.add_get("/healthz", healthz)
    async with TestClient(TestServer(app)) as c:
        body = await (await c.get("/healthz")).text()
        assert "execution_result" not in body and "entries" not in body
        for p in ("/audit/", "/audit/api/log", "/audit/api/stats"):
            assert (await c.get(p)).status == 404


def test_main_does_not_mount_dashboard_on_the_health_app():
    src = (Path(__file__).parents[1] / "src" / "agentpass" / "__main__.py").read_text()
    assert "setup_dashboard" not in src


# --- config defaults -----------------------------------------------------------------------


def write(tmp_path, gateway="{}", listen="", extra=""):
    (tmp_path / "tools.yaml").write_text("tools: {}\n")
    (tmp_path / "gateway.yaml").write_text(
        textwrap.dedent(
            f"""\
            gateway: {gateway}
            {listen}
            agent: {{token: tok}}
            messenger: {{type: telegram, telegram: {{token: t, chat_id: 1, allowed_users: [1]}}}}
            services:
              svc: {{url: "http://localhost", auth: {{type: bearer, token: t}}, tools: tools.yaml}}
            storage: {{type: sqlite, path: ./d.db}}
            """
        )
    )
    (tmp_path / "permissions.yaml").write_text("defaults: []\nrules: []\n")
    return str(tmp_path / "gateway.yaml"), str(tmp_path / "permissions.yaml")


def test_defaults_no_tcp_dashboard_no_health_port(tmp_path):
    cfg = load_config(write(tmp_path, listen="listen: {}")[0])
    assert cfg.listen.admin_socket == "/run/agentpass/admin.sock"
    assert cfg.listen.admin_group == "agentpass-admin"
    assert cfg.listen.dashboard_tcp is None
    assert cfg.gateway.health_port is None


def test_dashboard_tcp_must_be_loopback(tmp_path):
    listen = "listen: {dashboard_tcp: {host: 0.0.0.0, port: 8207, admin_token: x}}"
    with pytest.raises(ConfigError, match="loopback"):
        load_config(write(tmp_path, listen=listen)[0])


# --- check-config --------------------------------------------------------------------------


def run_check(tmp_path, gateway="{}", dash=""):
    g = my_group()
    listen = f"listen: {{group: {g}, admin_group: {g}{dash}}}"
    cfg, perms = write(tmp_path, gateway, listen)
    return check(cfg, perms, env={})


def test_check_clean_without_health_port(tmp_path):
    report = run_check(tmp_path)
    assert report.errors == [] and report.warnings == []


@pytest.mark.parametrize("port", [8080, 8084, 3306])
def test_check_errors_on_reserved_health_port(tmp_path, port):
    gateway = f"{{health_port: {port}, reserved_ports: [8080, 8084, 3306]}}"
    report = run_check(tmp_path, gateway=gateway)
    assert "reserved-port" in [f.code for f in report.errors]


def test_check_no_reserved_ports_by_default(tmp_path):
    assert run_check(tmp_path, gateway="{health_port: 8080}").errors == []


def test_check_errors_on_reserved_dashboard_port(tmp_path):
    dash = ", dashboard_tcp: {port: 8207, admin_token: abcdef123}"
    report = run_check(tmp_path, gateway="{reserved_ports: [8207]}", dash=dash)
    assert "reserved-port" in [f.code for f in report.errors]


@pytest.mark.parametrize("bad", ["[0]", "[70000]", "[8080, x]", "8080", "[true]"])
def test_reserved_ports_validated(tmp_path, bad):
    with pytest.raises(ConfigError, match="reserved_ports"):
        load_config(write(tmp_path, f"{{reserved_ports: {bad}}}", "listen: {}")[0])


def test_check_accepts_free_health_port(tmp_path):
    assert run_check(tmp_path, gateway="{health_port: 8210}").errors == []


def test_check_errors_on_tcp_dashboard_without_auth(tmp_path):
    report = run_check(tmp_path, dash=", dashboard_tcp: {port: 8207}")
    assert "dashboard-tcp-no-auth" in [f.code for f in report.errors]
    assert "dashboard-tcp" in [f.code for f in report.warnings]


def test_check_warns_on_tcp_dashboard_even_with_auth(tmp_path):
    report = run_check(tmp_path, dash=", dashboard_tcp: {port: 8207, admin_token: abcdef123}")
    assert report.errors == []
    assert "dashboard-tcp" in [f.code for f in report.warnings]
