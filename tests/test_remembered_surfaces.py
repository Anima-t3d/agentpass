"""Remembered decisions: tool risk table, dashboard, CLI and check-config."""

from __future__ import annotations

import asyncio
import tempfile
import threading
from argparse import Namespace
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agentpass import cli
from agentpass.check import check
from agentpass.config import ConfigError, load_config, load_tools_file
from agentpass.dashboard import build_dashboard_app
from agentpass.db import Database
from agentpass.registry import build_registry
from agentpass.remembered import RememberedService, iso, tool_fingerprint
from tests.test_check import write_setup

ROOT = Path(__file__).resolve().parent.parent
CSRF = {"X-Requested-With": "agentpass"}

# The risk of every Google / Home Assistant tool
RISK_TABLE = {
    "gmail": {
        "gmail_list_messages": "low",
        "gmail_get_message": "low",
        "gmail_list_labels": "low",
        "gmail_send_message": "high",
    },
    "calendar": {
        "calendar_list_calendars": "low",
        "calendar_list_events": "low",
        "calendar_create_event": "medium",
    },
    "homeassistant": {
        "ha_get_state": "low",
        "ha_get_states": "low",
        "ha_get_services": "low",
        "ha_get_history": "low",
        "ha_get_logbook": "low",
        "ha_get_config": "low",
        "ha_render_template": "low",
        # domain/service are arguments, so this cannot be split by domain: high
        "ha_call_service": "high",
        "ha_fire_event": "high",
    },
}


@pytest.mark.parametrize("service", RISK_TABLE)
def test_shipped_tools_have_the_decided_risk(service):
    tools = {t.name: t for t in load_tools_file(str(ROOT / "tools" / f"{service}.yaml"), service)}
    assert {n: t.risk for n, t in tools.items()} == RISK_TABLE[service]


def test_signature_remember_only_where_the_signature_is_the_whole_request():
    for service in RISK_TABLE:
        for tool in load_tools_file(str(ROOT / "tools" / f"{service}.yaml"), service):
            if tool.remember == "signature":
                assert tool.risk == "low", tool.name  # never a write


def test_invalid_remember_mode_is_a_config_error(tmp_path):
    path = tmp_path / "t.yaml"
    path.write_text("tools:\n  t:\n    remember: always\n    request: {method: GET, path: /x}\n")
    with pytest.raises(ConfigError, match="remember"):
        load_tools_file(str(path), "svc")


# --- dashboard ---


@pytest.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "t.db"))
    await database.initialize()
    yield database
    await database.close()


def _rule(**kw):
    return {
        "agent_id": "bot",
        "scope": "tool",
        "tool_name": "gmail_list_messages",
        "signature": None,
        "args_hash": None,
        "pattern": "gmail_list_messages(*)",
        "action": "allow",
        "created_by": "42",
        "created_at": iso(),
        "expires_at": "2099-01-01T00:00:00Z",
        "source_request_id": "r1",
        "tool_fingerprint": "fp",
        **kw,
    }


@pytest.fixture
async def client(db):
    service = RememberedService(db, None)
    async with TestClient(TestServer(build_dashboard_app(db, remembered=service))) as c:
        yield c


async def test_dashboard_lists_with_state_and_expiry(client, db):
    await db.upsert_remembered_rule(_rule())
    await db.upsert_remembered_rule(
        _rule(tool_name="x", pattern="x(*)", expires_at="2020-01-01T00:00:00Z")
    )
    body = await (await client.get("/remembered/api/rules?all=1")).json()
    states = {r["pattern"]: r["state"] for r in body["rules"]}
    assert states == {
        "gmail_list_messages(*)": "inactive",
        "x(*)": "expired",
    }  # no registry: tool gone
    assert all("tool_fingerprint" not in r and "expires_at" in r for r in body["rules"])
    page = await (await client.get("/remembered/?all=1")).text()
    assert "gmail_list_messages(*)" in page and "2099-01-01" in page and "Revoke" in page


async def test_dashboard_revoke_needs_the_csrf_header_and_same_origin(client, db):
    rule_id, _ = await db.upsert_remembered_rule(_rule())
    url = f"/remembered/api/rules/{rule_id}/revoke"
    assert (await client.post(url)).status == 403
    assert (await client.post(url, headers={**CSRF, "Origin": "http://evil.example"})).status == 403
    assert (await db.get_remembered_rule(rule_id))["revoked_at"] is None

    resp = await client.post(url, headers=CSRF)
    assert resp.status == 200
    rule = await db.get_remembered_rule(rule_id)
    assert rule["revoked_at"] and rule["revoked_by"] == "dashboard"
    assert (await client.post(url, headers=CSRF)).status == 404  # already revoked
    assert (await client.post("/remembered/api/rules/abc/revoke", headers=CSRF)).status == 400


async def test_dashboard_has_no_way_to_create_a_rule(client, db):
    for method, path in (
        ("post", "/remembered/api/rules"),
        ("put", "/remembered/api/rules"),
        ("post", "/remembered/"),
    ):
        resp = await getattr(client, method)(path, json=_rule(), headers=CSRF)
        assert resp.status in (404, 405)
    assert await db.list_remembered_rules() == []


async def test_dashboard_without_a_service_has_no_remembered_routes(db):
    async with TestClient(TestServer(build_dashboard_app(db))) as c:
        assert (await c.get("/remembered/")).status == 404


# --- CLI over a real Unix socket ---


class _AdminServer:
    """The dashboard on a Unix socket in its own thread, so the sync CLI can call it."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.sock = tempfile.mkdtemp(prefix="agp") + "/admin.sock"
        self.ready = threading.Event()
        self.stop = None

    def start(self) -> None:
        self.thread = threading.Thread(target=lambda: asyncio.run(self._main()), daemon=True)
        self.thread.start()
        assert self.ready.wait(10)

    async def _main(self) -> None:
        self.db = Database(str(self.tmp / "cli.db"))
        await self.db.initialize()
        self.loop = asyncio.get_running_loop()
        for i in range(3):
            await self.db.upsert_remembered_rule(_rule(tool_name=f"t{i}", pattern=f"t{i}(*)"))
        runner = web.AppRunner(
            build_dashboard_app(self.db, remembered=RememberedService(self.db, None))
        )
        await runner.setup()
        await web.UnixSite(runner, self.sock).start()
        self.stop = asyncio.Event()
        self.ready.set()
        await self.stop.wait()
        await runner.cleanup()
        await self.db.close()

    def shutdown(self) -> None:
        self.loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(10)


@pytest.fixture
def admin(tmp_path):
    server = _AdminServer(tmp_path)
    server.start()
    yield server
    server.shutdown()


def _args(admin, **kw):
    return Namespace(
        socket=admin.sock, config="none.yaml", agent=None, all=False, json=False, ids=[], **kw
    )


def test_cli_list_and_revoke(admin, capsys):
    assert cli.run_remembered(_args(admin, remembered_command="list")) == 0
    out = capsys.readouterr().out  # inactive-by-policy rules are listed: they are still stored
    assert "t0(*)" in out and "t2(*)" in out and "AGENT" in out and "tool removed" in out

    revoke = Namespace(**{**vars(_args(admin, remembered_command="revoke")), "ids": [1, 99]})
    assert cli.run_remembered(revoke) == 1
    out = capsys.readouterr().out
    assert "#1: revoked" in out and "#99: not found" in out

    assert cli.run_remembered(_args(admin, remembered_command="list")) == 0
    assert "t0(*)" not in capsys.readouterr().out  # revoked rules hidden without --all


def test_cli_revoke_all_for_an_agent_and_usage_errors(admin, capsys):
    base = vars(_args(admin, remembered_command="revoke"))
    assert cli.run_remembered(Namespace(**{**base, "all": True, "agent": "bot"})) == 0
    capsys.readouterr()
    assert cli.run_remembered(Namespace(**{**base, "all": False, "agent": None})) == 4
    assert cli.run_remembered(Namespace(**{**base, "all": True, "agent": None})) == 4
    listing = {**vars(_args(admin, remembered_command="list")), "json": True}
    assert cli.run_remembered(Namespace(**listing)) == 0
    assert capsys.readouterr().out.strip().endswith("[]")


def test_cli_reports_an_unreachable_socket(tmp_path, capsys):
    args = Namespace(
        socket=str(tmp_path / "nope.sock"),
        config="x",
        remembered_command="list",
        agent=None,
        all=False,
        json=False,
    )
    assert cli.run_remembered(args) == 3
    assert "cannot reach the admin socket" in capsys.readouterr().err


# --- check-config ---


def _setup_with_db(tmp_path):
    cfg, perms = write_setup(tmp_path)
    text = Path(cfg).read_text().replace("./d.db", str(tmp_path / "d.db"))
    Path(cfg).write_text(text)
    return cfg, perms


def _seed(tmp_path, cfg, rules):
    registry = build_registry(load_config(cfg).services)

    async def go():
        db = Database(str(tmp_path / "d.db"))
        await db.initialize()
        for rule in rules(registry):
            await db.upsert_remembered_rule(rule)
        await db.close()

    asyncio.run(go())


def test_check_config_counts_and_flags_remembered_rules(tmp_path):
    cfg, perms = _setup_with_db(tmp_path)
    assert check(cfg, perms, env={}).summary["remembered rules active"] == 0  # no database yet

    _seed(
        tmp_path,
        cfg,
        lambda reg: [
            _rule(
                tool_name="t_get",
                pattern="t_get(y)",
                scope="exact",
                signature="t_get(y)",
                tool_fingerprint=tool_fingerprint(reg.get_tool("t_get")),
            ),
            # tool scope needs a risk level, which t_get does not have
            _rule(
                tool_name="t_get",
                pattern="t_get(*)",
                tool_fingerprint=tool_fingerprint(reg.get_tool("t_get")),
            ),
            _rule(
                tool_name="t_get",
                pattern="t_get(x)",
                scope="exact",
                signature="t_get(x)",
                tool_fingerprint="stale",
            ),
            _rule(tool_name="gone", pattern="gone(*)"),
        ],
    )
    report = check(cfg, perms, env={})
    assert report.summary["remembered rules active"] == 1
    reasons = {w.where: w.message for w in report.warnings if w.code == "remembered-inactive"}
    assert any("tool changed" in m for m in reasons.values())
    assert any("tool removed" in m for m in reasons.values())
    assert any("no risk level set" in m for m in reasons.values())
    assert report.errors == []


def test_check_config_survives_a_database_without_the_table(tmp_path):
    import sqlite3

    cfg, perms = _setup_with_db(tmp_path)
    conn = sqlite3.connect(tmp_path / "d.db")
    conn.execute("CREATE TABLE audit_log (id INTEGER)")
    conn.commit()
    conn.close()
    assert check(cfg, perms, env={}).summary["remembered rules active"] == 0
