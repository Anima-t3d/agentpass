"""Per-agent identities: tokens, agent files, floor, sessions, scoping, migration."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentpass.agents import (
    AgentIdentity,
    AgentRegistry,
    generate_token,
    hash_token,
    load_agents,
    parse_token,
    write_agent_file,
)
from agentpass.config import ConfigError
from agentpass.db import SCHEMA_VERSION, Database
from agentpass.engine import Evaluation, PermissionEngine
from agentpass.executor import Executor
from agentpass.models import Decision
from agentpass.pipeline import Pipeline, RateLimited
from agentpass.server import NOT_AUTHENTICATED, GatewayServer
from tests.fakes import FakeChannel, make_coordinator
from tests.test_server import MockWebSocket, _auth_msg, _cancel_task

# --- tokens ---


def test_token_roundtrip_and_hash_only_in_file(tmp_path):
    token = write_agent_file(tmp_path, "hermes")
    assert parse_token(token) == "hermes"
    text = (tmp_path / "hermes.yaml").read_text()
    assert token not in text and hash_token(token) in text
    registry = load_agents(tmp_path)
    assert registry.authenticate(token).id == "hermes"


def test_write_agent_file_never_overwrites(tmp_path):
    write_agent_file(tmp_path, "hermes")
    with pytest.raises(ConfigError, match="already exists"):
        write_agent_file(tmp_path, "hermes")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        None,
        42,
        "hermes_" + "a" * 43,  # no agp_ prefix
        "agp_hermes",  # no secret
        "agp_hermes_short",  # secret too short
        "agp_Hermes_" + "a" * 43,  # uppercase id
        "agp__" + "a" * 43,  # empty id
        "agp_her mes_" + "a" * 43,
    ],
)
def test_parse_token_rejects_malformed(bad):
    assert parse_token(bad) is None


def test_generate_token_rejects_bad_id():
    with pytest.raises(ConfigError):
        generate_token("Bad_Id")


def test_authenticate_rejects_wrong_secret_and_unknown_id(tmp_path):
    token = write_agent_file(tmp_path, "hermes")
    other = write_agent_file(tmp_path, "paseo-dev")
    registry = load_agents(tmp_path)
    forged = "agp_hermes_" + "x" * 43
    assert registry.authenticate(forged) is None
    assert registry.authenticate("agp_ghost_" + "x" * 43) is None
    assert registry.authenticate(None) is None
    # a valid token for another agent does not authenticate as this one
    assert registry.authenticate(other).id == "paseo-dev"
    assert registry.authenticate(token).id == "hermes"


# --- agent files, extends, floor ---


def _agent_yaml(agent_id, token_hash, body=""):
    return f'id: {agent_id}\ntoken_hash: "sha256:{token_hash}"\n{body}'


def test_floor_deny_cannot_be_overridden_by_agent_allow(tmp_path):
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy" / "_floor.yaml").write_text(
        'rules:\n  - { pattern: "ha_call_service(lock.*)", action: deny }\n'
    )
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "hermes.yaml").write_text(
        _agent_yaml(
            "hermes",
            hash_token("t"),
            'defaults:\n  - { pattern: "*", action: allow }\n'
            'rules:\n  - { pattern: "ha_call_service(lock.*)", action: allow }\n'
            '  - { pattern: "ha_call_service(light.*)", action: allow }\n',
        )
    )
    agent = load_agents(tmp_path / "agents").get("hermes")
    engine = PermissionEngine(agent.permissions)
    assert engine.evaluate(
        "x", {}, signature="ha_call_service(lock.unlock, lock.door)"
    ).decision == (Decision.DENY)
    assert engine.evaluate("x", {}, signature="ha_call_service(light.on, light.a)").decision == (
        Decision.ALLOW
    )


def test_floor_may_only_contain_deny(tmp_path):
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy" / "_floor.yaml").write_text(
        'rules:\n  - { pattern: "*", action: allow }\n'
    )
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "a.yaml").write_text(_agent_yaml("a", hash_token("t")))
    with pytest.raises(ConfigError, match="floor"):
        load_agents(tmp_path / "agents")


def test_extends_merges_rules_and_detects_cycles(tmp_path):
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy" / "readonly.yaml").write_text(
        'defaults:\n  - { pattern: "get_*", action: allow }\n'
        'rules:\n  - { pattern: "delete_*", action: deny }\n'
    )
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "a.yaml").write_text(
        _agent_yaml("a", hash_token("t"), "extends: [readonly]\n")
    )
    perms = load_agents(tmp_path / "agents").get("a").permissions
    engine = PermissionEngine(perms)
    assert engine.evaluate("x", {}, signature="get_x").decision == Decision.ALLOW
    assert engine.evaluate("x", {}, signature="delete_x").decision == Decision.DENY

    (tmp_path / "policy" / "p.yaml").write_text("extends: [q]\n")
    (tmp_path / "policy" / "q.yaml").write_text("extends: [p]\n")
    (tmp_path / "agents" / "a.yaml").write_text(_agent_yaml("a", hash_token("t"), "extends: [p]\n"))
    with pytest.raises(ConfigError, match="Circular"):
        load_agents(tmp_path / "agents")


def test_agent_file_validation(tmp_path):
    (tmp_path / "bad.yaml").write_text(_agent_yaml("bad", hash_token("t"), "surprise: 1\n"))
    with pytest.raises(ConfigError, match="unknown keys"):
        load_agents(tmp_path)
    (tmp_path / "bad.yaml").write_text(_agent_yaml("other", hash_token("t")))
    with pytest.raises(ConfigError, match="file name"):
        load_agents(tmp_path)


# --- pipeline: per-agent limits ---


def _pipeline(**kw):
    engine = MagicMock(spec=PermissionEngine)
    engine.evaluate.return_value = Evaluation(Decision.ASK)
    channel = FakeChannel()
    executor = AsyncMock(spec=Executor)
    executor.execute.return_value = {"ok": True}
    db = AsyncMock(spec=Database)
    coordinator = make_coordinator(db, channel)
    p = Pipeline(engine=engine, executor=executor, coordinator=coordinator, db=db, **kw)
    return p, engine, channel, db


async def test_per_agent_rate_limit():
    p, engine, *_ = _pipeline()
    engine.evaluate.return_value = Evaluation(Decision.ALLOW)
    slow = AgentIdentity(id="slow", requests_per_minute=1)
    fast = AgentIdentity(id="fast", requests_per_minute=5)
    await p.process(slow, "t", {})
    with pytest.raises(RateLimited):
        await p.process(slow, "t", {})
    for _ in range(5):
        await p.process(fast, "t", {})


async def test_per_agent_pending_cap_and_agent_name_in_approval():
    p, _, channel, db = _pipeline(max_pending=10)
    a = AgentIdentity(id="a", name="Agent A", max_pending=1)
    b = AgentIdentity(id="b")
    t1 = asyncio.create_task(p.process(a, "t", {}))
    await asyncio.sleep(0.05)
    with pytest.raises(RateLimited, match="pending"):
        await p.process(a, "t", {})
    t2 = asyncio.create_task(p.process(b, "t", {}))  # b is not affected by a's cap
    await asyncio.sleep(0.05)
    sent = channel.sent
    assert [(r.agent_id, r.agent_name) for r in sent] == [("a", "Agent A"), ("b", "b")]
    assert [c.kwargs["agent_id"] for c in db.insert_pending.call_args_list] == ["a", "b"]
    await p.resolve_all_pending()
    await asyncio.gather(t1, t2, return_exceptions=True)


async def test_identity_engine_is_used():
    p, default_engine, *_ = _pipeline()
    own = MagicMock(spec=PermissionEngine)
    own.evaluate.return_value = Evaluation(Decision.ALLOW)
    await p.process(AgentIdentity(id="a", engine=own), "t", {})
    own.evaluate.assert_called_once()
    default_engine.evaluate.assert_not_called()


# --- database: scoping and migration ---


async def test_get_completed_results_is_agent_scoped(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    await db.initialize()
    for rid, agent in [("r1", "a"), ("r2", "b")]:
        await db.insert_pending(rid, "t", {}, "t", "2999-01-01T00:00:00Z", agent_id=agent)
        await db.update_pending_result(rid, json.dumps({"status": "executed"}))
    assert [r["request_id"] for r in await db.get_completed_results("a")] == ["r1"]
    await db.delete_completed_results(["r1", "r2"], "a")  # cannot delete b's row
    assert [r["request_id"] for r in await db.get_completed_results()] == ["r2"]
    await db.close()


def _make_v0_db(path, with_rows=True):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            request_id TEXT NOT NULL, tool_name TEXT NOT NULL, args TEXT NOT NULL,
            signature TEXT NOT NULL, decision TEXT NOT NULL, resolution TEXT,
            resolved_by TEXT, resolved_at TEXT, execution_result TEXT,
            agent_id TEXT DEFAULT 'default');
        CREATE TABLE pending_requests (
            request_id TEXT PRIMARY KEY, tool_name TEXT NOT NULL, args TEXT NOT NULL,
            signature TEXT NOT NULL, message_id TEXT, chat_id INTEGER, result TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            expires_at TEXT NOT NULL);
        INSERT INTO pending_requests (request_id, tool_name, args, signature, result, expires_at)
            VALUES ('old', 't', '{}', 't', '{"status": "executed"}', '2999-01-01T00:00:00Z');
        """
    )
    conn.commit()
    conn.close()


async def test_migration_from_unversioned_schema(tmp_path):
    path = str(tmp_path / "old.db")
    _make_v0_db(path)
    db = Database(path)
    await db.initialize()
    rows = await db.get_completed_results("default")  # legacy rows belong to "default"
    assert [r["request_id"] for r in rows] == ["old"]
    await db.insert_pending("new", "t", {}, "t", "2999-01-01T00:00:00Z", agent_id="hermes")
    assert (await db.get_pending("new"))["agent_id"] == "hermes"
    await db.close()
    version = sqlite3.connect(path).execute("PRAGMA user_version").fetchone()[0]
    assert version == SCHEMA_VERSION

    db = Database(path)  # idempotent on reopen
    await db.initialize()
    await db.close()


async def test_fresh_db_gets_current_version_and_newer_is_refused(tmp_path):
    path = str(tmp_path / "new.db")
    db = Database(path)
    await db.initialize()
    await db.close()
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError, match="newer"):
        await Database(path).initialize()


# --- server: auth, sessions, scoped pending results ---


def _server(registry=None, **kw):
    engine = MagicMock(spec=PermissionEngine)
    engine.evaluate.return_value = Evaluation(Decision.ALLOW)
    executor = AsyncMock(spec=Executor)
    executor.execute.return_value = {"ok": True}
    db = kw.pop("db", AsyncMock(spec=Database))
    channel = FakeChannel()
    server = GatewayServer(
        agents=registry,
        engine=engine,
        executor=executor,
        coordinator=make_coordinator(db, channel),
        db=db,
        **kw,
    )
    server.channel = channel  # tests answer approvals through it
    return server


def _registry(**limits):
    tokens = {}
    agents = []
    for name in ("hermes", "paseo-dev"):
        token, token_hash = generate_token(name)
        tokens[name] = token
        agents.append(
            AgentIdentity(
                id=name, token_hash=token_hash.removeprefix("sha256:"), **limits.get(name, {})
            )
        )
    return AgentRegistry(agents), tokens


async def test_server_rejects_bad_token_and_accepts_agent_tokens():
    registry, tokens = _registry()
    server = _server(registry)
    bad = MockWebSocket()
    bad.enqueue(_auth_msg("agp_hermes_" + "x" * 43))
    await server.handle_connection(bad)
    assert bad.get_responses()[0]["error"]["code"] == NOT_AUTHENTICATED and bad.closed

    ws = MockWebSocket()
    ws.enqueue(_auth_msg(tokens["hermes"]))
    await server.handle_connection(ws)
    assert ws.get_responses()[0]["result"]["status"] == "authenticated"


async def test_multiple_sessions_per_agent_unless_max_sessions():
    registry, tokens = _registry(**{"paseo-dev": {"max_sessions": 1}})
    server = _server(registry)

    async def connect(name):
        ws = MockWebSocket()
        ws._iter_timeout = 0.5
        ws.enqueue(_auth_msg(tokens[name]))
        return ws, asyncio.create_task(server.handle_connection(ws))

    h1, t1 = await connect("hermes")
    h2, t2 = await connect("hermes")
    p1, t3 = await connect("paseo-dev")
    p2, t4 = await connect("paseo-dev")
    await asyncio.sleep(0.2)
    assert not h1.closed and not h2.closed and not p1.closed  # hermes unlimited
    assert p2.closed and p2.close_code == 4000  # paseo-dev capped at one
    for t in (t1, t2, t3, t4):
        await _cancel_task(t)
    assert server._sessions == {}


async def test_get_pending_results_only_returns_own_rows(tmp_path):
    registry, tokens = _registry()
    db = Database(str(tmp_path / "t.db"))
    await db.initialize()
    for rid, agent in [("for-hermes", "hermes"), ("for-paseo", "paseo-dev")]:
        await db.insert_pending(rid, "t", {}, "t", "2999-01-01T00:00:00Z", agent_id=agent)
        await db.update_pending_result(rid, json.dumps({"status": "executed"}))
    server = _server(registry, db=db)

    ws = MockWebSocket()
    ws.enqueue(_auth_msg(tokens["hermes"]))
    ws.enqueue({"jsonrpc": "2.0", "method": "get_pending_results", "id": "p"})
    await server.handle_connection(ws)
    result = next(r for r in ws.get_responses() if r["id"] == "p")["result"]
    assert [r["request_id"] for r in result["results"]] == ["for-hermes"]
    remaining = [r["request_id"] for r in await db.get_completed_results()]
    assert remaining == ["for-paseo"]
    await db.close()


async def test_audit_and_pending_carry_the_authenticated_agent():
    registry, tokens = _registry()
    server = _server(registry)
    server._engine.evaluate.return_value = Evaluation(Decision.ASK)
    ws = MockWebSocket()
    ws._iter_timeout = 0.5
    ws.enqueue(_auth_msg(tokens["paseo-dev"]))
    ws.enqueue(
        {"jsonrpc": "2.0", "method": "tool_request", "params": {"tool": "t", "args": {}}, "id": 1}
    )
    task = asyncio.create_task(server.handle_connection(ws))
    await asyncio.sleep(0.2)
    entry = server._db.log_audit.call_args[0][0]
    assert entry.agent_id == "paseo-dev"
    (pending,) = server._pending.values()
    assert pending.agent_id == "paseo-dev"
    await server.channel.deny(pending.request.id, "1")
    await asyncio.sleep(0.1)
    await _cancel_task(task)


# --- shared token vs registry are mutually exclusive ---


def test_server_rejects_both_token_and_registry():
    registry, _ = _registry()
    with pytest.raises(ValueError, match="mutually exclusive"):
        _server(registry, agent_token="shared")


async def test_registry_server_does_not_accept_a_shared_token():
    registry, _ = _registry()
    server = _server(registry)
    for presented in ("shared", "default", "agp_default_" + "x" * 43):
        ws = MockWebSocket()
        ws.enqueue(_auth_msg(presented))
        await server.handle_connection(ws)
        assert ws.get_responses()[0]["error"]["code"] == NOT_AUTHENTICATED
    assert server._sessions == {}


async def test_legacy_server_still_accepts_only_the_shared_token():
    server = _server(None, agent_token="shared")
    ok = MockWebSocket()
    ok.enqueue(_auth_msg("shared"))
    await server.handle_connection(ok)
    assert ok.get_responses()[0]["result"]["status"] == "authenticated"
    _, tokens = _registry()
    bad = MockWebSocket()
    bad.enqueue(_auth_msg(tokens["hermes"]))
    await server.handle_connection(bad)
    assert bad.get_responses()[0]["error"]["code"] == NOT_AUTHENTICATED


# --- agent create writes where the gateway reads ---


def test_agent_create_resolves_dir_from_config_not_cwd(tmp_path, monkeypatch, capsys):
    from agentpass.__main__ import main

    cfg_dir = tmp_path / "etc"
    cfg_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    main(["agent", "create", "hermes", "--config", str(cfg_dir / "config.yaml")])
    out = capsys.readouterr().out
    written = cfg_dir / "agents" / "hermes.yaml"
    assert written.is_file()
    assert not (elsewhere / "agents").exists()
    assert f"Created {written.resolve()}" in out
    # the gateway's loader finds the file at the same place
    assert load_agents(cfg_dir / "agents").get("hermes") is not None


def test_agent_create_relative_config_prints_absolute_path(tmp_path, monkeypatch, capsys):
    from agentpass.__main__ import main

    (tmp_path / "conf").mkdir()
    monkeypatch.chdir(tmp_path)
    main(["agent", "create", "paseo-dev", "--config", "conf/config.yaml", "--agents-dir", "who"])
    out = capsys.readouterr().out
    assert f"Created {(tmp_path / 'conf' / 'who' / 'paseo-dev.yaml').resolve()}" in out


# --- migration does not depend on string-splitting the schema ---


async def test_migration_of_half_created_legacy_database(tmp_path):
    path = str(tmp_path / "half.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            request_id TEXT NOT NULL, tool_name TEXT NOT NULL, args TEXT NOT NULL,
            signature TEXT NOT NULL, decision TEXT NOT NULL, resolution TEXT,
            resolved_by TEXT, resolved_at TEXT, execution_result TEXT);
        """
    )
    conn.commit()
    conn.close()
    db = Database(path)
    await db.initialize()
    await db.insert_pending("r", "t", {}, "t", "2999-01-01T00:00:00Z", agent_id="a")
    assert (await db.get_pending("r"))["agent_id"] == "a"
    await db.close()
    cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(audit_log)")}
    assert "agent_id" in cols


# --- agent create follows the config's agents_dir ---


def _create(tmp_path, monkeypatch, capsys, config_text, *extra):
    from agentpass.__main__ import main

    cfg_dir = tmp_path / "etc"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.yaml").write_text(config_text)
    monkeypatch.chdir(tmp_path)
    main(["agent", "create", "hermes", "--config", str(cfg_dir / "config.yaml"), *extra])
    return cfg_dir, capsys.readouterr().out


def test_agent_create_uses_agents_dir_from_config(tmp_path, monkeypatch, capsys):
    cfg_dir, out = _create(
        tmp_path, monkeypatch, capsys, "agent:\n  agents_dir: custom/ids\n  policy_dir: pol\n"
    )
    written = cfg_dir / "custom" / "ids" / "hermes.yaml"
    assert written.is_file() and not (cfg_dir / "agents").exists()
    assert not (cfg_dir / "pol").exists()  # policy_dir untouched
    assert f"Created {written.resolve()} (from config)" in out


def test_agent_create_explicit_agents_dir_overrides_config(tmp_path, monkeypatch, capsys):
    cfg_dir, out = _create(
        tmp_path,
        monkeypatch,
        capsys,
        "agent:\n  agents_dir: custom\n",
        "--agents-dir",
        "explicit",
    )
    assert (cfg_dir / "explicit" / "hermes.yaml").is_file()
    assert not (cfg_dir / "custom").exists()
    assert "(from --agents-dir)" in out


def test_agent_create_legacy_token_config_falls_back_to_default(tmp_path, monkeypatch, capsys):
    cfg_dir, out = _create(tmp_path, monkeypatch, capsys, 'agent:\n  token: "shared"\n')
    assert (cfg_dir / "agents" / "hermes.yaml").is_file()
    assert f"Created {(cfg_dir / 'agents' / 'hermes.yaml').resolve()} (default)" in out


def test_agent_create_missing_config_falls_back_to_default(tmp_path, monkeypatch, capsys):
    from agentpass.__main__ import main

    (tmp_path / "etc").mkdir()
    monkeypatch.chdir(tmp_path)
    main(["agent", "create", "hermes", "--config", str(tmp_path / "etc" / "nope.yaml")])
    assert (tmp_path / "etc" / "agents" / "hermes.yaml").is_file()
    assert "(default)" in capsys.readouterr().out
