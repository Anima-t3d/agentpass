"""Approval coordinator: fan-out, DB-arbitrated first answer, timeout, restart, require."""

from __future__ import annotations

import asyncio
import sqlite3
import time

import pytest

from agentpass.approval import (
    Answer,
    AnswerStatus,
    ApprovalCoordinator,
    ApprovalReason,
    ApprovalRequest,
    NoChannelError,
)
from agentpass.db import SCHEMA_VERSION, Database
from tests.fakes import FakeChannel


@pytest.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "approval.db"))
    await database.initialize()
    yield database
    await database.close()


def _req(approval_id="r1", ttl=60.0, require="any_trusted", **kw) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=approval_id,
        agent_id="agent",
        tool="ha_call_service",
        signature="ha_call_service(light.turn_on)",
        args={"entity_id": "light.bedroom"},
        expires_at=time.time() + ttl,
        require=require,
        **kw,
    )


async def _state(db, approval_id) -> str | None:
    row = await db.get_pending(approval_id)
    return row["state"] if row else None


async def _started(db, *channels) -> ApprovalCoordinator:
    coordinator = ApprovalCoordinator(db, list(channels))
    await coordinator.start()
    return coordinator


async def _wait_sent(*channels) -> None:
    for _ in range(200):
        if all(c.sent for c in channels):
            return
        await asyncio.sleep(0.01)
    raise AssertionError("request never reached the channels")


# --- fan-out and finalize ---


async def test_fans_out_to_every_channel_and_finalizes_all(db):
    a, b = FakeChannel("a"), FakeChannel("b")
    coordinator = await _started(db, a, b)
    seen = []
    task = asyncio.create_task(
        coordinator.request(_req(), on_pending=lambda i, e: seen.append((i, e)))
    )
    await _wait_sent(a, b)
    assert a.last_request.approval_id == b.last_request.approval_id == "r1"
    assert await _state(db, "r1") == "pending"

    assert await b.approve("r1", "owner") is AnswerStatus.ACCEPTED
    outcome = await task

    assert outcome.approved and outcome.reason is ApprovalReason.APPROVED
    assert (outcome.channel, outcome.approver_id) == ("b", "owner")
    assert seen and seen[0][0] == "r1"
    assert await _state(db, "r1") == "resolved"
    for channel in (a, b):  # the answering channel too: every message gets edited
        [(handle, final)] = channel.finalized
        assert handle.channel == channel.name and final is outcome


async def test_deny_resolves_denied(db):
    ch = FakeChannel()
    coordinator = await _started(db, ch)
    task = asyncio.create_task(coordinator.request(_req()))
    await _wait_sent(ch)
    await ch.deny("r1")
    outcome = await task
    assert not outcome.approved and outcome.reason is ApprovalReason.DENIED


async def test_restricts_fan_out_to_named_channels(db):
    a, b = FakeChannel("a"), FakeChannel("b")
    coordinator = await _started(db, a, b)
    task = asyncio.create_task(coordinator.request(_req(), channels=["b"]))
    await _wait_sent(b)
    await b.approve("r1")
    await task
    assert a.sent == [] and a.finalized == []


# --- first answer wins, in the DB ---


async def test_concurrent_double_answer_has_one_winner(db):
    a, b = FakeChannel("a"), FakeChannel("b")
    coordinator = await _started(db, a, b)
    task = asyncio.create_task(coordinator.request(_req()))
    await _wait_sent(a, b)

    statuses = await asyncio.gather(a.approve("r1", "one"), b.deny("r1", "two"))
    outcome = await task

    assert sorted(statuses) == [AnswerStatus.ACCEPTED, AnswerStatus.ALREADY_RESOLVED]
    winner = a if statuses[0] is AnswerStatus.ACCEPTED else b
    assert outcome.channel == winner.name
    assert outcome.approved == (winner is a)
    assert await _state(db, "r1") == "resolved"
    # a third, later answer is ignored too
    assert await a.approve("r1") is AnswerStatus.ALREADY_RESOLVED


async def test_db_arbitrates_not_memory(db):
    """If the row is no longer pending, an in-memory waiter cannot be resolved by an answer."""
    ch = FakeChannel()
    coordinator = await _started(db, ch)
    task = asyncio.create_task(coordinator.request(_req(ttl=0.3)))
    await _wait_sent(ch)
    assert await db.transition_pending("r1", "resolved")  # someone else won in the DB
    assert await ch.approve("r1") is AnswerStatus.ALREADY_RESOLVED
    outcome = await task  # nobody could resolve it in memory: it times out
    assert outcome.reason is ApprovalReason.TIMEOUT


async def test_answer_for_unknown_request_is_already_resolved(db):
    ch = FakeChannel()
    await _started(db, ch)
    assert await ch.approve("nope") is AnswerStatus.ALREADY_RESOLVED


# --- failing and missing channels ---


async def test_one_failing_channel_does_not_fail_the_request(db):
    good, bad = FakeChannel("good"), FakeChannel("bad")
    bad.send_error = RuntimeError("telegram down")
    coordinator = await _started(db, bad, good)
    task = asyncio.create_task(coordinator.request(_req()))
    await _wait_sent(good)
    await good.approve("r1")
    outcome = await task
    assert outcome.approved
    assert bad.finalized == [] and len(good.finalized) == 1


async def test_no_channel_configured(db):
    coordinator = await _started(db)
    with pytest.raises(NoChannelError):
        await coordinator.request(_req())
    assert await db.get_pending("r1") is None


async def test_every_channel_failing_deletes_the_row(db):
    a, b = FakeChannel("a"), FakeChannel("b")
    a.send_error = b.send_error = RuntimeError("down")
    coordinator = await _started(db, a, b)
    with pytest.raises(NoChannelError):
        await coordinator.request(_req())
    assert await db.get_pending("r1") is None


async def test_channel_that_failed_to_start_is_not_used(db):
    bad, good = FakeChannel("bad"), FakeChannel("good")

    async def boom(sink):
        raise RuntimeError("no network")

    bad.start = boom
    coordinator = await _started(db, bad, good)
    assert await coordinator.health_check() == {"bad": False, "good": True}
    task = asyncio.create_task(coordinator.request(_req()))
    await _wait_sent(good)
    assert bad.sent == []
    await good.approve("r1")
    await task


async def test_only_notify_channels_accepting_is_no_channel(db):
    """Nobody who could approve got the request: fail now, don't wait for the timeout."""
    notify = FakeChannel("paseo", trust="notify")
    coordinator = await _started(db, notify)
    with pytest.raises(NoChannelError):
        await coordinator.request(_req())
    assert await db.get_pending("r1") is None
    [(_, outcome)] = notify.finalized  # the notification it did show gets closed
    assert outcome.reason is ApprovalReason.NO_CHANNEL


# --- timeout ---


async def test_timeout_is_owned_by_the_coordinator(db):
    ch = FakeChannel()
    coordinator = await _started(db, ch)
    outcome = await coordinator.request(_req(ttl=0.05))
    assert not outcome.approved
    assert outcome.reason is ApprovalReason.TIMEOUT and outcome.approver_id == "gateway"
    assert await _state(db, "r1") == "resolved"
    [(_, final)] = ch.finalized
    assert final.reason is ApprovalReason.TIMEOUT
    assert await ch.approve("r1") is AnswerStatus.ALREADY_RESOLVED  # late tap


async def test_answer_racing_the_timeout_wins_if_the_db_says_so(db):
    ch = FakeChannel()
    coordinator = await _started(db, ch)
    task = asyncio.create_task(coordinator.request(_req(ttl=0.2)))
    await _wait_sent(ch)
    await ch.approve("r1")
    outcome = await task
    assert outcome.reason is ApprovalReason.APPROVED


# --- shutdown and restart ---


async def test_resolve_all_denies_open_requests_as_shutdown(db):
    a, b = FakeChannel("a"), FakeChannel("b")
    coordinator = await _started(db, a, b)
    tasks = [asyncio.create_task(coordinator.request(_req(f"r{i}"))) for i in range(2)]
    await asyncio.sleep(0.1)
    await coordinator.resolve_all()
    outcomes = await asyncio.gather(*tasks)
    assert {o.reason for o in outcomes} == {ApprovalReason.GATEWAY_SHUTDOWN}
    assert len(a.finalized) == len(b.finalized) == 2


async def test_start_abandons_leftover_pending_rows_and_finalizes_them(db):
    first = FakeChannel()
    old = await _started(db, first)
    task = asyncio.create_task(old.request(_req("left-over")))
    await _wait_sent(first)
    # the process dies here: a new one opens the same database
    second = FakeChannel()
    new = await _started(db, second)

    assert await _state(db, "left-over") == "abandoned"
    [(handle, outcome)] = second.finalized
    assert handle.ref == {"message_id": 1}  # the persisted handle, not in-memory state
    assert outcome.reason is ApprovalReason.RESTART and not outcome.approved
    # a tap on the old message after the restart is "already resolved"
    assert await second.approve("left-over") is AnswerStatus.ALREADY_RESOLVED
    assert await new.health_check() == {"telegram": True}
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_start_leaves_resolved_rows_alone(db):
    ch = FakeChannel()
    coordinator = await _started(db, ch)
    task = asyncio.create_task(coordinator.request(_req()))
    await _wait_sent(ch)
    await ch.approve("r1")
    await task
    again = FakeChannel()
    await _started(db, again)
    assert again.finalized == [] and await _state(db, "r1") == "resolved"


async def test_cancelled_request_abandons_its_row(db):
    ch = FakeChannel()
    coordinator = await _started(db, ch)
    task = asyncio.create_task(coordinator.request(_req()))
    await _wait_sent(ch)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await _state(db, "r1") == "abandoned"
    assert await ch.approve("r1") is AnswerStatus.ALREADY_RESOLVED


# --- rule-level require ---


async def test_notify_channel_cannot_resolve(db):
    notify = FakeChannel("paseo", trust="notify")
    trusted = FakeChannel("telegram")
    coordinator = await _started(db, notify, trusted)
    task = asyncio.create_task(coordinator.request(_req()))
    await _wait_sent(notify, trusted)

    assert await notify.approve("r1") is AnswerStatus.REJECTED
    assert await notify.deny("r1") is AnswerStatus.REJECTED
    assert not task.done() and await _state(db, "r1") == "pending"

    assert await trusted.approve("r1") is AnswerStatus.ACCEPTED
    assert (await task).channel == "telegram"


async def test_require_telegram_needs_a_telegram_proof_channel(db):
    other = FakeChannel("other", proof_kinds={"something_else"})
    tg = FakeChannel("telegram")
    coordinator = await _started(db, other, tg)
    task = asyncio.create_task(coordinator.request(_req(require="telegram")))
    await _wait_sent(other, tg)
    assert await other.approve("r1") is AnswerStatus.REJECTED
    assert await tg.approve("r1") is AnswerStatus.ACCEPTED
    await task


async def test_require_passkey_is_never_satisfied_by_telegram(db):
    tg = FakeChannel("telegram")
    coordinator = await _started(db, tg)
    # no channel could ever satisfy it: fail now rather than time out
    with pytest.raises(NoChannelError):
        await coordinator.request(_req(require="passkey"))


async def test_require_passkey_works_once_a_webauthn_channel_exists(db):
    tg = FakeChannel("telegram")
    pk = FakeChannel("passkey", proof_kinds={"webauthn"})
    coordinator = await _started(db, tg, pk)
    task = asyncio.create_task(coordinator.request(_req(require="passkey")))
    await _wait_sent(tg, pk)

    assert await tg.approve("r1") is AnswerStatus.REJECTED
    assert await pk.answer("r1", True) is AnswerStatus.REJECTED  # no assertion attached
    assert not task.done()
    assert await pk.answer("r1", True, proof={"assertion": "..."}) is AnswerStatus.ACCEPTED
    outcome = await task
    assert outcome.approved and outcome.channel == "passkey"


async def test_denial_from_a_trusted_channel_always_counts(db):
    tg = FakeChannel("telegram")
    pk = FakeChannel("passkey", proof_kinds={"webauthn"})
    coordinator = await _started(db, tg, pk)
    task = asyncio.create_task(coordinator.request(_req(require="passkey")))
    await _wait_sent(tg, pk)
    assert await tg.deny("r1") is AnswerStatus.ACCEPTED  # denying is always safe
    assert not (await task).approved


async def test_sink_ignores_answers_naming_an_unknown_channel(db):
    ch = FakeChannel()
    coordinator = await _started(db, ch)
    task = asyncio.create_task(coordinator.request(_req(ttl=0.2)))
    await _wait_sent(ch)
    status = await coordinator.answer("r1", Answer(True, "forged", "agent"))
    assert status is AnswerStatus.REJECTED
    assert (await task).reason is ApprovalReason.TIMEOUT


def test_duplicate_channel_names_are_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        ApprovalCoordinator(None, [FakeChannel("x"), FakeChannel("x")])


async def test_notify_reaches_channels_that_support_it(db):
    class Notifying(FakeChannel):
        texts: list

        async def notify(self, text):
            self.texts.append(text)

    ch = Notifying()
    ch.texts = []
    broken = Notifying("broken")
    broken.texts = []

    async def fail(text):
        raise RuntimeError("x")

    broken.notify = fail
    coordinator = await _started(db, broken, ch)
    await coordinator.notify("consent needed")
    assert ch.texts == ["consent needed"]


# --- schema ---


async def test_v2_database_migrates_to_current(tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            request_id TEXT NOT NULL, tool_name TEXT NOT NULL, args TEXT NOT NULL,
            signature TEXT NOT NULL, decision TEXT NOT NULL, resolution TEXT, resolved_by TEXT,
            resolved_at TEXT, execution_result TEXT, agent_id TEXT DEFAULT 'default');
        CREATE TABLE pending_requests (request_id TEXT PRIMARY KEY, tool_name TEXT NOT NULL,
            args TEXT NOT NULL, signature TEXT NOT NULL, message_id TEXT, chat_id INTEGER,
            result TEXT, created_at TEXT NOT NULL DEFAULT 'x', expires_at TEXT NOT NULL,
            agent_id TEXT NOT NULL DEFAULT 'default');
        INSERT INTO pending_requests (request_id, tool_name, args, signature, result, expires_at)
            VALUES ('done', 't', '{}', 's', '{"status": "executed"}', 'x'),
                   ('open', 't', '{}', 's', NULL, 'x');
        PRAGMA user_version = 2;
        """
    )
    conn.commit()
    conn.close()

    database = Database(path)
    await database.initialize()
    assert (await database.get_pending("done"))["state"] == "resolved"
    assert (await database.get_pending("open"))["state"] == "pending"
    assert SCHEMA_VERSION == 6
    await database.close()
    assert sqlite3.connect(path).execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


async def test_v3_database_migrates_to_remembered_rules(tmp_path):
    path = str(tmp_path / "v3.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            request_id TEXT NOT NULL, tool_name TEXT NOT NULL, args TEXT NOT NULL,
            signature TEXT NOT NULL, decision TEXT NOT NULL, resolution TEXT, resolved_by TEXT,
            resolved_at TEXT, execution_result TEXT, agent_id TEXT DEFAULT 'default');
        CREATE TABLE pending_requests (request_id TEXT PRIMARY KEY, tool_name TEXT NOT NULL,
            args TEXT NOT NULL, signature TEXT NOT NULL, message_id TEXT, chat_id INTEGER,
            result TEXT, created_at TEXT NOT NULL DEFAULT 'x', expires_at TEXT NOT NULL,
            agent_id TEXT NOT NULL DEFAULT 'default', state TEXT NOT NULL DEFAULT 'pending',
            handles TEXT);
        INSERT INTO audit_log (timestamp, request_id, tool_name, args, signature, decision)
            VALUES ('2026-01-01T00:00:00Z', 'old', 't', '{}', 't', 'allow');
        PRAGMA user_version = 3;
        """
    )
    conn.commit()
    conn.close()

    database = Database(path)
    await database.initialize()
    [entry] = await database.get_audit_log()
    assert entry.request_id == "old" and entry.remembered_rule_id is None
    assert await database.list_remembered_rules() == []
    await database.close()
    assert sqlite3.connect(path).execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
