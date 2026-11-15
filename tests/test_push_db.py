"""Push devices storage."""

from __future__ import annotations

import sqlite3

import pytest

from agentpass.db import SCHEMA_VERSION, Database
from agentpass.push.models import PushDevice


def _device(**overrides) -> PushDevice:
    values = {
        "device_id": "dev-1",
        "label": "Phone",
        "endpoint": "https://push.example/abc",
        "p256dh": "key-1",
        "auth": "auth-1",
        "one_tap_approve": False,
        "credential_id": "cred-1",
        "created_at": "2026-11-15T10:00:00Z",
        "last_seen": "2026-11-15T10:00:00Z",
    }
    values.update(overrides)
    return PushDevice(**values)


@pytest.fixture()
async def db(tmp_path):
    database = Database(str(tmp_path / "test.db"))
    await database.initialize()
    yield database
    await database.close()


async def test_upsert_new_device_defaults_one_tap_off(db):
    stored = await db.upsert_push_device(_device())
    assert stored == _device()
    assert stored.one_tap_approve is False
    assert await db.get_push_device("dev-1") == stored
    assert await db.list_push_devices() == [stored]
    assert await db.get_push_device("nope") is None


async def test_resubscribe_same_endpoint_keeps_id_and_setting(db):
    await db.upsert_push_device(_device())
    assert await db.set_push_device("dev-1", one_tap_approve=True)
    again = await db.upsert_push_device(
        _device(
            device_id="dev-2",
            p256dh="key-2",
            auth="auth-2",
            last_seen="2026-11-15T11:00:00Z",
            created_at="2026-11-15T11:00:00Z",
        )
    )
    assert again.device_id == "dev-1"
    assert again.one_tap_approve is True
    assert again.p256dh == "key-2"
    assert again.auth == "auth-2"
    assert again.last_seen == "2026-11-15T11:00:00Z"
    assert again.created_at == "2026-11-15T10:00:00Z"
    assert len(await db.list_push_devices()) == 1


async def test_set_and_delete(db):
    await db.upsert_push_device(_device())
    assert await db.set_push_device("dev-1", label="Tablet")
    assert (await db.get_push_device("dev-1")).label == "Tablet"
    assert (await db.get_push_device("dev-1")).one_tap_approve is False
    assert await db.set_push_device("dev-1", one_tap_approve=True)
    assert (await db.get_push_device("dev-1")).one_tap_approve is True
    assert (await db.get_push_device("dev-1")).label == "Tablet"
    assert await db.set_push_device("dev-1", one_tap_approve=False)
    assert (await db.get_push_device("dev-1")).one_tap_approve is False
    assert not await db.set_push_device("missing", label="x")
    assert await db.delete_push_device("dev-1")
    assert not await db.delete_push_device("dev-1")
    assert await db.get_push_device("dev-1") is None


async def test_delete_by_endpoint(db):
    await db.upsert_push_device(_device())
    assert not await db.delete_push_device_by_endpoint("https://push.example/other")
    assert await db.delete_push_device_by_endpoint("https://push.example/abc")
    assert await db.list_push_devices() == []


async def test_touch_updates_last_seen_only(db):
    await db.upsert_push_device(_device(last_seen="2020-01-01T00:00:00Z"))
    await db.touch_push_device("dev-1")
    after = await db.get_push_device("dev-1")
    assert after.last_seen > "2025-01-01T00:00:00Z"
    assert after.created_at == "2026-11-15T10:00:00Z"
    await db.touch_push_device("missing")


async def test_table_created_on_existing_db(tmp_path):
    path = str(tmp_path / "old.db")
    first = Database(path)
    await first.initialize()
    await first.close()
    # Rewind to the previous schema: no push table, version 6, one audit row.
    con = sqlite3.connect(path)
    con.executescript("DROP TABLE push_devices; PRAGMA user_version = 6;")
    con.execute(
        "INSERT INTO audit_log (timestamp, request_id, tool_name, args, signature, decision)"
        " VALUES ('2026-11-15T09:00:00Z', 'r1', 't', '{}', 's', 'allow')"
    )
    con.commit()
    con.close()

    second = Database(path)
    await second.initialize()
    try:
        await second.upsert_push_device(_device())
        assert len(await second.list_push_devices()) == 1
        conn = second._get_conn()
        cursor = await conn.execute("SELECT request_id FROM audit_log")
        assert [r[0] for r in await cursor.fetchall()] == ["r1"]
    finally:
        await second.close()
    check = sqlite3.connect(path)
    assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    check.close()
