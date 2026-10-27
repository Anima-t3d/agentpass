"""SQLite storage for audit log and pending requests."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite

from agentpass.models import AuditEntry

_IDEMPOTENCY_TABLE = """CREATE TABLE IF NOT EXISTS idempotency_keys (
    agent_id TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args TEXT NOT NULL,
    request_id TEXT,
    result TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (agent_id, idem_key)
)"""

_REMEMBERED_TABLE = """CREATE TABLE IF NOT EXISTS remembered_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('exact', 'tool')),
    tool_name TEXT NOT NULL,
    signature TEXT,
    args_hash TEXT,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    revoked_by TEXT,
    source_request_id TEXT NOT NULL,
    tool_fingerprint TEXT NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    last_used_at TEXT
)"""

_REMEMBERED_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_remembered_lookup"
    " ON remembered_rules(agent_id, tool_name) WHERE revoked_at IS NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_remembered_unique"
    " ON remembered_rules(agent_id, scope, tool_name, COALESCE(signature, ''),"
    " COALESCE(args_hash, ''), action) WHERE revoked_at IS NULL",
]

_TABLES = [
    """CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    request_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args TEXT NOT NULL,
    signature TEXT NOT NULL,
    decision TEXT NOT NULL,
    resolution TEXT,
    resolved_by TEXT,
    resolved_at TEXT,
    execution_result TEXT,
    agent_id TEXT DEFAULT 'default',
    remembered_rule_id INTEGER
)""",
    """CREATE TABLE IF NOT EXISTS pending_requests (
    request_id TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL,
    args TEXT NOT NULL,
    signature TEXT NOT NULL,
    message_id TEXT,
    chat_id INTEGER,
    result TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT NOT NULL,
    agent_id TEXT NOT NULL DEFAULT 'default',
    state TEXT NOT NULL DEFAULT 'pending',
    handles TEXT
)""",
    _IDEMPOTENCY_TABLE,
    _REMEMBERED_TABLE,
]

# Indexes may reference migrated columns, so they run after _migrate().
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool_name)",
    "CREATE INDEX IF NOT EXISTS idx_pending_expires ON pending_requests(expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_pending_agent ON pending_requests(agent_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id)",
    *_REMEMBERED_INDEXES,
]

_SCHEMA = ";\n".join([*_TABLES, *_INDEXES]) + ";\n"

# Bump when the schema changes and add a step to _MIGRATIONS. A database with
# user_version 0 is either brand new or from before versioning (v0 baseline).
SCHEMA_VERSION = 4


async def _columns(conn: aiosqlite.Connection, table: str) -> set[str]:
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in await cursor.fetchall()}


async def _migrate_to_v1(conn: aiosqlite.Connection) -> None:
    """Per-agent identities: agent_id on pending_requests (and audit_log if very old)."""
    if "agent_id" not in await _columns(conn, "pending_requests"):
        await conn.execute(
            "ALTER TABLE pending_requests ADD COLUMN agent_id TEXT NOT NULL DEFAULT 'default'"
        )
    if "agent_id" not in await _columns(conn, "audit_log"):
        await conn.execute("ALTER TABLE audit_log ADD COLUMN agent_id TEXT DEFAULT 'default'")


async def _migrate_to_v2(conn: aiosqlite.Connection) -> None:
    """Idempotency keys survive restarts (DESIGN 7.4)."""
    await conn.execute(_IDEMPOTENCY_TABLE)


async def _migrate_to_v3(conn: aiosqlite.Connection) -> None:
    """Approval coordinator: the DB arbitrates the first answer (DESIGN 4.2)."""
    columns = await _columns(conn, "pending_requests")
    if "state" not in columns:
        await conn.execute(
            "ALTER TABLE pending_requests ADD COLUMN state TEXT NOT NULL DEFAULT 'pending'"
        )
        # rows that already carry a final result were resolved before this version
        await conn.execute(
            "UPDATE pending_requests SET state = 'resolved' WHERE result IS NOT NULL"
        )
    if "handles" not in columns:
        await conn.execute("ALTER TABLE pending_requests ADD COLUMN handles TEXT")


async def _migrate_to_v4(conn: aiosqlite.Connection) -> None:
    """Remembered decisions (Allow always / Deny always); audit rows name the rule."""
    await conn.execute(_REMEMBERED_TABLE)
    for statement in _REMEMBERED_INDEXES:
        await conn.execute(statement)
    if "remembered_rule_id" not in await _columns(conn, "audit_log"):
        await conn.execute("ALTER TABLE audit_log ADD COLUMN remembered_rule_id INTEGER")


_MIGRATIONS = {1: _migrate_to_v1, 2: _migrate_to_v2, 3: _migrate_to_v3, 4: _migrate_to_v4}


async def _migrate(conn: aiosqlite.Connection) -> None:
    """Upgrade an existing database in place. Runs before _SCHEMA touches anything."""
    cursor = await conn.execute("PRAGMA user_version")
    row = await cursor.fetchone()
    version = row[0] if row else 0
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {version} is newer than supported ({SCHEMA_VERSION})"
        )
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
        "('audit_log', 'pending_requests')"
    )
    existing = {r[0] for r in await cursor.fetchall()}
    if existing:  # fresh databases get the current shape from _SCHEMA
        if existing != {"audit_log", "pending_requests"}:
            # Half-created legacy database: create the rest first, then migrate
            for statement in _TABLES:
                await conn.execute(statement)
        for target in range(version + 1, SCHEMA_VERSION + 1):
            await _MIGRATIONS[target](conn)
    await conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    await conn.commit()


def _epoch_to_iso(epoch: float) -> str:
    """Convert epoch float to ISO 8601 string."""
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Database:
    """Async SQLite database for audit logging and pending requests."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._conn: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Create schema, open persistent connection, and set file permissions."""
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await _migrate(self._conn)
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()

        # Set file permissions to 0600
        os.chmod(self._path, stat.S_IRUSR | stat.S_IWUSR)

    def _get_conn(self) -> aiosqlite.Connection:
        """Return the persistent connection, or raise if not initialized."""
        if self._conn is None:
            raise RuntimeError("Database not initialized — call initialize() first")
        return self._conn

    async def log_audit(self, entry: AuditEntry) -> None:
        """Insert an audit log entry."""
        conn = self._get_conn()
        timestamp = _epoch_to_iso(entry.timestamp)
        resolved_at = _epoch_to_iso(entry.resolved_at) if entry.resolved_at else None
        args_json = json.dumps(entry.args)
        result_json = json.dumps(entry.execution_result) if entry.execution_result else None

        await conn.execute(
            """INSERT INTO audit_log
               (timestamp, request_id, tool_name, args, signature, decision,
                resolution, resolved_by, resolved_at, execution_result, agent_id,
                remembered_rule_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp,
                entry.request_id,
                entry.tool_name,
                args_json,
                entry.signature,
                entry.decision,
                entry.resolution,
                entry.resolved_by,
                resolved_at,
                result_json,
                entry.agent_id,
                entry.remembered_rule_id,
            ),
        )
        await conn.commit()

    async def get_audit_log(self, limit: int = 100) -> list[AuditEntry]:
        """Query recent audit log entries in reverse chronological order."""
        conn = self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [self._row_to_audit_entry(dict(row)) for row in rows]

    @staticmethod
    def _row_to_audit_entry(row: dict[str, Any]) -> AuditEntry:
        """Convert a database row dict to an AuditEntry dataclass."""
        # Parse ISO timestamp back to epoch float
        ts = datetime.fromisoformat(row["timestamp"]).replace(tzinfo=UTC).timestamp()

        # Parse resolved_at ISO back to epoch float if present
        resolved_at: float | None = None
        if row.get("resolved_at"):
            resolved_at = datetime.fromisoformat(row["resolved_at"]).replace(tzinfo=UTC).timestamp()

        # Parse JSON args back to dict
        args = json.loads(row["args"]) if isinstance(row["args"], str) else row["args"]

        # Parse execution_result JSON back to dict if present
        execution_result: dict[str, Any] | None = None
        if row.get("execution_result"):
            execution_result = (
                json.loads(row["execution_result"])
                if isinstance(row["execution_result"], str)
                else row["execution_result"]
            )

        return AuditEntry(
            request_id=row["request_id"],
            timestamp=ts,
            tool_name=row["tool_name"],
            args=args,
            signature=row["signature"],
            decision=row["decision"],
            resolution=row.get("resolution"),
            resolved_by=row.get("resolved_by"),
            resolved_at=resolved_at,
            execution_result=execution_result,
            agent_id=row.get("agent_id", "default"),
            remembered_rule_id=row.get("remembered_rule_id"),
        )

    async def insert_pending(
        self,
        request_id: str,
        tool_name: str,
        args: dict,
        signature: str,
        expires_at: str,
        agent_id: str = "default",
    ) -> None:
        """Insert a pending approval request."""
        conn = self._get_conn()
        args_json = json.dumps(args)
        await conn.execute(
            """INSERT INTO pending_requests
               (request_id, tool_name, args, signature, expires_at, agent_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (request_id, tool_name, args_json, signature, expires_at, agent_id),
        )
        await conn.commit()

    async def set_pending_handles(self, request_id: str, handles: str) -> None:
        """Store the channel handles (JSON) so a restart can finalize the messages."""
        conn = self._get_conn()
        await conn.execute(
            "UPDATE pending_requests SET handles = ? WHERE request_id = ?", (handles, request_id)
        )
        await conn.commit()

    async def transition_pending(self, request_id: str, state: str) -> bool:
        """Atomically move a ``pending`` row to *state*; True only for the caller that did it."""
        conn = self._get_conn()
        cursor = await conn.execute(
            "UPDATE pending_requests SET state = ? WHERE request_id = ? AND state = 'pending'",
            (state, request_id),
        )
        await conn.commit()
        return cursor.rowcount == 1

    async def abandon_pending(self) -> list[dict[str, Any]]:
        """At startup: every leftover ``pending`` row becomes ``abandoned``; returns them."""
        conn = self._get_conn()
        cursor = await conn.execute("SELECT * FROM pending_requests WHERE state = 'pending'")
        rows = [dict(row) for row in await cursor.fetchall()]
        await conn.execute(
            "UPDATE pending_requests SET state = 'abandoned' WHERE state = 'pending'"
        )
        await conn.commit()
        return rows

    async def get_pending(self, request_id: str) -> dict[str, Any] | None:
        """Get a single pending request, or None if not found."""
        conn = self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM pending_requests WHERE request_id = ?", (request_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def delete_pending(self, request_id: str) -> None:
        """Delete a resolved pending request."""
        conn = self._get_conn()
        await conn.execute("DELETE FROM pending_requests WHERE request_id = ?", (request_id,))
        await conn.commit()

    async def cleanup_stale_requests(self) -> list[dict[str, Any]]:
        """Delete expired pending requests and return them."""
        conn = self._get_conn()
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor = await conn.execute(
            "SELECT * FROM pending_requests WHERE expires_at <= ? AND result IS NULL", (now,)
        )
        stale = [dict(row) for row in await cursor.fetchall()]
        if stale:
            await conn.execute(
                "DELETE FROM pending_requests WHERE expires_at <= ? AND result IS NULL", (now,)
            )
            await conn.commit()
        return stale

    async def settle_orphans(self) -> int:
        """At startup nothing is waiting any more: give unanswered approvals a final result.

        Expired ones become ``timeout``, the rest ``denied`` (the gateway restarted
        before a human answered). Unfinished idempotency keys are dropped so a retry
        asks afresh. Returns how many approvals were settled.
        """
        conn = self._get_conn()
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor = await conn.execute(
            "SELECT request_id, expires_at FROM pending_requests WHERE result IS NULL"
        )
        rows = await cursor.fetchall()
        for row in rows:
            if row["expires_at"] <= now:
                payload = {"status": "timeout", "code": "approval_timeout"}
                payload["data"] = "Approval timed out"
            else:
                payload = {"status": "denied", "code": "approval_denied"}
                payload["data"] = "Gateway restarted before the approval was answered"
            await conn.execute(
                "UPDATE pending_requests SET result = ? WHERE request_id = ?",
                (json.dumps(payload), row["request_id"]),
            )
        await conn.execute("DELETE FROM idempotency_keys WHERE result IS NULL")
        await conn.commit()
        return len(rows)

    async def purge_finished(self, max_age_seconds: float) -> None:
        """Drop stored results and idempotency keys older than *max_age_seconds*."""
        conn = self._get_conn()
        cutoff = _epoch_to_iso(datetime.now(UTC).timestamp() - max_age_seconds)
        await conn.execute(
            "DELETE FROM pending_requests WHERE result IS NOT NULL AND created_at <= ?", (cutoff,)
        )
        await conn.execute("DELETE FROM idempotency_keys WHERE created_at <= ?", (cutoff,))
        await conn.commit()

    # --- Idempotency keys ---

    async def get_idempotency(self, agent_id: str, key: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM idempotency_keys WHERE agent_id = ? AND idem_key = ?", (agent_id, key)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def put_idempotency(self, agent_id: str, key: str, tool_name: str, args: str) -> None:
        """Register a key (replacing a stale one); *args* is canonical JSON."""
        conn = self._get_conn()
        await conn.execute(
            "INSERT OR REPLACE INTO idempotency_keys (agent_id, idem_key, tool_name, args)"
            " VALUES (?, ?, ?, ?)",
            (agent_id, key, tool_name, args),
        )
        await conn.commit()

    async def set_idempotency_request(self, agent_id: str, key: str, request_id: str) -> None:
        conn = self._get_conn()
        await conn.execute(
            "UPDATE idempotency_keys SET request_id = ? WHERE agent_id = ? AND idem_key = ?",
            (request_id, agent_id, key),
        )
        await conn.commit()

    async def set_idempotency_result(self, agent_id: str, key: str, result: str) -> None:
        conn = self._get_conn()
        await conn.execute(
            "UPDATE idempotency_keys SET result = ? WHERE agent_id = ? AND idem_key = ?",
            (result, agent_id, key),
        )
        await conn.commit()

    async def delete_idempotency(self, agent_id: str, key: str) -> None:
        conn = self._get_conn()
        await conn.execute(
            "DELETE FROM idempotency_keys WHERE agent_id = ? AND idem_key = ?", (agent_id, key)
        )
        await conn.commit()

    async def update_pending_result(self, request_id: str, result: str) -> None:
        """Write a JSON result string to the result column of a pending request."""
        conn = self._get_conn()
        await conn.execute(
            "UPDATE pending_requests SET result = ? WHERE request_id = ?",
            (result, request_id),
        )
        await conn.commit()

    async def get_completed_results(self, agent_id: str | None = None) -> list[dict[str, Any]]:
        """Return pending_requests rows where result IS NOT NULL (only *agent_id*'s if given)."""
        conn = self._get_conn()
        query = "SELECT * FROM pending_requests WHERE result IS NOT NULL"
        params: tuple[Any, ...] = ()
        if agent_id is not None:
            query += " AND agent_id = ?"
            params = (agent_id,)
        cursor = await conn.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def delete_completed_results(
        self, request_ids: list[str], agent_id: str | None = None
    ) -> None:
        """Delete pending_requests by request_id list (only *agent_id*'s if given)."""
        if not request_ids:
            return
        conn = self._get_conn()
        placeholders = ",".join("?" for _ in request_ids)
        query = f"DELETE FROM pending_requests WHERE request_id IN ({placeholders})"
        params: list[Any] = list(request_ids)
        if agent_id is not None:
            query += " AND agent_id = ?"
            params.append(agent_id)
        await conn.execute(query, params)
        await conn.commit()

    async def update_audit_resolution(
        self,
        request_id: str,
        resolution: str,
        resolved_by: str,
        resolved_at: float,
        execution_result: dict[str, Any] | None = None,
        remembered_rule_id: int | None = None,
    ) -> None:
        """Update an existing audit entry with resolution details."""
        conn = self._get_conn()
        resolved_at_iso = _epoch_to_iso(resolved_at)
        result_json = json.dumps(execution_result) if execution_result else None
        await conn.execute(
            """UPDATE audit_log
               SET resolution = ?, resolved_by = ?, resolved_at = ?, execution_result = ?,
                   remembered_rule_id = COALESCE(?, remembered_rule_id)
               WHERE request_id = ?""",
            (resolution, resolved_by, resolved_at_iso, result_json, remembered_rule_id, request_id),
        )
        await conn.commit()

    async def get_audit_log_filtered(
        self,
        tool_name: str | None = None,
        decision: str | None = None,
        resolution: str | None = None,
        from_ts: float | None = None,
        to_ts: float | None = None,
        limit: int = 50,
        offset: int = 0,
        agent_id: str | None = None,
    ) -> tuple[list[AuditEntry], int]:
        """Return (entries, total_count) with filtering and pagination."""
        conn = self._get_conn()
        conditions: list[str] = []
        params: list[Any] = []

        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if decision:
            conditions.append("decision = ?")
            params.append(decision)
        if resolution:
            conditions.append("resolution = ?")
            params.append(resolution)
        if from_ts is not None:
            conditions.append("timestamp >= ?")
            params.append(_epoch_to_iso(from_ts))
        if to_ts is not None:
            conditions.append("timestamp <= ?")
            params.append(_epoch_to_iso(to_ts))

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        # Get total count
        count_cursor = await conn.execute(f"SELECT COUNT(*) FROM audit_log {where}", params)
        row = await count_cursor.fetchone()
        total = row[0] if row else 0

        # Get paginated entries
        cursor = await conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        rows = await cursor.fetchall()
        return [self._row_to_audit_entry(dict(r)) for r in rows], total

    async def get_audit_stats(self) -> dict[str, Any]:
        """Return summary statistics from the audit log."""
        conn = self._get_conn()

        # Total requests
        cursor = await conn.execute("SELECT COUNT(*) FROM audit_log")
        row = await cursor.fetchone()
        total = row[0] if row else 0

        # Last 24 hours
        cutoff = _epoch_to_iso(datetime.now(UTC).timestamp() - 86400)
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?", (cutoff,)
        )
        row = await cursor.fetchone()
        last_24h = row[0] if row else 0

        # Decision breakdown
        cursor = await conn.execute("SELECT decision, COUNT(*) FROM audit_log GROUP BY decision")
        decision_breakdown: dict[str, int] = {}
        for r in await cursor.fetchall():
            decision_breakdown[r[0]] = r[1]

        # Approval rate (approved out of all ask decisions that resolved)
        ask_total = decision_breakdown.get("ask", 0)
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE decision = 'ask' AND resolution = 'approved'"
        )
        row = await cursor.fetchone()
        approved_count = row[0] if row else 0
        approval_rate = approved_count / ask_total if ask_total > 0 else 0.0

        # Top tools
        cursor = await conn.execute(
            "SELECT tool_name, COUNT(*) as cnt FROM audit_log "
            "WHERE tool_name != '' GROUP BY tool_name ORDER BY cnt DESC LIMIT 10"
        )
        top_tools = [{"name": r[0], "count": r[1]} for r in await cursor.fetchall()]

        return {
            "total_requests": total,
            "last_24h": last_24h,
            "approval_rate": round(approval_rate, 2),
            "top_tools": top_tools,
            "decision_breakdown": decision_breakdown,
        }

    async def get_distinct_tool_names(self) -> list[str]:
        """Return sorted list of distinct tool names from the audit log."""
        conn = self._get_conn()
        cursor = await conn.execute(
            "SELECT DISTINCT tool_name FROM audit_log WHERE tool_name != '' ORDER BY tool_name"
        )
        return [r[0] for r in await cursor.fetchall()]

    # --- Remembered decisions (Allow always / Deny always) ---

    async def upsert_remembered_rule(self, rule: dict[str, Any]) -> tuple[int, bool]:
        """Insert a rule; an identical unrevoked one is renewed instead. Returns (id, created)."""
        conn = self._get_conn()
        cursor = await conn.execute(
            """SELECT id FROM remembered_rules
               WHERE revoked_at IS NULL AND agent_id = ? AND scope = ? AND tool_name = ?
                 AND COALESCE(signature, '') = ? AND COALESCE(args_hash, '') = ? AND action = ?""",
            (
                rule["agent_id"],
                rule["scope"],
                rule["tool_name"],
                rule["signature"] or "",
                rule["args_hash"] or "",
                rule["action"],
            ),
        )
        existing = await cursor.fetchone()
        if existing is not None:
            await conn.execute(
                """UPDATE remembered_rules SET created_by = ?, created_at = ?, expires_at = ?,
                          source_request_id = ?, tool_fingerprint = ?, pattern = ?
                   WHERE id = ?""",
                (
                    rule["created_by"],
                    rule["created_at"],
                    rule["expires_at"],
                    rule["source_request_id"],
                    rule["tool_fingerprint"],
                    rule["pattern"],
                    existing["id"],
                ),
            )
            await conn.commit()
            return existing["id"], False
        cursor = await conn.execute(
            """INSERT INTO remembered_rules
               (agent_id, scope, tool_name, signature, args_hash, pattern, action, created_by,
                created_at, expires_at, source_request_id, tool_fingerprint)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule["agent_id"],
                rule["scope"],
                rule["tool_name"],
                rule["signature"],
                rule["args_hash"],
                rule["pattern"],
                rule["action"],
                rule["created_by"],
                rule["created_at"],
                rule["expires_at"],
                rule["source_request_id"],
                rule["tool_fingerprint"],
            ),
        )
        await conn.commit()
        assert cursor.lastrowid is not None
        return cursor.lastrowid, True

    async def candidate_remembered_rules(
        self, agent_id: str, tool_name: str, now_iso: str
    ) -> list[dict[str, Any]]:
        """Unrevoked, unexpired rules of one agent for one tool (matching is done by the caller)."""
        conn = self._get_conn()
        cursor = await conn.execute(
            """SELECT * FROM remembered_rules
               WHERE agent_id = ? AND tool_name = ? AND revoked_at IS NULL
                 AND (expires_at IS NULL OR expires_at > ?)
               ORDER BY id""",
            (agent_id, tool_name, now_iso),
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def list_remembered_rules(
        self, agent_id: str | None = None, include_inactive: bool = True
    ) -> list[dict[str, Any]]:
        """All rules (newest first); with *include_inactive* False only the unrevoked ones."""
        conn = self._get_conn()
        conditions: list[str] = []
        params: list[Any] = []
        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if not include_inactive:
            conditions.append("revoked_at IS NULL")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        cursor = await conn.execute(
            f"SELECT * FROM remembered_rules {where} ORDER BY id DESC", params
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_remembered_rule(self, rule_id: int) -> dict[str, Any] | None:
        conn = self._get_conn()
        cursor = await conn.execute("SELECT * FROM remembered_rules WHERE id = ?", (rule_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def revoke_remembered_rule(self, rule_id: int, revoked_by: str, now_iso: str) -> bool:
        """Revoke an unrevoked rule; True only for the caller that did it."""
        conn = self._get_conn()
        cursor = await conn.execute(
            "UPDATE remembered_rules SET revoked_at = ?, revoked_by = ?"
            " WHERE id = ? AND revoked_at IS NULL",
            (now_iso, revoked_by, rule_id),
        )
        await conn.commit()
        return cursor.rowcount == 1

    async def touch_remembered_rule(self, rule_id: int, now_iso: str) -> None:
        conn = self._get_conn()
        await conn.execute(
            "UPDATE remembered_rules SET use_count = use_count + 1, last_used_at = ? WHERE id = ?",
            (now_iso, rule_id),
        )
        await conn.commit()

    async def health_check(self) -> bool:
        """Return True if the database connection is alive."""
        try:
            conn = self._get_conn()
            await conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        """Close the persistent connection."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
