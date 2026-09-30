import json
import sqlite3
from datetime import datetime, timezone

from .domain import ConflictError, NotFoundError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entities_kind_status
                    ON entities(kind, status);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                    ON audit_log(entity_id, id);
                CREATE TABLE IF NOT EXISTS idempotency (
                    actor_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(actor_id, idem_key)
                );
                CREATE TABLE IF NOT EXISTS governance_batches (
                    id TEXT PRIMARY KEY,
                    dataset_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    policy_version INTEGER,
                    detail TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_batches_dataset
                    ON governance_batches(dataset_id, id);
                CREATE INDEX IF NOT EXISTS idx_batches_status
                    ON governance_batches(status);
                CREATE TABLE IF NOT EXISTS governance_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    entity_kind TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_items_batch
                    ON governance_items(batch_id, id);
                CREATE INDEX IF NOT EXISTS idx_items_status
                    ON governance_items(status);
            """)

    @staticmethod
    def _entity_from_row(row):
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "version": int(row["version"]),
            "data": json.loads(row["data"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_entity(self, entity_id, kind, status, data, actor_id):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (entity_id, kind, status, payload, actor_id, now, now),
            )
        return self.get_entity(entity_id)

    def get_entity(self, entity_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, kind=None, status=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM entities" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def find_entities(self, kind, field, value):
        return [
            entity
            for entity in self.list_entities(kind=kind)
            if (entity["id"] == value if field == "id" else entity["data"].get(field) == value)
        ]

    def update_entity(self, entity_id, expected_version, status, data):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + entity_id)
            current_version = int(row["version"])
            if expected_version is not None and current_version != int(expected_version):
                raise ConflictError(
                    "version conflict: expected %s, found %s"
                    % (expected_version, current_version)
                )
            connection.execute(
                "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (status, payload, now, entity_id, current_version),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(entity_id)

    def append_audit(self, entity_id, actor_id, actor_role, action, from_status, to_status, detail):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entity_id,
                    actor_id,
                    actor_role,
                    action,
                    from_status,
                    to_status,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    utcnow(),
                ),
            )

    def list_audit(self, entity_id=None):
        with self._connect() as connection:
            if entity_id:
                rows = connection.execute(
                    "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY id", (entity_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        return [
            {
                "id": row["id"],
                "entity_id": row["entity_id"],
                "actor_id": row["actor_id"],
                "actor_role": row["actor_role"],
                "action": row["action"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "detail": json.loads(row["detail"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def get_idempotency(self, actor_id, idem_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?",
                (actor_id, idem_key),
            ).fetchone()
        return row["entity_id"] if row else None

    def save_idempotency(self, actor_id, idem_key, entity_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO idempotency(actor_id, idem_key, entity_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (actor_id, idem_key, entity_id, utcnow()),
            )

    # ---- governance batches ----

    @staticmethod
    def _batch_from_row(row):
        return {
            "id": row["id"],
            "dataset_id": row["dataset_id"],
            "kind": row["kind"],
            "status": row["status"],
            "policy_version": int(row["policy_version"]) if row["policy_version"] is not None else None,
            "detail": json.loads(row["detail"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _item_from_row(row):
        return {
            "id": int(row["id"]),
            "batch_id": row["batch_id"],
            "entity_id": row["entity_id"],
            "entity_kind": row["entity_kind"],
            "action": row["action"],
            "status": row["status"],
            "attempts": int(row["attempts"]),
            "last_error": row["last_error"],
            "detail": json.loads(row["detail"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_batch(self, batch_id, dataset_id, kind, policy_version, detail, actor_id):
        now = utcnow()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO governance_batches(id, dataset_id, kind, status, policy_version, detail, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
                (
                    batch_id,
                    dataset_id,
                    kind,
                    policy_version,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    actor_id,
                    now,
                    now,
                ),
            )
        return self.get_batch(batch_id)

    def get_batch(self, batch_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM governance_batches WHERE id = ?", (batch_id,)
            ).fetchone()
        return self._batch_from_row(row) if row else None

    def list_batches(self, dataset_id=None, status=None):
        clauses = []
        params = []
        if dataset_id:
            clauses.append("dataset_id = ?")
            params.append(dataset_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM governance_batches" + where + " ORDER BY id", params
            ).fetchall()
        return [self._batch_from_row(row) for row in rows]

    def list_incomplete_batches(self):
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM governance_batches WHERE status IN ('pending', 'running', 'failed') ORDER BY id"
            ).fetchall()
        return [self._batch_from_row(row) for row in rows]

    def update_batch_status(self, batch_id, status, detail=None):
        now = utcnow()
        with self._connect() as connection:
            if detail is None:
                connection.execute(
                    "UPDATE governance_batches SET status = ?, updated_at = ? WHERE id = ?",
                    (status, now, batch_id),
                )
            else:
                connection.execute(
                    "UPDATE governance_batches SET status = ?, detail = ?, updated_at = ? WHERE id = ?",
                    (status, json.dumps(detail, ensure_ascii=False, sort_keys=True), now, batch_id),
                )
        return self.get_batch(batch_id)

    def add_batch_item(self, batch_id, entity_id, entity_kind, action, detail=None):
        now = utcnow()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO governance_items(batch_id, entity_id, entity_kind, action, status, attempts, last_error, detail, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'pending', 0, NULL, ?, ?, ?)",
                (
                    batch_id,
                    entity_id,
                    entity_kind,
                    action,
                    json.dumps(detail or {}, ensure_ascii=False, sort_keys=True),
                    now,
                    now,
                ),
            )

    def list_batch_items(self, batch_id):
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM governance_items WHERE batch_id = ? ORDER BY id", (batch_id,)
            ).fetchall()
        return [self._item_from_row(row) for row in rows]

    def update_batch_item(self, item_id, status, attempts=None, last_error=None, detail=None):
        now = utcnow()
        with self._connect() as connection:
            connection.execute(
                "UPDATE governance_items SET status = ?, attempts = COALESCE(?, attempts), "
                "last_error = ?, detail = COALESCE(?, detail), updated_at = ? WHERE id = ?",
                (
                    status,
                    attempts,
                    last_error,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True) if detail is not None else None,
                    now,
                    item_id,
                ),
            )

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
