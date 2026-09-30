import json
import sqlite3
from datetime import datetime, timezone

from .domain import ConflictError, NotFoundError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class LockedTransaction:
    """BEGIN IMMEDIATE 下的同一连接：检查与写入必须在同一事务里，
    才能保证“先完成的作为当前事实”，晚到一方读到的是对手已提交的事实。"""

    def __init__(self, repository):
        self.repository = repository
        self.connection = None

    def __enter__(self):
        self.connection = self.repository._connect()
        self.connection.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.connection.commit()
        else:
            self.connection.rollback()
        self.connection.close()
        self.connection = None
        return False

    def get_entity(self, entity_id):
        row = self.connection.execute(
            "SELECT * FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        return self.repository._entity_from_row(row) if row else None

    def find_entities(self, kind, field, value):
        rows = self.connection.execute(
            "SELECT * FROM entities WHERE kind = ? ORDER BY created_at, id", (kind,)
        ).fetchall()
        result = []
        for row in rows:
            entity = self.repository._entity_from_row(row)
            if field == "id":
                matched = entity["id"] == value
            else:
                matched = str(entity["data"].get(field)) == str(value)
            if matched:
                result.append(entity)
        return result

    def create_entity(self, entity_id, kind, status, data, actor_id):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        try:
            self.connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (entity_id, kind, status, payload, actor_id, now, now),
            )
        except sqlite3.IntegrityError:
            raise ConflictError("entity already exists: " + entity_id)
        return self.get_entity(entity_id)

    def update_entity(self, entity_id, expected_version, status, data):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        row = self.connection.execute(
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
        self.connection.execute(
            "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
            "WHERE id = ? AND version = ?",
            (status, payload, now, entity_id, current_version),
        )
        return self.get_entity(entity_id)

    def append_audit(self, entity_id, actor_id, actor_role, action,
                     from_status, to_status, detail):
        self.connection.execute(
            "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, "
            "from_status, to_status, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entity_id, actor_id, actor_role, action, from_status, to_status,
                json.dumps(detail or {}, ensure_ascii=False, sort_keys=True),
                utcnow(),
            ),
        )

    def insert_policy_batch(self, batch_id, dataset_id, old_policy_version,
                            new_policy_version, new_access_policy, reason,
                            triggered_by):
        now = utcnow()
        self.connection.execute(
            "INSERT INTO policy_batches(id, dataset_id, old_policy_version, "
            "new_policy_version, new_access_policy, reason, triggered_by, status, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'processing', ?, ?)",
            (batch_id, dataset_id, old_policy_version, new_policy_version,
             new_access_policy, reason, triggered_by, now, now),
        )

    def insert_batch_item(self, batch_id, entity_id, entity_kind, from_status):
        self.connection.execute(
            "INSERT INTO policy_batch_items(batch_id, entity_id, entity_kind, "
            "from_status, result, detail, attempts, updated_at) "
            "VALUES (?, ?, ?, ?, 'pending', '', 0, ?)",
            (batch_id, entity_id, entity_kind, from_status, utcnow()),
        )


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def locked(self):
        return LockedTransaction(self)

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
                CREATE TABLE IF NOT EXISTS policy_batches (
                    id TEXT PRIMARY KEY,
                    dataset_id TEXT NOT NULL,
                    old_policy_version INTEGER NOT NULL,
                    new_policy_version INTEGER NOT NULL,
                    new_access_policy TEXT NOT NULL,
                    reason TEXT,
                    triggered_by TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_policy_batches_dataset
                    ON policy_batches(dataset_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_policy_batches_status
                    ON policy_batches(status);
                CREATE TABLE IF NOT EXISTS policy_batch_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    entity_kind TEXT NOT NULL,
                    from_status TEXT,
                    result TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    replacement_grant_id TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    updated_at TEXT NOT NULL,
                    UNIQUE(batch_id, entity_id)
                );
                CREATE INDEX IF NOT EXISTS idx_batch_items_batch
                    ON policy_batch_items(batch_id, result);
                CREATE TABLE IF NOT EXISTS policy_batch_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    run_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    processed INTEGER NOT NULL,
                    failed INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_batch_runs_batch
                    ON policy_batch_runs(batch_id, id);
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
        return [self._audit_from_row(row) for row in rows]

    @staticmethod
    def _audit_from_row(row):
        return {
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

    # ---- 治理批次 ----

    @staticmethod
    def _batch_from_row(row):
        return {
            "id": row["id"],
            "dataset_id": row["dataset_id"],
            "old_policy_version": int(row["old_policy_version"]),
            "new_policy_version": int(row["new_policy_version"]),
            "new_access_policy": row["new_access_policy"],
            "reason": row["reason"],
            "triggered_by": row["triggered_by"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_policy_batch(self, batch):
        now = utcnow()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO policy_batches(id, dataset_id, old_policy_version, "
                "new_policy_version, new_access_policy, reason, triggered_by, status, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    batch["id"], batch["dataset_id"], batch["old_policy_version"],
                    batch["new_policy_version"], batch["new_access_policy"],
                    batch.get("reason"), batch["triggered_by"], batch["status"],
                    now, now,
                ),
            )
        return self.get_policy_batch(batch["id"])

    def get_policy_batch(self, batch_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM policy_batches WHERE id = ?", (batch_id,)
            ).fetchone()
        return self._batch_from_row(row) if row else None

    def list_policy_batches(self, dataset_id=None, status=None):
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
                "SELECT * FROM policy_batches" + where + " ORDER BY created_at, id",
                params,
            ).fetchall()
        return [self._batch_from_row(row) for row in rows]

    def set_policy_batch_status(self, batch_id, status):
        with self._connect() as connection:
            connection.execute(
                "UPDATE policy_batches SET status = ?, updated_at = ? WHERE id = ?",
                (status, utcnow(), batch_id),
            )

    def add_batch_item(self, batch_id, entity_id, entity_kind, from_status):
        now = utcnow()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO policy_batch_items(batch_id, entity_id, entity_kind, "
                "from_status, result, detail, attempts, updated_at) "
                "VALUES (?, ?, ?, ?, 'pending', '', 0, ?)",
                (batch_id, entity_id, entity_kind, from_status, now),
            )

    @staticmethod
    def _batch_item_from_row(row):
        return {
            "id": row["id"],
            "batch_id": row["batch_id"],
            "entity_id": row["entity_id"],
            "entity_kind": row["entity_kind"],
            "from_status": row["from_status"],
            "result": row["result"],
            "detail": json.loads(row["detail"] or "{}"),
            "replacement_grant_id": row["replacement_grant_id"],
            "attempts": int(row["attempts"]),
            "last_error": row["last_error"],
            "updated_at": row["updated_at"],
        }

    def list_batch_items(self, batch_id, result=None):
        clauses = ["batch_id = ?"]
        params = [batch_id]
        if result:
            clauses.append("result = ?")
            params.append(result)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM policy_batch_items WHERE "
                + " AND ".join(clauses)
                + " ORDER BY id",
                params,
            ).fetchall()
        return [self._batch_item_from_row(row) for row in rows]

    def get_batch_item(self, batch_id, entity_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM policy_batch_items WHERE batch_id = ? AND entity_id = ?",
                (batch_id, entity_id),
            ).fetchone()
        return self._batch_item_from_row(row) if row else None

    def mark_batch_item(self, batch_id, entity_id, result, detail=None,
                        replacement_grant_id=None, error=None):
        with self._connect() as connection:
            connection.execute(
                "UPDATE policy_batch_items SET result = ?, detail = ?, "
                "replacement_grant_id = COALESCE(?, replacement_grant_id), "
                "attempts = attempts + 1, last_error = ?, updated_at = ? "
                "WHERE batch_id = ? AND entity_id = ?",
                (
                    result,
                    json.dumps(detail or {}, ensure_ascii=False, sort_keys=True),
                    replacement_grant_id, error, utcnow(), batch_id, entity_id,
                ),
            )

    def add_batch_run(self, batch_id, run_type, actor_id, status,
                      processed, failed):
        now = utcnow()
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO policy_batch_runs(batch_id, run_type, actor_id, status, "
                "processed, failed, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (batch_id, run_type, actor_id, status, processed, failed, now),
            )
            return cursor.lastrowid

    def list_batch_runs(self, batch_id):
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM policy_batch_runs WHERE batch_id = ? ORDER BY id",
                (batch_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "batch_id": row["batch_id"],
                "run_type": row["run_type"],
                "actor_id": row["actor_id"],
                "status": row["status"],
                "processed": int(row["processed"]),
                "failed": int(row["failed"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
