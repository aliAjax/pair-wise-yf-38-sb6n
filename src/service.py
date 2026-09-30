from uuid import uuid4

from .audit import AuditTrail
from .domain import (
    Actor,
    ConflictError,
    NotFoundError,
    PermissionDenied,
    ValidationError,
)
from .repository import utcnow
from .rules import ORIGINAL_POLICY_VERSION, RuleEngine, policy_version_of


# 系统续跑身份：重启后续做/批次内联动作以管理员权威执行。
SYSTEM_ACTOR = Actor("system", "admin")

PENDING_APPLICATION_STATUSES = ("submitted", "under_review")
LIVE_GRANT_STATUSES = ("issued", "active")
TERMINAL_ITEM_RESULTS = ("done", "skipped")


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)
        # 测试可注入：callback(batch, item)，在条目事务内抛错可模拟批次失败。
        self.item_hook = None

    # ---- 基础辅助 ----

    def _lookup_in(self, tx):
        def lookup(kind, field, value):
            return tx.find_entities(self.rules.normalize_kind(kind), field, value)
        return lookup

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    # ---- 创建 ----

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        entity_id = str(payload.pop("id", "") or uuid4())
        with self.repository.locked() as tx:
            if tx.get_entity(entity_id):
                raise ConflictError("entity already exists: " + entity_id)
            validated = self.rules.validate_create(
                actor, kind, payload, self._lookup_in(tx)
            )
            if kind == "dataset":
                validated.setdefault(
                    "policy_version", ORIGINAL_POLICY_VERSION
                )
                validated.setdefault(
                    "policy_history",
                    [{
                        "version": ORIGINAL_POLICY_VERSION,
                        "access_policy": validated.get("access_policy"),
                        "reason": "registered",
                        "at": utcnow(),
                        "by": actor.user_id,
                    }],
                )
            status = self.rules.initial_status(kind)
            entity = tx.create_entity(entity_id, kind, status, validated, actor.user_id)
            tx.append_audit(entity_id, actor.user_id, actor.role, "create",
                            None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    # ---- 状态转移（全部走同一把锁：检查+写入原子化）----

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        data = dict(data or {})
        with self.repository.locked() as tx:
            entity = tx.get_entity(entity_id)
            if not entity:
                raise NotFoundError("entity not found: " + entity_id)
            kind = self.rules.normalize_kind(entity["kind"])
            if kind == "dataset" and action == "update_policy":
                raise ValidationError(
                    "policy update must be submitted via the policy batch endpoint"
                )
            expected = (
                int(expected_version)
                if expected_version is not None
                else entity["version"]
            )
            next_status, patch = self.rules.validate_transition(
                actor, entity, action, data, self._lookup_in(tx)
            )
            merged = dict(entity["data"])
            merged.update(patch)
            updated = tx.update_entity(entity_id, expected, next_status, merged)
            tx.append_audit(
                entity_id, actor.user_id, actor.role, action,
                entity["status"], updated["status"], {"patch": patch},
            )
            return updated

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        kind = self.rules.normalize_kind(kind) if kind else None
        if kind == "policy_batch":
            return self.repository.list_policy_batches(status=status)
        return self.repository.list_entities(kind=kind, status=status)

    def list_policy_batches(self, dataset_id=None, status=None):
        return self.repository.list_policy_batches(
            dataset_id=dataset_id, status=status
        )

    def audit_log(self, entity_id=None, dataset_id=None):
        if dataset_id:
            return self._audit_for_dataset(dataset_id)
        return self.repository.list_audit(entity_id=entity_id)

    def _audit_for_dataset(self, dataset_id):
        dataset = self.repository.get_entity(dataset_id)
        if not dataset:
            raise NotFoundError("dataset not found: " + dataset_id)
        related = {dataset_id}
        for batch in self.repository.list_policy_batches(dataset_id=dataset_id):
            related.add(batch["id"])
            for item in self.repository.list_batch_items(batch["id"]):
                related.add(item["entity_id"])
                if item.get("replacement_grant_id"):
                    related.add(item["replacement_grant_id"])
        rows = [
            row for row in self.repository.list_audit()
            if row["entity_id"] in related
        ]
        rows.sort(key=lambda row: row["id"])
        return rows

    # ---- 政策变更治理批次 ----

    def update_policy(self, actor, dataset_id, data):
        if actor.role != "admin":
            raise PermissionDenied("only administrators can change access policy")
        new_policy = (data or {}).get("access_policy")
        if not new_policy or len(str(new_policy)) < 3:
            raise ValidationError("access_policy is required")
        reason = (data or {}).get("reason") or "policy update"

        with self.repository.locked() as tx:
            dataset = tx.get_entity(dataset_id)
            if not dataset:
                raise NotFoundError("dataset not found: " + dataset_id)
            old_version = policy_version_of(dataset["data"])
            new_version = old_version + 1
            history = list(dataset["data"].get("policy_history") or [])
            history.append({
                "version": new_version,
                "access_policy": new_policy,
                "reason": reason,
                "at": utcnow(),
                "by": actor.user_id,
            })
            patched = dict(dataset["data"])
            patched.update({
                "access_policy": new_policy,
                "policy_version": new_version,
                "policy_history": history,
            })
            tx.update_entity(dataset_id, dataset["version"], dataset["status"], patched)
            tx.append_audit(
                dataset_id, actor.user_id, actor.role, "update_policy",
                dataset["status"], dataset["status"],
                {"old_policy_version": old_version,
                 "new_policy_version": new_version, "reason": reason},
            )

            applications = tx.find_entities("application", "dataset_id", dataset_id)
            grants = tx.find_entities("grant", "dataset_id", dataset_id)
            affected_apps = [
                app for app in applications
                if policy_version_of(app["data"]) == old_version
                and app["status"] in PENDING_APPLICATION_STATUSES
            ]
            affected_grants = [
                grant for grant in grants
                if policy_version_of(grant["data"]) == old_version
                and grant["status"] in LIVE_GRANT_STATUSES
            ]

            batch_id = "batch-" + uuid4().hex[:12]
            tx.insert_policy_batch(
                batch_id, dataset_id, old_version, new_version,
                new_policy, reason, actor.user_id,
            )
            for app in affected_apps:
                tx.insert_batch_item(batch_id, app["id"], "application", app["status"])
            for grant in affected_grants:
                tx.insert_batch_item(batch_id, grant["id"], "grant", grant["status"])
            tx.append_audit(
                batch_id, actor.user_id, actor.role, "policy_batch_opened",
                None, "processing",
                {"dataset_id": dataset_id,
                 "old_policy_version": old_version,
                 "new_policy_version": new_version,
                 "affected_applications": len(affected_apps),
                 "affected_grants": len(affected_grants)},
            )

        # 政策已提交即生效；条目逐条独立事务处理，失败保留、可重试。
        return self._run_batch(batch_id, run_type="initial", actor=actor)

    def retry_policy_batch(self, actor, batch_id):
        if actor.role != "admin":
            raise PermissionDenied("only administrators can retry policy batches")
        batch = self.repository.get_policy_batch(batch_id)
        if not batch:
            raise NotFoundError("policy batch not found: " + batch_id)
        return self._run_batch(batch_id, run_type="retry", actor=actor)

    def resume_on_startup(self):
        """重启后续做：只处理中断在 processing 的批次，已完成条目不会重复处理。"""
        resumed = []
        for batch in self.repository.list_policy_batches(status="processing"):
            resumed.append(
                self._run_batch(batch["id"], run_type="resume", actor=SYSTEM_ACTOR)
            )
        return resumed

    def _run_batch(self, batch_id, run_type, actor):
        batch = self.repository.get_policy_batch(batch_id)
        if not batch:
            raise NotFoundError("policy batch not found: " + batch_id)
        self.repository.set_policy_batch_status(batch_id, "processing")

        pending = [
            item for item in self.repository.list_batch_items(batch_id)
            if item["result"] not in TERMINAL_ITEM_RESULTS
        ]
        processed = 0
        failed = 0
        for item in pending:
            try:
                outcome = self._process_item(batch, item, actor)
            except Exception as exc:  # 单条失败：回滚该条，保留待重试
                failed += 1
                self.repository.mark_batch_item(
                    batch_id, item["entity_id"], "failed",
                    detail={"run_type": run_type}, error=str(exc),
                )
                self.repository.append_audit(
                    batch_id, actor.user_id, actor.role,
                    "policy_batch_item_failed", None, "failed",
                    {"run_type": run_type, "entity_id": item["entity_id"],
                     "entity_kind": item["entity_kind"], "error": str(exc)},
                )
                continue
            processed += 1
            self.repository.mark_batch_item(
                batch_id, item["entity_id"], outcome["result"],
                detail={"run_type": run_type, **outcome.get("detail", {})},
                replacement_grant_id=outcome.get("replacement_grant_id"),
            )
            self.repository.append_audit(
                batch_id, actor.user_id, actor.role,
                "policy_batch_item_" + outcome["result"], None, outcome["result"],
                {"run_type": run_type, "entity_id": item["entity_id"],
                 "entity_kind": item["entity_kind"],
                 **outcome.get("detail", {})},
            )

        remaining = [
            item for item in self.repository.list_batch_items(batch_id)
            if item["result"] not in TERMINAL_ITEM_RESULTS
        ]
        final_status = "completed" if not remaining else "failed"
        self.repository.set_policy_batch_status(batch_id, final_status)
        self.repository.add_batch_run(
            batch_id, run_type, actor.user_id, final_status, processed, failed
        )
        self.repository.append_audit(
            batch_id, actor.user_id, actor.role, "policy_batch_run",
            None, final_status,
            {"run_type": run_type, "processed": processed, "failed": failed},
        )
        return self.get_policy_batch(batch_id)

    def _process_item(self, batch, item, actor):
        """单个条目在一个 IMMEDIATE 事务内完成；任何异常整体回滚，不留半成品。"""
        with self.repository.locked() as tx:
            entity = tx.get_entity(item["entity_id"])
            if not entity:
                raise NotFoundError("entity not found: " + item["entity_id"])
            if self.item_hook:
                self.item_hook(batch, item)

            reason = "policy %s -> %s: %s" % (
                batch["old_policy_version"],
                batch["new_policy_version"],
                batch.get("reason") or "policy update",
            )

            if item["entity_kind"] == "application":
                return self._process_application_item(tx, batch, entity, reason, actor)
            return self._process_grant_item(tx, batch, entity, reason, actor)

    def _process_application_item(self, tx, batch, application, reason, actor):
        if application["status"] not in PENDING_APPLICATION_STATUSES:
            # 条目登记后申请已被撤回/拒绝/批准：不处理，也不能重复操作。
            return {"result": "skipped",
                    "detail": {"reason": "no longer pending approval",
                               "status": application["status"]}}
        next_status, patch = self.rules.validate_transition(
            actor, application, "return_for_review",
            {"reason": reason}, self._lookup_in(tx)
        )
        patch.update({
            "batch_id": batch["id"],
            "old_policy_version": batch["old_policy_version"],
            "returned_at": utcnow(),
        })
        merged = dict(application["data"])
        merged.update(patch)
        tx.update_entity(application["id"], application["version"], next_status, merged)
        tx.append_audit(
            application["id"], actor.user_id, actor.role, "return_for_review",
            application["status"], next_status,
            {"batch_id": batch["id"], "patch": patch},
        )
        return {"result": "done",
                "detail": {"to_status": next_status}}

    def _process_grant_item(self, tx, batch, grant, reason, actor):
        if grant["status"] not in LIVE_GRANT_STATUSES:
            # 已吊销/已过期：不能也不必重复吊销。
            return {"result": "skipped",
                    "detail": {"reason": "grant no longer live",
                               "status": grant["status"]}}

        replacement_id = "grant-" + uuid4().hex[:12]
        next_status, patch = self.rules.validate_transition(
            actor, grant, "revoke_policy_change",
            {"reason": reason}, self._lookup_in(tx)
        )
        patch.update({
            "batch_id": batch["id"],
            "superseded_by": replacement_id,
            "revoked_at": utcnow(),
        })
        merged = dict(grant["data"])
        merged.update(patch)
        tx.update_entity(grant["id"], grant["version"], next_status, merged)
        tx.append_audit(
            grant["id"], actor.user_id, actor.role, "revoke_policy_change",
            grant["status"], next_status,
            {"batch_id": batch["id"], "replacement_grant_id": replacement_id,
             "patch": patch},
        )

        # 生成新版本凭证：按新政策签发、初始 issued，等待正常激活流程。
        replacement = {
            "application_id": grant["data"].get("application_id"),
            "dataset_id": batch["dataset_id"],
            "recipient": grant["data"].get("recipient"),
            "policy_version": batch["new_policy_version"],
            "supersedes": grant["id"],
            "batch_id": batch["id"],
        }
        tx.create_entity(
            replacement_id, "grant", "issued", replacement, actor.user_id
        )
        tx.append_audit(
            replacement_id, actor.user_id, actor.role, "create",
            None, "issued",
            {"kind": "grant", "policy_replacement_for": grant["id"],
             "policy_version": batch["new_policy_version"],
             "batch_id": batch["id"]},
        )
        return {"result": "done",
                "detail": {"to_status": next_status},
                "replacement_grant_id": replacement_id}

    # ---- 批次查询与按数据集治理视图 ----

    def get_policy_batch(self, batch_id):
        batch = self.repository.get_policy_batch(batch_id)
        if not batch:
            raise NotFoundError("policy batch not found: " + batch_id)
        items = self.repository.list_batch_items(batch_id)
        runs = self.repository.list_batch_runs(batch_id)
        result = dict(batch)
        result["items"] = items
        result["runs"] = runs
        counts = {"pending": 0, "failed": 0, "done": 0, "skipped": 0}
        for item in items:
            counts[item["result"]] = counts.get(item["result"], 0) + 1
        result["item_counts"] = counts
        return result

    def governance_view(self, dataset_id):
        dataset = self.repository.get_entity(dataset_id)
        if not dataset or self.rules.normalize_kind(dataset["kind"]) != "dataset":
            raise NotFoundError("dataset not found: " + dataset_id)
        batches = [
            self.get_policy_batch(batch["id"])
            for batch in self.repository.list_policy_batches(dataset_id=dataset_id)
        ]
        affected_applications = []
        affected_grants = []
        for batch in batches:
            for item in batch["items"]:
                entity = self.repository.get_entity(item["entity_id"])
                entry = {
                    "batch_id": batch["id"],
                    "result": item["result"],
                    "attempts": item["attempts"],
                    "last_error": item["last_error"],
                    "entity": entity,
                }
                if item["entity_kind"] == "application":
                    affected_applications.append(entry)
                else:
                    entry["replacement_grant_id"] = item["replacement_grant_id"]
                    affected_grants.append(entry)
        return {
            "dataset": {
                "id": dataset["id"],
                "name": dataset["data"].get("name"),
                "status": dataset["status"],
                "access_policy": dataset["data"].get("access_policy"),
                "policy_version": policy_version_of(dataset["data"]),
                "policy_version_recorded": "policy_version" in dataset["data"],
                "policy_history": dataset["data"].get("policy_history", []),
            },
            "affected_applications": affected_applications,
            "affected_grants": affected_grants,
            "batches": batches,
        }

    # ---- 旧数据补录政策版本（缺失时按原政策兼容留档）----

    def backfill_policy_version(self, actor, dataset_id, data=None):
        if actor.role != "admin":
            raise PermissionDenied("only administrators can backfill policy version")
        data = data or {}
        version = int(data.get("policy_version") or ORIGINAL_POLICY_VERSION)
        note = data.get("note") or "backfill legacy records under original policy"

        backfilled = []
        with self.repository.locked() as tx:
            dataset = tx.get_entity(dataset_id)
            if not dataset:
                raise NotFoundError("dataset not found: " + dataset_id)
            dataset_missing_version = "policy_version" not in dataset["data"]
            if dataset_missing_version:
                patched = dict(dataset["data"])
                patched["policy_version"] = version
                history = list(patched.get("policy_history") or [])
                if not any(entry.get("backfilled") for entry in history):
                    history.append({
                        "version": version, "reason": note, "at": utcnow(),
                        "by": actor.user_id, "backfilled": True,
                    })
                patched["policy_history"] = history
                tx.update_entity(
                    dataset_id, dataset["version"], dataset["status"], patched
                )
                tx.append_audit(
                    dataset_id, actor.user_id, actor.role,
                    "backfill_policy_version", dataset["status"],
                    dataset["status"], {"policy_version": version, "note": note},
                )
                backfilled.append(dataset_id)

            for kind in ("application", "grant"):
                for entity in tx.find_entities(kind, "dataset_id", dataset_id):
                    if "policy_version" in entity["data"]:
                        continue
                    entity_data = dict(entity["data"])
                    entity_data["policy_version"] = version
                    entity_data["backfilled_policy_version"] = True
                    tx.update_entity(
                        entity["id"], entity["version"],
                        entity["status"], entity_data
                    )
                    tx.append_audit(
                        entity["id"], actor.user_id, actor.role,
                        "backfill_policy_version", entity["status"],
                        entity["status"], {"policy_version": version, "note": note},
                    )
                    backfilled.append(entity["id"])
        return {"policy_version": version, "backfilled": backfilled,
                "count": len(backfilled)}
