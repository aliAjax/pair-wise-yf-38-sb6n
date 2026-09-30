import threading
from uuid import uuid4

from .audit import AuditTrail
from .domain import Actor, ConflictError, NotFoundError
from .rules import RuleEngine


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)
        # Serializes policy-sensitive mutations within one process so that
        # concurrent policy changes and credential activations have a
        # well-defined "first committer wins" order.
        self._lock = threading.RLock()
        self._resume_batches()

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def _dataset_for(self, dataset_id):
        return self.repository.get_entity(dataset_id)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        with self._lock:
            payload = self.rules.validate_create(actor, kind, payload, self._lookup)
            if kind == "dataset":
                payload.setdefault("policy_version", 1)
            elif kind in ("application", "grant"):
                dataset = self._dataset_for(payload.get("dataset_id"))
                if dataset:
                    payload["policy_version"] = dataset["data"].get("policy_version", 1)
            entity_id = str(payload.pop("id", "") or uuid4())
            if self.repository.get_entity(entity_id):
                raise ConflictError("entity already exists: " + entity_id)
            status = self.rules.initial_status(kind)
            entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
            self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
            if idempotency_key:
                self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        with self._lock:
            entity = self.repository.get_entity(entity_id)
            if not entity:
                raise NotFoundError("entity not found: " + entity_id)
            expected = int(expected_version) if expected_version is not None else entity["version"]
            next_status, patch = self.rules.validate_transition(
                actor, entity, action, dict(data or {}), self._lookup
            )
            merged = dict(entity["data"])
            merged.update(patch)
            updated = self.repository.update_entity(entity_id, expected, next_status, merged)
            self.audit.record(
                entity_id,
                actor,
                action,
                entity["status"],
                updated["status"],
                {"patch": patch},
            )
            return updated

    def update_policy(self, actor, dataset_id, access_policy):
        """Admin updates a dataset access policy: bump version and run a governance batch."""
        with self._lock:
            dataset = self._dataset_for(dataset_id)
            if not dataset:
                raise NotFoundError("dataset not found: " + dataset_id)
            next_status, patch = self.rules.validate_transition(
                actor, dataset, "update_policy", {"access_policy": access_policy}, self._lookup
            )
            old_version = int(dataset["data"].get("policy_version", 1) or 1)
            merged = dict(dataset["data"])
            merged.update(patch)
            updated = self.repository.update_entity(dataset_id, dataset["version"], next_status, merged)
            new_version = int(patch["policy_version"])
            self.audit.record(
                dataset_id,
                actor,
                "policy_updated",
                dataset["status"],
                updated["status"],
                {"from_version": old_version, "to_version": new_version, "access_policy": access_policy},
            )
            batch = self._create_governance_batch(dataset_id, "policy_change", new_version, actor)
            self._populate_batch(batch, dataset_id)
            self._process_batch(batch)
            return updated

    def deactivate(self, actor, dataset_id):
        """Admin deactivates a dataset: no credential may be used; batch revokes/returns."""
        with self._lock:
            dataset = self._dataset_for(dataset_id)
            if not dataset:
                raise NotFoundError("dataset not found: " + dataset_id)
            next_status, patch = self.rules.validate_transition(
                actor, dataset, "deactivate", {}, self._lookup
            )
            merged = dict(dataset["data"])
            merged.update(patch)
            updated = self.repository.update_entity(dataset_id, dataset["version"], next_status, merged)
            self.audit.record(
                dataset_id,
                actor,
                "deactivated",
                dataset["status"],
                updated["status"],
                {"policy_version": dataset["data"].get("policy_version", 1)},
            )
            batch = self._create_governance_batch(dataset_id, "deactivation", None, actor)
            self._populate_batch(batch, dataset_id)
            self._process_batch(batch)
            return updated

    def reactivate(self, actor, dataset_id):
        """Admin reactivates a previously deactivated dataset."""
        with self._lock:
            dataset = self._dataset_for(dataset_id)
            if not dataset:
                raise NotFoundError("dataset not found: " + dataset_id)
            next_status, patch = self.rules.validate_transition(
                actor, dataset, "reactivate", {}, self._lookup
            )
            merged = dict(dataset["data"])
            merged.update(patch)
            updated = self.repository.update_entity(dataset_id, dataset["version"], next_status, merged)
            self.audit.record(
                dataset_id,
                actor,
                "reactivated",
                dataset["status"],
                updated["status"],
                {"policy_version": dataset["data"].get("policy_version", 1)},
            )
            return updated

    def backfill_policy(self, actor, dataset_id):
        """Backfill policy_version=1 on legacy data that lacks it (compatibility archive)."""
        self.rules.require_role(actor, ("admin",))
        with self._lock:
            dataset = self._dataset_for(dataset_id)
            if not dataset:
                raise NotFoundError("dataset not found: " + dataset_id)
            summary = {"dataset": 0, "applications": 0, "grants": 0}
            if "policy_version" not in dataset["data"]:
                merged = dict(dataset["data"])
                merged["policy_version"] = 1
                self.repository.update_entity(dataset_id, dataset["version"], dataset["status"], merged)
                self.audit.record(
                    dataset_id, actor, "policy_backfilled", dataset["status"], dataset["status"],
                    {"policy_version": 1},
                )
                summary["dataset"] = 1
            for app in self.repository.list_entities(kind="application"):
                if app["data"].get("dataset_id") != dataset_id:
                    continue
                if "policy_version" not in app["data"]:
                    merged = dict(app["data"])
                    merged["policy_version"] = 1
                    self.repository.update_entity(app["id"], app["version"], app["status"], merged)
                    self.audit.record(
                        app["id"], actor, "policy_backfilled", app["status"], app["status"],
                        {"policy_version": 1, "dataset_id": dataset_id},
                    )
                    summary["applications"] += 1
            for grant in self.repository.list_entities(kind="grant"):
                if grant["data"].get("dataset_id") != dataset_id:
                    continue
                if "policy_version" not in grant["data"]:
                    merged = dict(grant["data"])
                    merged["policy_version"] = 1
                    self.repository.update_entity(grant["id"], grant["version"], grant["status"], merged)
                    self.audit.record(
                        grant["id"], actor, "policy_backfilled", grant["status"], grant["status"],
                        {"policy_version": 1, "dataset_id": dataset_id},
                    )
                    summary["grants"] += 1
            return summary

    def _create_governance_batch(self, dataset_id, kind, policy_version, actor):
        batch_id = str(uuid4())
        detail = {"kind": kind, "policy_version": policy_version}
        return self.repository.create_batch(
            batch_id, dataset_id, kind, policy_version, detail, actor.user_id
        )

    def _populate_batch(self, batch, dataset_id):
        # Only in-use (active) credentials are revoked by the batch. Issued
        # credentials are not yet in use; they are invalidated at activation
        # time by the policy-version / deactivation checks instead.
        for grant in self.repository.list_entities(kind="grant"):
            if grant["data"].get("dataset_id") != dataset_id:
                continue
            if grant["status"] == "active":
                self.repository.add_batch_item(
                    batch["id"],
                    grant["id"],
                    "grant",
                    "revoke",
                    {"policy_version": grant["data"].get("policy_version", 1), "status": grant["status"]},
                )
        for app in self.repository.list_entities(kind="application"):
            if app["data"].get("dataset_id") != dataset_id:
                continue
            if app["status"] in ("submitted", "under_review"):
                self.repository.add_batch_item(
                    batch["id"],
                    app["id"],
                    "application",
                    "return",
                    {"policy_version": app["data"].get("policy_version", 1), "status": app["status"]},
                )

    def _process_batch(self, batch):
        system_actor = Actor("governance-batch", "admin")
        self.repository.update_batch_status(batch["id"], "running")
        items = self.repository.list_batch_items(batch["id"])
        for item in items:
            if item["status"] in ("processed", "skipped"):
                continue  # already handled; never redo a completed item
            if item["status"] == "failed":
                self.repository.update_batch_item(
                    item["id"], "pending", attempts=item["attempts"], last_error=None
                )
            try:
                self._process_item(batch, item, system_actor)
            except Exception as exc:
                self.repository.update_batch_item(
                    item["id"],
                    "failed",
                    attempts=item["attempts"] + 1,
                    last_error=str(exc),
                    detail={"error": str(exc)},
                )
                self.repository.update_batch_status(batch["id"], "failed", {"error": str(exc)})
                return  # stop; unprocessed items remain pending for a later retry
        self.repository.update_batch_status(batch["id"], "completed", {"processed": len(items)})

    def _process_item(self, batch, item, system_actor):
        if item["action"] == "revoke":
            self._revoke_item(batch, item, system_actor)
        elif item["action"] == "return":
            self._return_item(batch, item, system_actor)
        else:
            raise ConflictError("unknown batch item action: " + str(item["action"]))

    def _revoke_item(self, batch, item, system_actor):
        grant = self.repository.get_entity(item["entity_id"])
        if not grant:
            self.repository.update_batch_item(item["id"], "skipped", detail={"reason": "entity_missing"})
            return
        if grant["status"] in ("revoked", "expired"):
            self.repository.update_batch_item(item["id"], "skipped", detail={"reason": "already_inactive"})
            return
        if grant["status"] not in ("issued", "active"):
            self.repository.update_batch_item(
                item["id"], "skipped", detail={"reason": "not_revocable", "status": grant["status"]}
            )
            return
        next_status, patch = self.rules.validate_transition(
            system_actor,
            grant,
            "revoke",
            {"reason": "governance batch %s" % batch["kind"]},
            self._lookup,
        )
        merged = dict(grant["data"])
        merged.update(patch)
        updated = self.repository.update_entity(item["entity_id"], grant["version"], next_status, merged)
        self.audit.record(
            item["entity_id"],
            system_actor,
            "revoke",
            grant["status"],
            updated["status"],
            {"batch_id": batch["id"], "dataset_id": batch["dataset_id"], "policy_version": batch["policy_version"]},
        )
        self.repository.update_batch_item(
            item["id"], "processed",
            detail={"from_status": grant["status"], "to_status": updated["status"]},
        )

    def _return_item(self, batch, item, system_actor):
        app = self.repository.get_entity(item["entity_id"])
        if not app:
            self.repository.update_batch_item(item["id"], "skipped", detail={"reason": "entity_missing"})
            return
        if app["status"] not in ("submitted", "under_review"):
            self.repository.update_batch_item(
                item["id"], "skipped", detail={"reason": "not_pending", "status": app["status"]}
            )
            return
        next_status, patch = self.rules.validate_transition(
            system_actor, app, "return", {}, self._lookup
        )
        merged = dict(app["data"])
        merged.update(patch)
        updated = self.repository.update_entity(item["entity_id"], app["version"], next_status, merged)
        self.audit.record(
            item["entity_id"],
            system_actor,
            "return",
            app["status"],
            updated["status"],
            {
                "batch_id": batch["id"],
                "dataset_id": batch["dataset_id"],
                "returned_from_policy": patch.get("returned_from_policy"),
            },
        )
        self.repository.update_batch_item(
            item["id"], "processed",
            detail={"from_status": app["status"], "to_status": updated["status"]},
        )

    def _resume_batches(self):
        try:
            batches = self.repository.list_incomplete_batches()
        except Exception:
            return
        for batch in batches:
            try:
                self._process_batch(batch)
            except Exception:
                continue

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)

    def dataset_governance(self, dataset_id):
        dataset = self.repository.get_entity(dataset_id)
        if not dataset:
            raise NotFoundError("dataset not found: " + dataset_id)
        policy_versions = []
        for record in self.repository.list_audit(entity_id=dataset_id):
            if record["action"] in ("policy_updated", "policy_backfilled"):
                policy_versions.append({
                    "action": record["action"],
                    "at": record["created_at"],
                    "by": record["actor_id"],
                    "detail": record["detail"],
                })
        batches = []
        for batch in self.repository.list_batches(dataset_id=dataset_id):
            items = self.repository.list_batch_items(batch["id"])
            failures = [i for i in items if i["status"] == "failed"]
            retries = [i for i in items if i["attempts"] > 1]
            batches.append({
                "id": batch["id"],
                "kind": batch["kind"],
                "status": batch["status"],
                "policy_version": batch["policy_version"],
                "created_by": batch["created_by"],
                "created_at": batch["created_at"],
                "detail": batch["detail"],
                "items": [
                    {
                        "entity_id": i["entity_id"],
                        "entity_kind": i["entity_kind"],
                        "action": i["action"],
                        "status": i["status"],
                        "attempts": i["attempts"],
                        "last_error": i["last_error"],
                        "detail": i["detail"],
                    }
                    for i in items
                ],
                "failures": [
                    {
                        "entity_id": i["entity_id"],
                        "entity_kind": i["entity_kind"],
                        "action": i["action"],
                        "attempts": i["attempts"],
                        "error": i["last_error"],
                    }
                    for i in failures
                ],
                "retries": [
                    {
                        "entity_id": i["entity_id"],
                        "entity_kind": i["entity_kind"],
                        "action": i["action"],
                        "attempts": i["attempts"],
                    }
                    for i in retries
                ],
            })
        return {
            "dataset": {
                "id": dataset["id"],
                "name": dataset["data"].get("name"),
                "access_policy": dataset["data"].get("access_policy"),
                "policy_version": int(dataset["data"].get("policy_version", 1) or 1),
                "deactivated": bool(dataset["data"].get("deactivated", False)),
                "status": dataset["status"],
            },
            "policy_versions": policy_versions,
            "batches": batches,
        }
