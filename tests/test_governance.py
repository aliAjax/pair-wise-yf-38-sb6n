import tempfile
import unittest
from pathlib import Path

from src.domain import Actor, ConflictError, PermissionDenied
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class GovernanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.admin = Actor("admin", "admin")
        self.committee = Actor("committee", "committee")
        self.applicant = Actor("applicant", "applicant")

    def tearDown(self):
        self.tmp.cleanup()

    def _setup(self):
        dataset = self.service.create(
            self.admin, "dataset", {"name": "Rare Disease Cohort", "access_policy": "controlled"}
        )
        app = self.service.create(
            self.admin,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": "APP-1", "purpose": "variant analysis"},
        )
        self.service.transition(self.admin, app["id"], "submit", {})
        self.service.transition(self.admin, app["id"], "review", {"committee_id": "committee-a"})
        self.service.transition(
            self.admin,
            app["id"],
            "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "noncommercial", "expires_at": "2099-01-01"},
        )
        grant = self.service.create(
            self.admin,
            "grant",
            {"application_id": app["id"], "dataset_id": dataset["id"], "recipient": "researcher-1"},
        )
        self.service.transition(
            self.admin,
            grant["id"],
            "activate",
            {"starts_at": "2026-09-24", "expires_at": "2099-01-01"},
        )
        return dataset, app, grant

    def _new_application(self, dataset_id, applicant_id="APP-2"):
        app = self.service.create(
            self.admin,
            "application",
            {"dataset_id": dataset_id, "applicant_id": applicant_id, "purpose": "follow-up"},
        )
        self.service.transition(self.admin, app["id"], "submit", {})
        self.service.transition(self.admin, app["id"], "review", {"committee_id": "committee-a"})
        return app

    def _activate(self, actor, grant_id):
        return self.service.transition(
            actor,
            grant_id,
            "activate",
            {"starts_at": "2026-09-24", "expires_at": "2099-01-01"},
        )

    def test_policy_update_revokes_active_grant_and_returns_pending_app(self):
        dataset, app, grant = self._setup()
        # a second, still-pending application
        pending = self._new_application(dataset["id"])

        updated = self.service.update_policy(self.admin, dataset["id"], "controlled-v2")

        self.assertEqual(updated["data"]["policy_version"], 2)
        self.assertEqual(self.service.get(grant["id"])["status"], "revoked")
        self.assertEqual(self.service.get(pending["id"])["status"], "submitted")
        # the already-approved application is not returned
        self.assertEqual(self.service.get(app["id"])["status"], "approved")

        batches = self.service.repository.list_batches(dataset_id=dataset["id"])
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0]["status"], "completed")
        self.assertEqual(batches[0]["kind"], "policy_change")
        items = self.service.repository.list_batch_items(batches[0]["id"])
        actions = {(i["entity_id"], i["action"]) for i in items}
        self.assertIn((grant["id"], "revoke"), actions)
        self.assertIn((pending["id"], "return"), actions)
        for item in items:
            self.assertEqual(item["status"], "processed")

    def test_late_grant_activation_after_policy_update_is_rejected(self):
        dataset, app, grant = self._setup()
        # grant is issued but not active; policy changes before activation
        issued = self.service.create(
            self.admin,
            "grant",
            {"application_id": app["id"], "dataset_id": dataset["id"], "recipient": "researcher-2"},
        )
        self.assertEqual(issued["status"], "issued")

        self.service.update_policy(self.admin, dataset["id"], "controlled-v2")

        with self.assertRaises(ConflictError):
            self._activate(self.admin, issued["id"])
        self.assertEqual(self.service.get(issued["id"])["status"], "issued")

    def test_activation_then_policy_update_revokes_grant(self):
        dataset, app, grant = self._setup()
        # activate a second grant first, then change policy
        second = self.service.create(
            self.admin,
            "grant",
            {"application_id": app["id"], "dataset_id": dataset["id"], "recipient": "researcher-2"},
        )
        self._activate(self.admin, second["id"])
        self.assertEqual(self.service.get(second["id"])["status"], "active")

        self.service.update_policy(self.admin, dataset["id"], "controlled-v2")

        self.assertEqual(self.service.get(second["id"])["status"], "revoked")

    def test_deactivate_blocks_committee_activation_and_approval(self):
        dataset, app, grant = self._setup()
        issued = self.service.create(
            self.admin,
            "grant",
            {"application_id": app["id"], "dataset_id": dataset["id"], "recipient": "researcher-2"},
        )
        self.service.deactivate(self.admin, dataset["id"])
        self.assertEqual(self.service.get(grant["id"])["status"], "revoked")

        # committee cannot bypass the admin deactivation decision
        with self.assertRaises(PermissionDenied):
            self._activate(self.committee, issued["id"])

        pending = self._new_application(dataset["id"])
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                self.committee,
                pending["id"],
                "approve",
                {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"},
            )

        # admin reactivates; committee can now activate
        self.service.reactivate(self.admin, dataset["id"])
        self._activate(self.committee, issued["id"])
        self.assertEqual(self.service.get(issued["id"])["status"], "active")

    def test_committee_cannot_update_or_deactivate_policy(self):
        dataset, app, grant = self._setup()
        with self.assertRaises(PermissionDenied):
            self.service.update_policy(self.committee, dataset["id"], "controlled-v2")
        with self.assertRaises(PermissionDenied):
            self.service.deactivate(self.committee, dataset["id"])

    def test_batch_failure_then_retry_processes_pending_only(self):
        dataset, app, grant = self._setup()
        pending = self._new_application(dataset["id"])

        original = self.service._revoke_item
        state = {"calls": 0}

        def failing_revoke(batch, item, system_actor):
            state["calls"] += 1
            if state["calls"] == 1:
                raise RuntimeError("simulated failure")
            return original(batch, item, system_actor)

        self.service._revoke_item = failing_revoke
        self.service.update_policy(self.admin, dataset["id"], "controlled-v2")

        # batch failed; grant still active; application item not attempted
        self.assertEqual(self.service.get(grant["id"])["status"], "active")
        batches = self.repo.list_batches(dataset_id=dataset["id"])
        self.assertEqual(batches[-1]["status"], "failed")
        items = self.repo.list_batch_items(batches[-1]["id"])
        statuses = {i["entity_id"]: i["status"] for i in items}
        self.assertEqual(statuses[grant["id"]], "failed")
        self.assertEqual(statuses[pending["id"]], "pending")

        # retry: failed item is re-run, pending item is processed, nothing redone
        self.service._revoke_item = original
        self.service._process_batch(batches[-1])

        self.assertEqual(self.service.get(grant["id"])["status"], "revoked")
        self.assertEqual(self.service.get(pending["id"])["status"], "submitted")
        items = self.repo.list_batch_items(batches[-1]["id"])
        for item in items:
            self.assertIn(item["status"], ("processed", "skipped"))
        self.assertEqual(self.repo.get_batch(batches[-1]["id"])["status"], "completed")

    def test_processed_items_are_not_revoked_twice(self):
        dataset, app, grant = self._setup()
        self.service.update_policy(self.admin, dataset["id"], "controlled-v2")
        batch = self.repo.list_batches(dataset_id=dataset["id"])[-1]
        self.assertEqual(batch["status"], "completed")
        self.assertEqual(self.service.get(grant["id"])["status"], "revoked")

        # re-running the same batch must not revoke again
        self.service._process_batch(batch)
        items = self.repo.list_batch_items(batch["id"])
        self.assertEqual(items[0]["status"], "processed")
        revoke_audits = [a for a in self.service.audit_log(grant["id"]) if a["action"] == "revoke"]
        self.assertEqual(len(revoke_audits), 1)

    def test_already_inactive_grant_is_skipped(self):
        dataset, app, grant = self._setup()
        self.service.transition(self.admin, grant["id"], "revoke", {"reason": "manual"})
        batch = self.service._create_governance_batch(dataset["id"], "policy_change", 2, self.admin)
        self.repo.add_batch_item(batch["id"], grant["id"], "grant", "revoke", {})
        self.service._process_batch(batch)
        items = self.repo.list_batch_items(batch["id"])
        self.assertEqual(items[0]["status"], "skipped")
        self.assertEqual(items[0]["detail"]["reason"], "already_inactive")

    def test_resume_on_restart_continues_pending_items(self):
        dataset, app, grant = self._setup()
        batch = self.service._create_governance_batch(dataset["id"], "policy_change", 2, self.admin)
        self.repo.add_batch_item(batch["id"], grant["id"], "grant", "revoke", {})
        self.assertEqual(self.service.get(grant["id"])["status"], "active")

        # simulate a process restart with a new service on the same database
        restarted = DomainService(self.repo, RuleEngine())
        self.assertEqual(restarted.get(grant["id"])["status"], "revoked")
        items = restarted.repository.list_batch_items(batch["id"])
        self.assertEqual(items[0]["status"], "processed")

    def test_governance_audit_shows_versions_items_failures_retries(self):
        dataset, app, grant = self._setup()
        self.service.update_policy(self.admin, dataset["id"], "controlled-v2")
        self.service.deactivate(self.admin, dataset["id"])

        view = self.service.dataset_governance(dataset["id"])
        self.assertEqual(view["dataset"]["policy_version"], 2)
        self.assertTrue(view["dataset"]["deactivated"])
        self.assertGreaterEqual(len(view["policy_versions"]), 1)
        actions = {v["action"] for v in view["policy_versions"]}
        self.assertIn("policy_updated", actions)
        self.assertEqual(len(view["batches"]), 2)
        for batch in view["batches"]:
            self.assertIn("items", batch)
            self.assertIn("failures", batch)
            self.assertIn("retries", batch)
            for item in batch["items"]:
                self.assertIn(item["entity_kind"], ("grant", "application"))

    def test_legacy_data_without_policy_version_defaults_and_backfills(self):
        # legacy dataset created before policy versioning
        dataset = self.service.create(
            self.admin, "dataset", {"name": "Legacy", "access_policy": "controlled"}
        )
        # strip policy_version to simulate legacy data
        data = dict(dataset["data"])
        del data["policy_version"]
        self.repo.update_entity(dataset["id"], dataset["version"], dataset["status"], data)

        # governance view treats missing version as the original policy (v1)
        view = self.service.dataset_governance(dataset["id"])
        self.assertEqual(view["dataset"]["policy_version"], 1)

        summary = self.service.backfill_policy(self.admin, dataset["id"])
        self.assertEqual(summary["dataset"], 1)
        self.assertEqual(self.service.get(dataset["id"])["data"]["policy_version"], 1)
        # backfill is recorded in audit
        view = self.service.dataset_governance(dataset["id"])
        self.assertTrue(any(v["action"] == "policy_backfilled" for v in view["policy_versions"]))

    def test_legacy_application_and_grant_backfill(self):
        dataset = self.service.create(
            self.admin, "dataset", {"name": "Legacy", "access_policy": "controlled"}
        )
        app = self.service.create(
            self.admin,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": "APP-1", "purpose": "research"},
        )
        grant = self.service.create(
            self.admin,
            "grant",
            {"application_id": app["id"], "dataset_id": dataset["id"], "recipient": "r1"},
        )
        # strip policy_version from all three
        for entity in (dataset, app, grant):
            data = dict(entity["data"])
            data.pop("policy_version", None)
            self.repo.update_entity(entity["id"], entity["version"], entity["status"], data)

        summary = self.service.backfill_policy(self.admin, dataset["id"])
        self.assertEqual(summary["dataset"], 1)
        self.assertEqual(summary["applications"], 1)
        self.assertEqual(summary["grants"], 1)
        for entity_id in (dataset["id"], app["id"], grant["id"]):
            self.assertEqual(self.service.get(entity_id)["data"]["policy_version"], 1)

    def test_policy_update_generates_new_version(self):
        dataset, _, _ = self._setup()
        self.assertEqual(self.service.get(dataset["id"])["data"]["policy_version"], 1)
        self.service.update_policy(self.admin, dataset["id"], "controlled-v2")
        self.assertEqual(self.service.get(dataset["id"])["data"]["policy_version"], 2)
        self.service.update_policy(self.admin, dataset["id"], "controlled-v3")
        self.assertEqual(self.service.get(dataset["id"])["data"]["policy_version"], 3)


if __name__ == "__main__":
    unittest.main()
