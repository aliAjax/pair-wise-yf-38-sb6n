import tempfile
import unittest
from pathlib import Path

from src.domain import (
    Actor,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)
from src.repository import SQLiteRepository
from src.rules import ORIGINAL_POLICY_VERSION, RuleEngine, policy_version_of
from src.service import DomainService


def make_service():
    tmp = tempfile.TemporaryDirectory()
    repo = SQLiteRepository(Path(tmp.name) / "policy.db")
    return DomainService(repo, RuleEngine()), tmp


def approved_dataset(service, admin, committee, *, grants=0, pending=0):
    """造一个含已批准申请、在用凭证与待审批申请的数据集。"""
    ds = service.create(
        admin, "dataset", {"name": "Cohort", "access_policy": "policy-v1"}
    )
    app = service.create(
        admin, "application",
        {"dataset_id": ds["id"], "applicant_id": "u0", "purpose": "analysis"},
    )
    service.transition(admin, app["id"], "submit", {})
    service.transition(committee, app["id"], "review", {"committee_id": "c1"})
    service.transition(
        committee, app["id"], "approve",
        {"approvals": ["r1", "r2", "r3"], "terms": "nc",
         "expires_at": "2099-01-01"},
    )
    grant_ids = []
    for i in range(grants):
        grant = service.create(
            admin, "grant",
            {"application_id": app["id"], "dataset_id": ds["id"],
             "recipient": "rec-%d" % i},
        )
        grant_ids.append(grant["id"])
    pending_ids = []
    for i in range(pending):
        pend = service.create(
            admin, "application",
            {"dataset_id": ds["id"], "applicant_id": "p%d" % i,
             "purpose": "pending work"},
        )
        service.transition(admin, pend["id"], "submit", {})
        pending_ids.append(pend["id"])
    return ds, app, grant_ids, pending_ids


class PolicyBatchTest(unittest.TestCase):
    def setUp(self):
        self.service, self.tmp = make_service()
        self.admin = Actor("admin-1", "admin")
        self.committee = Actor("cm-1", "committee")

    def tearDown(self):
        self.tmp.cleanup()

    def test_policy_change_revokes_old_grants_and_returns_pending_applications(self):
        service = self.service
        ds, app, grant_ids, pending = approved_dataset(
            service, self.admin, self.committee, grants=2, pending=2
        )
        active = service.transition(
            self.committee, grant_ids[0], "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )
        self.assertEqual(active["status"], "active")

        batch = service.update_policy(
            self.admin, ds["id"],
            {"access_policy": "policy-v2", "reason": "annual review"},
        )

        # 政策版本立即更新
        self.assertEqual(batch["status"], "completed")
        dataset = service.get(ds["id"])
        self.assertEqual(dataset["data"]["policy_version"], 2)
        self.assertEqual(dataset["data"]["access_policy"], "policy-v2")

        # 待审批申请退回复核
        for app_id in pending:
            self.assertEqual(
                service.get(app_id)["status"], "returned_for_review"
            )

        # 旧凭证（在用 active 与待激活 issued）全部吊销，且有新版本凭证
        for grant_id in grant_ids:
            old = service.get(grant_id)
            self.assertEqual(old["status"], "revoked_policy_change")
            replacement = service.get(old["data"]["superseded_by"])
            self.assertEqual(replacement["status"], "issued")
            self.assertEqual(
                replacement["data"]["policy_version"], 2
            )
            self.assertEqual(replacement["data"]["supersedes"], grant_id)

        # 旧版凭证的晚到激活按新政策拒绝，不留旧政策凭证
        with self.assertRaises(InvalidTransition):
            service.transition(
                self.committee, grant_ids[0], "activate",
                {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
            )

        # 新版本凭证可按正常流程激活
        old_active = service.get(grant_ids[0])
        new_grant = service.get(old_active["data"]["superseded_by"])
        activated = service.transition(
            self.committee, new_grant["id"], "activate",
            {"starts_at": "2026-02-01", "expires_at": "2099-01-01"},
        )
        self.assertEqual(activated["status"], "active")

        # 退回的申请复核后重新提交，按新政策盖章
        resubmitted = service.transition(
            self.admin, pending[0], "resubmit", {}
        )
        self.assertEqual(resubmitted["status"], "submitted")
        self.assertEqual(resubmitted["data"]["policy_version"], 2)

    def test_only_admin_can_change_policy(self):
        service = self.service
        ds, _, _, _ = approved_dataset(
            service, self.admin, self.committee
        )
        with self.assertRaises(PermissionDenied):
            service.update_policy(
                self.committee, ds["id"],
                {"access_policy": "policy-v2", "reason": "x"},
            )

    def test_governance_view_and_dataset_audit(self):
        service = self.service
        ds, _, grant_ids, pending = approved_dataset(
            service, self.admin, self.committee, grants=1, pending=1
        )
        batch = service.update_policy(
            self.admin, ds["id"],
            {"access_policy": "policy-v2", "reason": "review"},
        )
        view = service.governance_view(ds["id"])
        self.assertEqual(view["dataset"]["policy_version"], 2)
        self.assertEqual(len(view["affected_applications"]), 1)
        self.assertEqual(len(view["affected_grants"]), 1)
        self.assertEqual(view["batches"][0]["id"], batch["id"])
        self.assertEqual(
            view["affected_grants"][0]["replacement_grant_id"],
            service.get(grant_ids[0])["data"]["superseded_by"],
        )

        audit = service.audit_log(dataset_id=ds["id"])
        actions = {row["action"] for row in audit}
        self.assertIn("update_policy", actions)
        self.assertIn("policy_batch_opened", actions)
        self.assertIn("policy_batch_run", actions)
        self.assertIn("return_for_review", actions)
        self.assertIn("revoke_policy_change", actions)
        # 新版本凭证的签发也在该数据集的审计时间线上
        replacement_rows = [
            row for row in audit if row["action"] == "create"
        ]
        self.assertTrue(replacement_rows)

    def test_view_unknown_dataset_raises_not_found(self):
        from src.domain import NotFoundError
        with self.assertRaises(NotFoundError):
            self.service.governance_view("missing")


class BatchFailureRetryTest(unittest.TestCase):
    def setUp(self):
        self.service, self.tmp = make_service()
        self.admin = Actor("admin-1", "admin")
        self.committee = Actor("cm-1", "committee")

    def tearDown(self):
        self.tmp.cleanup()

    def test_failed_items_are_retained_and_retried_without_revoking_twice(self):
        service = self.service
        ds, _, _, pending = approved_dataset(
            service, self.admin, self.committee, pending=3
        )

        calls = {"count": 0}

        def hook(batch, item):
            calls["count"] += 1
            if calls["count"] == 2:
                raise RuntimeError("simulated processing failure")

        service.item_hook = hook
        batch = service.update_policy(
            self.admin, ds["id"],
            {"access_policy": "policy-v2", "reason": "review"},
        )
        self.assertEqual(batch["status"], "failed")

        items = service.get_policy_batch(batch["id"])["items"]
        failed = [item for item in items if item["result"] == "failed"]
        self.assertEqual(len(failed), 1)
        # 失败条目事务回滚：申请仍是旧状态，未被部分处理
        failed_entity = service.get(failed[0]["entity_id"])
        self.assertEqual(failed_entity["status"], "submitted")

        # 已处理对象不能重复处理：重试只做未完成条目
        service.item_hook = None
        retry = service.retry_policy_batch(self.admin, batch["id"])
        self.assertEqual(retry["status"], "completed")
        attempts = sorted(item["attempts"] for item in
                          service.get_policy_batch(batch["id"])["items"])
        self.assertEqual(attempts, [1, 1, 2])
        for app_id in pending:
            self.assertEqual(
                service.get(app_id)["status"], "returned_for_review"
            )

        runs = service.get_policy_batch(batch["id"])["runs"]
        self.assertEqual([run["run_type"] for run in runs],
                         ["initial", "retry"])

        # 批次完成后再重试是空操作
        again = service.retry_policy_batch(self.admin, batch["id"])
        self.assertEqual(again["runs"][-1]["processed"], 0)

    def test_retry_requires_admin(self):
        service = self.service
        ds, _, _, _ = approved_dataset(
            service, self.admin, self.committee
        )
        batch = service.update_policy(
            self.admin, ds["id"],
            {"access_policy": "policy-v2", "reason": "review"},
        )
        with self.assertRaises(PermissionDenied):
            service.retry_policy_batch(self.committee, batch["id"])

    def test_restart_only_resumes_interrupted_batch(self):
        service = self.service
        ds, _, _, pending = approved_dataset(
            service, self.admin, self.committee, pending=2
        )
        batch = service.update_policy(
            self.admin, ds["id"],
            {"access_policy": "policy-v2", "reason": "review"},
        )
        # 已完成批次重启时不重做
        self.assertEqual(service.resume_on_startup(), [])

        # 模拟进程在批次中途崩溃：批次留在 processing
        service.repository.set_policy_batch_status(batch["id"], "processing")
        new_service = DomainService(service.repository, RuleEngine())
        resumed = new_service.resume_on_startup()
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0]["id"], batch["id"])
        self.assertEqual(resumed[0]["status"], "completed")
        # 已处理对象没有重复处理
        for item in new_service.get_policy_batch(batch["id"])["items"]:
            self.assertEqual(item["attempts"], 1)
        # 再重启无事可做
        self.assertEqual(new_service.resume_on_startup(), [])

    def test_item_becomes_skipped_when_state_changed_concurrently(self):
        service = self.service
        ds, app, _, pending = approved_dataset(
            service, self.admin, self.committee, pending=1
        )
        pend_id = pending[0]
        # 政策提交（批次登记）后、条目处理前，申请已被撤回。
        # update_policy 在同一事务里登记条目后立刻逐条处理，因此这里通过
        # 在政策提交前先撤回申请来复现“登记时在处理、处理时已不待审批”的竞态：
        # 撤回的申请不属于受影响集合；为直接验证处理期竞态，改为对一个
        # 提交后即处于非待审批终态的申请检查 skip：此处用 grant 过期场景。
        service.transition(self.admin, pend_id, "withdraw",
                           {"reason": "changed mind"})
        batch = service.update_policy(
            self.admin, ds["id"],
            {"access_policy": "policy-v2", "reason": "review"},
        )
        # 撤回的申请不在批次范围内，批次只处理其余对象（无待审批、无在用凭证）
        self.assertEqual(batch["status"], "completed")
        self.assertEqual(service.get(pend_id)["status"], "withdrawn")
        self.assertEqual(batch["item_counts"]["done"], 0)

        # 直接构造“批次条目存在、但对象已不处于可处理状态”的处理期竞态：
        # 新增一个待审批申请，手工登记批次条目，再在处理前撤回。
        second = service.create(
            self.admin, "application",
            {"dataset_id": ds["id"], "applicant_id": "late",
             "purpose": "raced"},
        )
        service.transition(self.admin, second["id"], "submit", {})
        race_batch_id = "batch-race"
        with service.repository.locked() as tx:
            tx.insert_policy_batch(
                race_batch_id, ds["id"], 2, 3, "policy-v3", "review",
                self.admin.user_id,
            )
            tx.insert_batch_item(race_batch_id, second["id"],
                                 "application", "submitted")
        service.transition(self.admin, second["id"], "withdraw",
                           {"reason": "raced withdrawal"})
        result = service.retry_policy_batch(self.admin, race_batch_id)
        self.assertEqual(result["status"], "completed")
        item = service.get_policy_batch(race_batch_id)["items"][0]
        self.assertEqual(item["result"], "skipped")
        self.assertEqual(service.get(second["id"])["status"], "withdrawn")


class DeactivationConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.service, self.tmp = make_service()
        self.admin = Actor("admin-1", "admin")
        self.committee = Actor("cm-1", "committee")

    def tearDown(self):
        self.tmp.cleanup()

    def _fresh_issued_grant(self):
        ds, app, grant_ids, _ = approved_dataset(
            self.service, self.admin, self.committee, grants=1
        )
        return ds, self.service.get(grant_ids[0])

    def test_deactivate_first_late_activation_refused(self):
        service = self.service
        ds, grant = self._fresh_issued_grant()
        service.transition(self.admin, ds["id"], "deactivate",
                           {"reason": "incident"})
        with self.assertRaises(PermissionDenied):
            service.transition(
                self.committee, grant["id"], "activate",
                {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
            )
        self.assertEqual(service.get(grant["id"])["status"], "issued")

    def test_activation_first_late_deactivation_refused(self):
        service = self.service
        ds, grant = self._fresh_issued_grant()
        service.transition(
            self.committee, grant["id"], "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )
        with self.assertRaises(InvalidTransition):
            service.transition(self.admin, ds["id"], "deactivate",
                               {"reason": "late"})
        self.assertEqual(service.get(ds["id"])["status"], "registered")

    def test_committee_cannot_bypass_admin_deactivation(self):
        service = self.service
        ds, grant = self._fresh_issued_grant()
        service.transition(self.admin, ds["id"], "deactivate",
                           {"reason": "admin decision"})
        # 委员会不能停用/恢复数据集
        with self.assertRaises(PermissionDenied):
            service.transition(self.committee, ds["id"], "reactivate",
                               {"reason": "override"})
        # 委员会也不能在停用数据集上签发或激活凭证
        with self.assertRaises(PermissionDenied):
            service.create(
                self.committee, "grant",
                {"application_id": grant["data"]["application_id"],
                 "dataset_id": ds["id"], "recipient": "x"},
            )

    def test_admin_can_revoke_then_deactivate(self):
        service = self.service
        ds, grant = self._fresh_issued_grant()
        service.transition(
            self.committee, grant["id"], "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )
        service.transition(self.committee, grant["id"], "revoke",
                           {"reason": "pre-deactivation"})
        service.transition(self.admin, ds["id"], "deactivate",
                           {"reason": "now clean"})
        self.assertEqual(service.get(ds["id"])["status"], "deactivated")


class LegacyBackfillTest(unittest.TestCase):
    def setUp(self):
        self.service, self.tmp = make_service()
        self.admin = Actor("admin-1", "admin")

    def tearDown(self):
        self.tmp.cleanup()

    def test_legacy_records_default_to_original_policy_and_can_be_backfilled(self):
        service = self.service
        repo = service.repository
        repo.create_entity(
            "legacy-ds", "dataset", "registered",
            {"name": "Legacy", "access_policy": "old-text"}, "admin",
        )
        repo.create_entity(
            "legacy-app", "application", "submitted",
            {"dataset_id": "legacy-ds", "applicant_id": "u", "purpose": "p"},
            "admin",
        )
        repo.create_entity(
            "legacy-grant", "grant", "active",
            {"dataset_id": "legacy-ds", "application_id": "legacy-app",
             "recipient": "r"}, "admin",
        )

        # 缺失政策版本：按原政策兼容留档，不报错
        view = service.governance_view("legacy-ds")
        self.assertFalse(view["dataset"]["policy_version_recorded"])
        self.assertEqual(
            view["dataset"]["policy_version"], ORIGINAL_POLICY_VERSION
        )
        self.assertEqual(
            policy_version_of(service.get("legacy-grant")["data"]),
            ORIGINAL_POLICY_VERSION,
        )

        result = service.backfill_policy_version(
            self.admin, "legacy-ds", {"note": "archive migration"}
        )
        self.assertEqual(result["count"], 3)
        self.assertEqual(
            service.get("legacy-ds")["data"]["policy_version"], 1
        )
        self.assertTrue(
            service.get("legacy-app")["data"]["backfilled_policy_version"]
        )

        # 补录幂等：再次执行不改动任何对象
        again = service.backfill_policy_version(
            self.admin, "legacy-ds", {}
        )
        self.assertEqual(again["count"], 0)

    def test_backfill_requires_admin(self):
        service = self.service
        service.repository.create_entity(
            "legacy-ds", "dataset", "registered",
            {"name": "Legacy", "access_policy": "old-text"}, "admin",
        )
        with self.assertRaises(PermissionDenied):
            service.backfill_policy_version(
                Actor("cm", "committee"), "legacy-ds", {}
            )

    def test_backfilled_legacy_records_are_swept_by_later_batch(self):
        service = self.service
        repo = service.repository
        repo.create_entity(
            "legacy-ds", "dataset", "registered",
            {"name": "Legacy", "access_policy": "old-text"}, "admin",
        )
        repo.create_entity(
            "legacy-app", "application", "submitted",
            {"dataset_id": "legacy-ds", "applicant_id": "u", "purpose": "p"},
            "admin",
        )
        repo.create_entity(
            "legacy-grant", "grant", "active",
            {"dataset_id": "legacy-ds", "application_id": "legacy-app",
             "recipient": "r"}, "admin",
        )
        service.backfill_policy_version(self.admin, "legacy-ds", {})
        batch = service.update_policy(
            self.admin, "legacy-ds",
            {"access_policy": "new-text", "reason": "modernize"},
        )
        self.assertEqual(batch["status"], "completed")
        self.assertEqual(batch["item_counts"]["done"], 2)
        self.assertEqual(
            service.get("legacy-app")["status"], "returned_for_review"
        )
        self.assertEqual(
            service.get("legacy-grant")["status"], "revoked_policy_change"
        )

    def test_policy_change_validates_new_policy(self):
        service = self.service
        ds = service.create(
            self.admin, "dataset", {"name": "D", "access_policy": "pol-1"}
        )
        with self.assertRaises(ValidationError):
            service.update_policy(
                self.admin, ds["id"], {"access_policy": "x", "reason": "r"}
            )


if __name__ == "__main__":
    unittest.main()
