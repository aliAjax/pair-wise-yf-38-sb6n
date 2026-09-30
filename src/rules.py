from datetime import datetime, timedelta

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


# 政策版本约定：旧数据缺少政策版本时按原政策（第 1 版）兼容留档。
ORIGINAL_POLICY_VERSION = 1


def policy_version_of(entity_data):
    """返回实体数据上记录的政策版本；缺失时按原政策兼容。"""
    raw = entity_data.get("policy_version")
    if raw is None:
        return ORIGINAL_POLICY_VERSION
    return int(raw)


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _require_active_dataset(dataset, action_label):
    if not dataset:
        raise ValidationError("dataset does not exist")
    if dataset["status"] == "deactivated" or dataset["data"].get("deactivated"):
        raise PermissionDenied(
            "dataset is deactivated by administrator; %s is refused" % action_label
        )
    return dataset


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")


def _validate_application_submit(actor, entity, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", entity["data"].get("dataset_id"))
    _require_active_dataset(dataset, "submit")
    # 提交（含退回后重新提交）时按数据集当前政策版本盖章，不能沿用旧政策。
    return {"policy_version": policy_version_of(dataset["data"])}


def _validate_application_resubmit(actor, entity, data, lookup):
    return _validate_application_submit(actor, entity, data, lookup)


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")


def _validate_grant(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    _require_active_dataset(dataset, "grant issuance")
    return {"policy_version": policy_version_of(dataset["data"])}


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    dataset = _find_one(lookup, "dataset", "id", entity["data"].get("dataset_id"))
    _require_active_dataset(dataset, "activation")
    grant_version = policy_version_of(entity["data"])
    current_version = policy_version_of(dataset["data"])
    if grant_version != current_version:
        # 政策更新后旧版凭证立即失效，晚到的激活按新政策拒绝。
        raise InvalidTransition(
            "grant policy_version %s does not match current policy_version %s"
            % (grant_version, current_version)
        )
    return {"activated_by": actor.user_id}


def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate_dataset_deactivate(actor, entity, data, lookup):
    # 停用与激活并发时：若激活已先提交为当前事实，晚到的停用按新事实拒绝，
    # 避免在已停用数据集上留下已生效的在用凭证。
    active = (lookup or (lambda *a: []))("grant", "dataset_id", entity["id"])
    active = [grant for grant in active if grant["status"] == "active"]
    if active:
        raise InvalidTransition(
            "cannot deactivate: %d active grant(s) already committed; "
            "revoke them before deactivation" % len(active)
        )
    return {"deactivated_at": _now_iso()}


CUSTOM_CREATE = {
    'dataset': _validate_dataset,
    'application': _validate_application,
    'grant': _validate_grant,
}
CUSTOM_TRANSITIONS = {
    ('dataset', 'deactivate'): _validate_dataset_deactivate,
    ('application', 'submit'): _validate_application_submit,
    ('application', 'resubmit'): _validate_application_resubmit,
    ('application', 'approve'): _validate_approve,
    ('grant', 'activate'): _validate_grant_activate,
}


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant',
               'policy_batches': 'policy_batch'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued'}
    TRANSITIONS = {
        'dataset': {
            'restrict': (('registered',), 'restricted'),
            'publish': (('restricted',), 'published'),
            # 管理员（委员会不可）的停用/恢复决定。
            'deactivate': (('registered', 'restricted', 'published'), 'deactivated'),
            'reactivate': (('deactivated',), 'restricted'),
        },
        'application': {
            'submit': (('draft',), 'submitted'),
            'review': (('submitted',), 'under_review'),
            'approve': (('under_review',), 'approved'),
            'reject': (('under_review',), 'rejected'),
            'withdraw': (('submitted', 'under_review'), 'withdrawn'),
            # 治理批次把旧政策下待审批申请退回复核；复核后按新政策重新提交。
            'return_for_review': (
                ('submitted', 'under_review'), 'returned_for_review'
            ),
            'resubmit': (('returned_for_review',), 'submitted'),
        },
        'grant': {
            'activate': (('issued',), 'active'),
            'revoke': (('active',), 'revoked'),
            'expire': (('active',), 'expired'),
            # 政策治理动作：在用与待激活凭证一并吊销并由新版本凭证取代。
            'revoke_policy_change': (
                ('active', 'issued'), 'revoked_policy_change'
            ),
        },
    }
    CREATE_REQUIRED = {'dataset': ('name', 'access_policy'), 'application': ('dataset_id', 'applicant_id', 'purpose'), 'grant': ('application_id', 'dataset_id', 'recipient')}
    ACTION_REQUIRED = {('dataset', 'restrict'): ('reason',), ('dataset', 'deactivate'): ('reason',), ('dataset', 'reactivate'): ('reason',), ('application', 'review'): ('committee_id',), ('application', 'approve'): ('approvals', 'terms', 'expires_at'), ('application', 'reject'): ('reason',), ('application', 'withdraw'): ('reason',), ('application', 'return_for_review'): ('reason',), ('grant', 'activate'): ('starts_at', 'expires_at'), ('grant', 'revoke'): ('reason',), ('grant', 'revoke_policy_change'): ('reason',), ('grant', 'expire'): ('expired_at',)}

    CREATE_ROLES = {'dataset': ('admin', 'committee'), 'application': ('admin', 'applicant'), 'grant': ('admin', 'committee')}
    ROLE_ACTIONS = {
        ('dataset', 'restrict'): ('admin', 'committee'),
        ('dataset', 'publish'): ('admin', 'committee'),
        ('dataset', 'deactivate'): ('admin',),
        ('dataset', 'reactivate'): ('admin',),
        ('application', 'submit'): ('admin', 'applicant'),
        ('application', 'resubmit'): ('admin', 'applicant'),
        ('application', 'review'): ('admin', 'committee'),
        ('application', 'approve'): ('admin', 'committee'),
        ('application', 'reject'): ('admin', 'committee'),
        ('application', 'return_for_review'): ('admin',),
        ('application', 'withdraw'): ('admin', 'applicant'),
        ('grant', 'activate'): ('admin', 'committee'),
        ('grant', 'revoke'): ('admin', 'committee'),
        ('grant', 'revoke_policy_change'): ('admin',),
        ('grant', 'expire'): ('admin', 'committee'),
    }

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        extra = custom(actor, data, lookup) if custom else {}
        payload = dict(data)
        if extra:
            payload.update(extra)
        return payload

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
