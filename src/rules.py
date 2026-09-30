from datetime import datetime, timedelta

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")


def _validate_grant_create(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if dataset.get("data", {}).get("deactivated"):
        raise PermissionDenied("dataset is deactivated; grants cannot be issued")


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")
    dataset = _find_one(lookup, "dataset", "id", entity["data"].get("dataset_id"))
    if dataset and dataset.get("data", {}).get("deactivated"):
        raise PermissionDenied("dataset is deactivated; approval is blocked")
    if dataset:
        return {"policy_version": _policy_version(dataset)}
    return {}


def _validate_return(actor, entity, data, lookup):
    return {"returned_from_policy": entity["data"].get("policy_version", 1)}


def _validate_dataset_update_policy(actor, entity, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")
    return {
        "access_policy": data["access_policy"],
        "policy_version": _policy_version(entity) + 1,
    }


def _validate_dataset_deactivate(actor, entity, data, lookup):
    if entity["data"].get("deactivated"):
        raise ValidationError("dataset is already deactivated")
    return {"deactivated": True}


def _validate_dataset_reactivate(actor, entity, data, lookup):
    if not entity["data"].get("deactivated"):
        raise ValidationError("dataset is not deactivated")
    return {"deactivated": False}


def _policy_version(entity):
    return int(entity.get("data", {}).get("policy_version", 1) or 1)


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    dataset = _find_one(lookup, "dataset", "id", entity["data"].get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if dataset.get("data", {}).get("deactivated"):
        raise PermissionDenied("dataset is deactivated; credential cannot be activated")
    grant_version = int(entity["data"].get("policy_version", 1) or 1)
    if grant_version != _policy_version(dataset):
        raise ConflictError(
            "grant policy version %s does not match current dataset policy version %s"
            % (grant_version, _policy_version(dataset))
        )
    return {"activated_by": actor.user_id}


CUSTOM_CREATE = {'dataset': _validate_dataset, 'application': _validate_application, 'grant': _validate_grant_create}
CUSTOM_TRANSITIONS = {
    ('application', 'approve'): _validate_approve,
    ('application', 'return'): _validate_return,
    ('grant', 'activate'): _validate_grant_activate,
    ('dataset', 'update_policy'): _validate_dataset_update_policy,
    ('dataset', 'deactivate'): _validate_dataset_deactivate,
    ('dataset', 'reactivate'): _validate_dataset_reactivate,
}

# Sentinel: the action does not change the entity's status (data-only patch).
_SAME_STATUS = "__same__"


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued'}
    TRANSITIONS = {
        'dataset': {
            'restrict': (('registered',), 'restricted'),
            'publish': (('restricted',), 'published'),
            'update_policy': (('registered', 'restricted', 'published'), _SAME_STATUS),
            'deactivate': (('registered', 'restricted', 'published'), _SAME_STATUS),
            'reactivate': (('registered', 'restricted', 'published'), _SAME_STATUS),
        },
        'application': {
            'submit': (('draft',), 'submitted'),
            'review': (('submitted',), 'under_review'),
            'approve': (('under_review',), 'approved'),
            'reject': (('under_review',), 'rejected'),
            'withdraw': (('submitted', 'under_review'), 'withdrawn'),
            'return': (('submitted', 'under_review'), 'submitted'),
        },
        'grant': {
            'activate': (('issued',), 'active'),
            'revoke': (('issued', 'active'), 'revoked'),
            'expire': (('active',), 'expired'),
        },
    }
    CREATE_REQUIRED = {'dataset': ('name', 'access_policy'), 'application': ('dataset_id', 'applicant_id', 'purpose'), 'grant': ('application_id', 'dataset_id', 'recipient')}
    ACTION_REQUIRED = {('dataset', 'restrict'): ('reason',), ('application', 'review'): ('committee_id',), ('application', 'approve'): ('approvals', 'terms', 'expires_at'), ('application', 'reject'): ('reason',), ('application', 'withdraw'): ('reason',), ('grant', 'activate'): ('starts_at', 'expires_at'), ('grant', 'revoke'): ('reason',), ('grant', 'expire'): ('expired_at',)}
    CREATE_ROLES = {'dataset': ('admin', 'committee'), 'application': ('admin', 'applicant'), 'grant': ('admin', 'committee')}
    ROLE_ACTIONS = {'restrict': ('admin', 'committee'), 'publish': ('admin', 'committee'), 'submit': ('admin', 'applicant'), 'review': ('admin', 'committee'), 'approve': ('admin', 'committee'), 'reject': ('admin', 'committee'), 'withdraw': ('admin', 'applicant'), 'activate': ('admin', 'committee'), 'revoke': ('admin', 'committee'), 'expire': ('admin', 'committee'), 'return': ('admin', 'committee'), 'update_policy': ('admin',), 'deactivate': ('admin',), 'reactivate': ('admin',)}

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
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if next_status == _SAME_STATUS:
            next_status = entity["status"]
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

    def require_role(self, actor, allowed):
        self._ensure_role(actor, allowed)


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
