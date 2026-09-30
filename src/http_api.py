import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .domain import (
    ConflictError,
    DomainError,
    InvalidTransition,
    NotFoundError,
    PermissionDenied,
    ValidationError,
    Actor,
)


def _json_bytes(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def create_handler(service, rules, static_dir):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ModularPython/1.0"

        def log_message(self, format, *args):
            return

        def _send(self, status, payload):
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, status, body):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _actor(self):
            return Actor.from_headers(self.headers)

        def _body(self):
            length = int(self.headers.get("Content-Length", "0") or 0)
            if not length:
                return {}
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise ValidationError("request body must be valid JSON")
            if not isinstance(value, dict):
                raise ValidationError("request body must be a JSON object")
            return value

        def _fail(self, exc):
            if isinstance(exc, PermissionDenied):
                status = 403
            elif isinstance(exc, NotFoundError):
                status = 404
            elif isinstance(exc, (ConflictError, InvalidTransition)):
                status = 409
            elif isinstance(exc, ValidationError):
                status = 400
            elif isinstance(exc, DomainError):
                status = 400
            else:
                status = 500
            self._send(status, {"error": str(exc), "type": type(exc).__name__})

        def do_GET(self):
            try:
                parsed = urlparse(self.path)
                parts = [part for part in parsed.path.split("/") if part]
                if parsed.path == "/health":
                    return self._send(200, service.health())
                if parsed.path == "/":
                    index = os.path.join(static_dir, "index.html")
                    with open(index, "r", encoding="utf-8") as handle:
                        return self._send_html(200, handle.read())
                # GET /api/audit?dataset_id=...：审计按数据集聚合
                if parts == ["api", "audit"]:
                    query = parse_qs(parsed.query)
                    dataset_id = query.get("dataset_id", [None])[0]
                    entity_id = query.get("entity_id", [None])[0]
                    return self._send(
                        200,
                        {"items": service.audit_log(
                            entity_id=entity_id, dataset_id=dataset_id
                        )},
                    )
                # GET /api/datasets/<id>/governance：政策版本/受影响对象/失败重试视图
                if len(parts) == 4 and parts[0] == "api" \
                        and parts[1] in ("datasets", "dataset") \
                        and parts[3] == "governance":
                    return self._send(
                        200, service.governance_view(parts[2])
                    )
                # GET /api/policy-batches/<id>
                if len(parts) == 3 and parts[:2] == ["api", "policy-batches"]:
                    return self._send(200, service.get_policy_batch(parts[2]))
                if len(parts) == 3 and parts[:2] == ["api", "entities"]:
                    return self._send(200, service.get(parts[2]))
                if len(parts) >= 2 and parts[0] == "api":
                    if parts[1] == "entities":
                        raise NotFoundError("not found")
                    if parts[1] == "policy-batches":
                        query = parse_qs(parsed.query)
                        dataset_id = query.get("dataset_id", [None])[0]
                        status = query.get("status", [None])[0]
                        return self._send(
                            200,
                            {"items": service.list_policy_batches(
                                dataset_id=dataset_id, status=status)},
                        )
                    if len(parts) == 3:
                        return self._send(200, service.get(parts[2]))
                    query = parse_qs(parsed.query)
                    status = query.get("status", [None])[0]
                    return self._send(
                        200,
                        {"items": service.list(parts[1], status=status)},
                    )
                raise NotFoundError("not found")
            except Exception as exc:
                self._fail(exc)

        def do_POST(self):
            try:
                parsed = urlparse(self.path)
                parts = [part for part in parsed.path.split("/") if part]
                actor = self._actor()
                # POST /api/datasets/<id>/policy：提交政策变更治理批次
                if len(parts) == 4 and parts[0] == "api" \
                        and parts[1] == "datasets" and parts[3] == "policy":
                    return self._send(
                        200, service.update_policy(actor, parts[2], self._body())
                    )
                # POST /api/datasets/<id>/backfill-policy：旧数据补录政策版本
                if len(parts) == 4 and parts[0] == "api" \
                        and parts[1] == "datasets" \
                        and parts[3] == "backfill-policy":
                    return self._send(
                        200,
                        service.backfill_policy_version(actor, parts[2], self._body()),
                    )
                # POST /api/policy-batches/<id>/retry：管理员重试失败批次
                if len(parts) == 4 and parts[:2] == ["api", "policy-batches"] \
                        and parts[3] == "retry":
                    return self._send(
                        200, service.retry_policy_batch(actor, parts[2])
                    )
                if len(parts) == 3 and parts[:2] == ["api", "entities"]:
                    body = self._body()
                    action = body.pop("action", None)
                    if not action:
                        raise ValidationError("action is required")
                    data = body.pop("data", body)
                    expected = body.pop("expected_version", None)
                    return self._send(
                        200,
                        service.transition(actor, parts[2], action, data, expected),
                    )
                if len(parts) == 4 and parts[0] == "api" and parts[3] == "actions":
                    body = self._body()
                    action = body.pop("action", None)
                    if not action:
                        raise ValidationError("action is required")
                    return self._send(
                        200,
                        service.transition(
                            actor,
                            parts[2],
                            action,
                            body.pop("data", body),
                            body.pop("expected_version", None),
                        ),
                    )
                if len(parts) == 5 and parts[0] == "api" and parts[4] == "actions":
                    return self._send(
                        200,
                        service.transition(actor, parts[2], parts[3], self._body(), None),
                    )
                if len(parts) == 2 and parts[0] == "api":
                    body = self._body()
                    idem = self.headers.get("Idempotency-Key")
                    return self._send(
                        201,
                        service.create(actor, parts[1], body, idem),
                    )
                raise NotFoundError("not found")
            except Exception as exc:
                self._fail(exc)

    return Handler


def create_server(host, port, service, rules, static_dir):
    handler = create_handler(service, rules, static_dir)
    return ThreadingHTTPServer((host, int(port)), handler)
