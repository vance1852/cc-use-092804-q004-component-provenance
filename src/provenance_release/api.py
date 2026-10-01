"""无第三方依赖的部件来源与兼容放行链 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .errors import ProvenanceError, ValidationFailed
from .service import ProvenanceService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    """将 HTTP 路由映射到领域服务，便于无网络单元测试。

    单个 SQLite 连接在请求锁内串行使用，保证多线程下的事务语义。
    """

    def __init__(self, service: ProvenanceService) -> None:
        self.service = service
        self._lock = threading.Lock()

    @staticmethod
    def _actor(headers: Mapping[str, str]) -> str:
        actor = headers.get("x-actor-id", "").strip()
        if not actor:
            raise ValidationFailed("缺少 X-Actor-Id")
        return actor

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    def handle(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        with self._lock:
            return self._dispatch(method, target, headers, body)

    def _dispatch(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        path = urlparse(target).path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok", "service": "provenance-release"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            if method == "POST" and path == "/users":
                return Response(201, self.service.create_user(payload["user_id"], payload["display_name"], payload["role"]))
            actor = self._actor(normalized_headers)
            if method == "POST" and path == "/models":
                return Response(201, self.service.register_model(
                    actor, payload["model_id"], payload["category"], payload["vendor"], payload["description"]))
            if method == "POST" and path == "/architectures":
                return Response(201, self.service.publish_architecture(
                    actor, payload["arch_id"], int(payload["version"]), payload["name"], payload.get("slots", [])))
            if method == "POST" and path == "/declarations":
                return Response(201, self.service.register_declaration(
                    actor, payload["declaration_id"], int(payload["version"]), payload["model_id"],
                    payload["vendor"], payload.get("statement", {})))
            if method == "POST" and path == "/firmware":
                return Response(201, self.service.register_firmware(
                    actor, payload["firmware_id"], int(payload["version"]), payload["model_id"],
                    payload["digest_sha256"], payload.get("notes", "")))
            if method == "POST" and path == "/capabilities":
                return Response(201, self.service.register_capability(
                    actor, payload["capability_id"], int(payload["version"]), payload["model_id"],
                    payload["firmware_id"], int(payload["firmware_version"]), payload.get("capabilities", {})))
            if method == "POST" and path == "/batches":
                return Response(201, self.service.register_batch(
                    actor, payload["batch_id"], payload["model_id"], payload["vendor"], payload["lot_code"]))
            if method == "POST" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "split":
                return Response(201, self.service.split_batch(actor, parts[1], payload.get("children", [])))
            if method == "POST" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "serials":
                return Response(201, self.service.register_serials(actor, parts[1], payload.get("serial_ids", [])))
            if method == "GET" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "genealogy":
                return Response(200, self.service.batch_genealogy(actor, parts[1]))
            if method == "POST" and path == "/inspections":
                return Response(201, self.service.record_inspection(
                    actor, payload["batch_id"], payload["inspection_type"], payload["result"], payload["evidence_ref"]))
            if method == "POST" and path == "/substitutions":
                return Response(201, self.service.propose_substitution(
                    actor, payload["substitution_id"], int(payload["version"]), payload["arch_id"],
                    int(payload["arch_version"]), payload["slot_id"], payload["from_model"],
                    payload["to_model"], payload.get("conditions", {})))
            if method == "GET" and len(parts) == 3 and parts[0] == "substitutions" and parts[2] == "coverage":
                return Response(200, self.service.substitution_coverage(actor, parts[1]))
            if method == "POST" and path == "/confirmations":
                return Response(201, self.service.confirm_evidence(
                    actor, payload["evidence_kind"], str(payload["evidence_id"]),
                    int(payload["evidence_version"]), payload["statement"]))
            if method == "POST" and path == "/invalidations":
                return Response(201, self.service.invalidate_evidence(
                    actor, payload["evidence_kind"], str(payload["evidence_id"]),
                    int(payload["evidence_version"]), payload["reason"]))
            if method == "POST" and path == "/configs":
                return Response(201, self.service.create_config(
                    actor, payload["config_id"], payload["robot_model"], payload["arch_id"],
                    int(payload["arch_version"]), payload.get("slots", [])))
            if method == "POST" and len(parts) == 3 and parts[0] == "configs" and parts[2] == "assemble":
                return Response(200, self.service.assemble_config(actor, parts[1], payload.get("assignments", {})))
            if method == "POST" and len(parts) == 3 and parts[0] == "configs" and parts[2] == "release":
                return Response(201, self.service.release_config(actor, parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "configs" and parts[2] == "ship":
                return Response(200, self.service.ship_config(actor, parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "configs" and parts[2] == "replace":
                return Response(200, self.service.replace_serial(
                    actor, parts[1], payload["slot_id"], payload["new_serial_id"],
                    payload["disposition"], payload.get("note", "")))
            if method == "GET" and len(parts) == 2 and parts[0] == "configs":
                return Response(200, self.service.explain_config(actor, parts[1]))
            if method == "GET" and len(parts) == 3 and parts[0] == "configs" and parts[2] == "pending":
                return Response(200, self.service.pending_items(actor, parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "serials" and parts[2] == "rework":
                return Response(200, self.service.rework_serial(actor, parts[1], payload.get("note", "")))
            if method == "POST" and len(parts) == 3 and parts[0] == "serials" and parts[2] == "return":
                return Response(200, self.service.return_serial(actor, parts[1], payload.get("note", "")))
            if method == "GET" and len(parts) == 3 and parts[0] == "serials" and parts[2] == "trace":
                return Response(200, self.service.serial_trace(actor, parts[1]))
            if method == "GET" and path == "/audit":
                return Response(200, self.service.audit_chain(actor))
            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except ProvenanceError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ProvenanceRelease/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动部件来源与兼容放行链 HTTP 服务")
    parser.add_argument("--database", type=Path, default=Path("provenance.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    application = JsonApplication(ProvenanceService(connection))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(application))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
