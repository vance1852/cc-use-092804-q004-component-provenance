"""无第三方依赖的部件来源与兼容放行链 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .errors import ServiceError, ValidationFailed
from .service import ReleaseChainService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Any


class JsonApplication:
    """把 HTTP 路由映射到放行链领域服务，便于无网络单元测试。"""

    def __init__(self, service: ReleaseChainService) -> None:
        self.service = service

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
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        path = urlparse(target).path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        actor = lambda: self._actor(normalized_headers)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok", "service": "release-chain"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}

            if method == "POST" and path == "/users":
                return Response(201, self.service.create_user(
                    actor(), payload["user_id"], payload["display_name"], payload["role"]))

            if method == "POST" and path == "/parts":
                return Response(201, self.service.register_part(
                    actor(), payload["part_no"], payload["kind"], payload["description"]))

            if method == "POST" and len(parts) == 2 and parts[0] == "architectures":
                return Response(201, self.service.publish_architecture(
                    actor(), parts[1], payload["content"]))
            if method == "GET" and len(parts) == 3 and parts[0] == "architectures":
                return Response(200, self.service.get_architecture(actor(), parts[1], int(parts[2])))

            if method == "POST" and len(parts) == 3 and parts[0] == "parts" and parts[2] == "evidence":
                return Response(201, self.service.submit_evidence(
                    actor(), parts[1], payload["kind"], payload["payload"]))
            if method == "GET" and len(parts) == 2 and parts[0] == "evidence":
                return Response(200, self.service.get_evidence(actor(), int(parts[1])))
            if method == "POST" and len(parts) == 3 and parts[0] == "evidence" and parts[2] == "sign":
                return Response(200, self.service.sign_evidence(
                    actor(), int(parts[1]), payload["decision"], payload.get("comment", "")))
            if method == "POST" and len(parts) == 3 and parts[0] == "evidence" and parts[2] == "revoke":
                return Response(200, self.service.revoke_evidence(
                    actor(), int(parts[1]), payload["reason"]))

            if method == "POST" and path == "/substitutions":
                return Response(201, self.service.approve_substitution(
                    actor(), payload["substitution_id"], payload["original_part_no"],
                    payload["substitute_part_no"], payload["justification"],
                    payload.get("architecture_id"),
                    payload.get("applies_from_version"), payload.get("applies_to_version")))
            if method == "POST" and len(parts) == 3 and parts[0] == "substitutions" and parts[2] == "revoke":
                return Response(200, self.service.revoke_substitution(actor(), parts[1], payload["reason"]))
            if method == "GET" and len(parts) == 3 and parts[0] == "substitutions" and parts[2] == "coverage":
                return Response(200, self.service.substitution_coverage(actor(), parts[1]))

            if method == "POST" and path == "/configurations":
                return Response(201, self.service.register_configuration(
                    actor(), payload["robot_serial"], payload["architecture_id"],
                    int(payload["architecture_version"]), payload["positions"]))

            if method == "POST" and path == "/movements":
                return Response(201, self.service.record_movement(
                    actor(), payload["serial_no"], payload["part_no"], payload["event"],
                    payload.get("robot_serial"), payload.get("config_sha256"),
                    payload.get("note", "")))
            if method == "GET" and len(parts) == 2 and parts[0] == "serials":
                return Response(200, self.service.serial_trace(actor(), parts[1]))

            if method == "POST" and path == "/releases/evaluate":
                return Response(200, self.service.evaluate_configuration(
                    actor(), payload["config_sha256"]))
            if method == "POST" and path == "/releases/decide":
                return Response(200, self.service.decide_release(
                    actor(), payload["config_sha256"], payload["decision"], payload["reason"]))
            if method == "POST" and path == "/releases/ship":
                return Response(200, self.service.ship_release(actor(), payload["config_sha256"]))
            if method == "GET" and path == "/releases/pending":
                return Response(200, {"pending": self.service.pending_releases(actor())})
            if method == "GET" and len(parts) == 3 and parts[0] == "robots" and parts[2] == "explain":
                return Response(200, self.service.explain_robot(actor(), parts[1]))

            if method == "GET" and len(parts) == 3 and parts[0] == "audit":
                return Response(200, {"events": self.service.audit(actor(), parts[1], parts[2])})

            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except ServiceError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ReleaseChain/1"

        def do_GET(self) -> None:
            self._dispatch()

        def do_POST(self) -> None:
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
    parser.add_argument("--database", type=Path, default=Path("release-chain.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    service = ReleaseChainService(connection)
    service.bootstrap_admin()
    application = JsonApplication(service)
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
