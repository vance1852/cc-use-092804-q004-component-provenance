from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone

from release_chain.api import JsonApplication
from release_chain.clock import FrozenClock
from release_chain.service import ReleaseChainService


def _body(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode()


class ReleaseChainApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        clock = FrozenClock(datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc))
        self.service = ReleaseChainService(self.connection, clock)
        self.app = JsonApplication(self.service)
        self.service.bootstrap_admin()
        self.admin = {"x-actor-id": "admin"}
        for uid, role in (("hw", "hardware"), ("sw", "software"), ("qa", "quality")):
            self.post("/users", {"user_id": uid, "display_name": uid, "role": role}, self.admin)
        self.post("/parts", {"part_no": "P1", "kind": "controller", "description": "控制器"},
                  {"x-actor-id": "hw"})

    def tearDown(self) -> None:
        self.connection.close()

    def request(self, method: str, path: str, payload: dict | None = None,
                headers: dict | None = None) -> tuple[int, dict]:
        response = self.app.handle(
            method, path, headers or {}, _body(payload) if payload is not None else b"")
        return response.status, response.body

    def post(self, path: str, payload: dict, headers: dict | None = None) -> tuple[int, dict]:
        return self.request("POST", path, payload, headers)

    def get(self, path: str, headers: dict | None = None) -> tuple[int, dict]:
        return self.request("GET", path, None, headers)

    def test_health(self) -> None:
        status, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "release-chain")

    def test_requires_actor_header(self) -> None:
        status, body = self.post("/parts", {"part_no": "P2", "kind": "controller", "description": "x"})
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "validation_failed")

    def test_role_forbidden_has_403_shape(self) -> None:
        status, body = self.post(
            "/parts/P1/evidence",
            {"kind": "firmware_digest", "payload": {
                "firmware_baseline": "2.4.1", "image_sha256": "c" * 64}},
            {"x-actor-id": "hw"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")

    def test_full_release_flow_over_http(self) -> None:
        # 架构
        status, arch = self.post("/architectures/arch-a", {"content": {
            "revision": "R1",
            "requirements": {"ctrl": {
                "kind": "controller", "part_no": "P1", "min_firmware": "2.4.0",
                "required_bus_protocols": ["ethercat"]}},
        }}, {"x-actor-id": "hw"})
        self.assertEqual(status, 201)

        # 硬件证据
        for kind, payload in (
            ("vendor_declaration", {"vendor": "厂", "document_ref": "D", "document_sha256": "a" * 64}),
            ("lineage", {"manufacturing_batch": "B1", "date_code": "2026-09-30", "parent_lot_id": None}),
        ):
            status, body = self.post("/parts/P1/evidence", {"kind": kind, "payload": payload},
                                     {"x-actor-id": "hw"})
            self.assertEqual(status, 201)
        # 软件证据与质量证据（提交角色各自不同）
        _, fw = self.post("/parts/P1/evidence",
                          {"kind": "firmware_digest",
                           "payload": {"firmware_baseline": "2.4.1", "image_sha256": "c" * 64}},
                          {"x-actor-id": "sw"})
        _, cap = self.post("/parts/P1/evidence",
                           {"kind": "interface_capability",
                            "payload": {"bus_protocols": ["ethercat"], "electrical": {}}},
                           {"x-actor-id": "sw"})
        _, insp = self.post("/parts/P1/evidence",
                            {"kind": "inspection", "payload": {
                                "result": "pass", "report_ref": "Q",
                                "report_sha256": "d" * 64, "findings": []}},
                            {"x-actor-id": "qa"})
        _, vendor = self.get("/evidence/1", {"x-actor-id": "admin"})
        self.assertEqual(vendor["kind"], "vendor_declaration")

        # 签署人必须不同于提交人：建立第二名硬件/软件/质量账号
        for uid, role in (("hw2", "hardware"), ("sw2", "software"), ("qa2", "quality")):
            self.post("/users", {"user_id": uid, "display_name": uid, "role": role}, self.admin)
        for evidence_id in (1, 2):
            status, _ = self.post(f"/evidence/{evidence_id}/sign", {"decision": "confirmed"},
                                  {"x-actor-id": "hw2"})
            self.assertEqual(status, 200)
        for evidence_id in (fw["evidence_id"], cap["evidence_id"]):
            status, _ = self.post(f"/evidence/{evidence_id}/sign", {"decision": "confirmed"},
                                  {"x-actor-id": "sw2"})
            self.assertEqual(status, 200)
        status, _ = self.post(f"/evidence/{insp['evidence_id']}/sign", {"decision": "confirmed"},
                              {"x-actor-id": "qa2"})
        self.assertEqual(status, 200)

        # 配置 + 装配
        _, config = self.post("/configurations", {
            "robot_serial": "R1", "architecture_id": "arch-a", "architecture_version": 1,
            "positions": {"ctrl": {"part_no": "P1", "serial_no": "SN1"}}},
            {"x-actor-id": "hw"})
        digest = config["config_sha256"]
        status, _ = self.post("/movements", {
            "serial_no": "SN1", "part_no": "P1", "event": "installed",
            "robot_serial": "R1", "config_sha256": digest}, {"x-actor-id": "hw"})
        self.assertEqual(status, 201)

        # 评估、放行、出厂
        status, evaluation = self.post("/releases/evaluate", {"config_sha256": digest},
                                       {"x-actor-id": "qa"})
        self.assertEqual(status, 200)
        self.assertEqual(evaluation["gate"], "released")
        status, _ = self.post("/releases/decide",
                              {"config_sha256": digest, "decision": "released", "reason": "齐套"},
                              {"x-actor-id": "qa"})
        self.assertEqual(status, 200)
        status, _ = self.post("/releases/ship", {"config_sha256": digest}, {"x-actor-id": "qa"})
        self.assertEqual(status, 200)

        # 解释接口回答“为什么允许使用”
        status, explanation = self.get(f"/robots/{digest}/explain", {"x-actor-id": "hw"})
        self.assertEqual(status, 200)
        self.assertTrue(explanation["factory_sealed"])
        self.assertEqual(explanation["slots"][0]["evidence"]["inspection"]["result"], "pass")

        # 待放行列表为空
        status, pending = self.get("/releases/pending", {"x-actor-id": "qa"})
        self.assertEqual(status, 200)
        self.assertEqual(pending["pending"], [])


if __name__ == "__main__":
    unittest.main()
