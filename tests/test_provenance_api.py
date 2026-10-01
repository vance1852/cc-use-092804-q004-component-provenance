from __future__ import annotations

import json
import sqlite3
import unittest

from provenance_release.api import JsonApplication
from provenance_release.service import ProvenanceService


def _body(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class ProvenanceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(ProvenanceService(self.connection))
        for user_id, role in (
            ("hw1", "hardware"), ("hw2", "hardware"), ("sw1", "software"), ("sw2", "software"),
            ("q1", "quality"), ("q2", "quality"), ("op1", "operator"),
        ):
            self.app.handle("POST", "/users", body=_body(
                {"user_id": user_id, "display_name": user_id, "role": role}))

    def tearDown(self) -> None:
        self.connection.close()

    def _post(self, path: str, actor: str, payload: dict):
        return self.app.handle("POST", path, {"X-Actor-Id": actor}, _body(payload))

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["service"], "provenance-release")

    def test_actor_header_required(self) -> None:
        response = self.app.handle("POST", "/models", body=_body(
            {"model_id": "MCU-G1", "category": "controller", "vendor": "华芯微", "description": "控制器"}))
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_error_shape_for_forbidden(self) -> None:
        response = self._post("/models", "q1",
                              {"model_id": "MCU-G1", "category": "controller", "vendor": "v", "description": "d"})
        self.assertEqual(response.status, 403)
        self.assertEqual(response.body["error"]["code"], "forbidden")

    def test_full_http_flow(self) -> None:
        self.assertEqual(self._post("/models", "hw1", {
            "model_id": "MCU-G1", "category": "controller", "vendor": "华芯微", "description": "国产控制器",
        }).status, 201)
        self.assertEqual(self._post("/architectures", "hw1", {
            "arch_id": "ARCH-R1", "version": 1, "name": "R1 架构",
            "slots": [{
                "slot_id": "controller", "category": "controller",
                "required_capabilities": {"bus": "CAN-FD"},
                "allowed_models": ["MCU-G1"], "required_inspections": ["ict"],
            }],
        }).status, 201)
        self.assertEqual(self._post("/declarations", "hw1", {
            "declaration_id": "DECL-1", "version": 1, "model_id": "MCU-G1",
            "vendor": "华芯微", "statement": {"origin": "国产"},
        }).status, 201)
        self.assertEqual(self._post("/confirmations", "hw2", {
            "evidence_kind": "vendor_declaration", "evidence_id": "DECL-1",
            "evidence_version": 1, "statement": "一致",
        }).status, 201)
        self.assertEqual(self._post("/firmware", "sw1", {
            "firmware_id": "FW-1", "version": 1, "model_id": "MCU-G1",
            "digest_sha256": "a" * 64, "notes": "基线",
        }).status, 201)
        self.assertEqual(self._post("/confirmations", "sw2", {
            "evidence_kind": "firmware_baseline", "evidence_id": "FW-1",
            "evidence_version": 1, "statement": "一致",
        }).status, 201)
        self.assertEqual(self._post("/capabilities", "hw1", {
            "capability_id": "CAP-1", "version": 1, "model_id": "MCU-G1",
            "firmware_id": "FW-1", "firmware_version": 1, "capabilities": {"bus": "CAN-FD"},
        }).status, 201)
        self.assertEqual(self._post("/confirmations", "hw2", {
            "evidence_kind": "interface_capability", "evidence_id": "CAP-1",
            "evidence_version": 1, "statement": "一致",
        }).status, 201)
        self.assertEqual(self._post("/batches", "op1", {
            "batch_id": "LOT-1", "model_id": "MCU-G1", "vendor": "华芯微", "lot_code": "L1",
        }).status, 201)
        self.assertEqual(self._post("/batches/LOT-1/serials", "op1", {"serial_ids": ["SN-1"]}).status, 201)
        inspection = self._post("/inspections", "q1", {
            "batch_id": "LOT-1", "inspection_type": "ict", "result": "pass", "evidence_ref": "r-1",
        })
        self.assertEqual(inspection.status, 201)
        self.assertEqual(self._post("/confirmations", "q2", {
            "evidence_kind": "inspection", "evidence_id": str(inspection.body["inspection_id"]),
            "evidence_version": 1, "statement": "复核无误",
        }).status, 201)
        self.assertEqual(self._post("/configs", "op1", {
            "config_id": "CFG-1", "robot_model": "R1", "arch_id": "ARCH-R1", "arch_version": 1,
            "slots": [{"slot_id": "controller", "model_id": "MCU-G1", "batch_id": "LOT-1",
                       "firmware_id": "FW-1", "firmware_version": 1}],
        }).status, 201)
        self.assertEqual(self._post("/configs/CFG-1/assemble", "op1",
                                    {"assignments": {"controller": "SN-1"}}).status, 200)
        pending = self.app.handle("GET", "/configs/CFG-1/pending", {"X-Actor-Id": "q1"})
        self.assertEqual(pending.status, 200)
        self.assertTrue(pending.body["complete"])
        release = self._post("/configs/CFG-1/release", "q1", {})
        self.assertEqual(release.status, 201)
        self.assertEqual(release.body["conclusion"], "released")
        replay = self._post("/configs/CFG-1/release", "q1", {})
        self.assertTrue(replay.body["replayed"])
        explain = self.app.handle("GET", "/configs/CFG-1", {"X-Actor-Id": "q1"})
        self.assertEqual(explain.status, 200)
        self.assertEqual(explain.body["evaluation"]["conclusion"], "released")
        ship = self._post("/configs/CFG-1/ship", "op1", {})
        self.assertEqual(ship.status, 200)
        self.assertEqual(ship.body["state"], "shipped")
        trace = self.app.handle("GET", "/serials/SN-1/trace", {"X-Actor-Id": "q1"})
        self.assertEqual(trace.body["current"]["state"], "shipped")
        genealogy = self.app.handle("GET", "/batches/LOT-1/genealogy", {"X-Actor-Id": "q1"})
        self.assertEqual(genealogy.body["serial_counts"], {"shipped": 1})

    def test_unknown_route(self) -> None:
        response = self.app.handle("GET", "/nothing", {"X-Actor-Id": "q1"})
        self.assertEqual(response.status, 404)
        self.assertEqual(response.body["error"]["code"], "route_not_found")


if __name__ == "__main__":
    unittest.main()
