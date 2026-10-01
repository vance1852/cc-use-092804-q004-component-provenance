from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from provenance_release.acceptance import run as acceptance_run
from provenance_release.clock import FrozenClock
from provenance_release.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from provenance_release.service import ProvenanceService
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SLOTS = [
    {
        "slot_id": "controller",
        "category": "controller",
        "required_capabilities": {"bus": "CAN-FD", "voltage": "3.3V"},
        "allowed_models": ["MCU-G1"],
        "required_inspections": ["ict"],
    },
    {
        "slot_id": "ai_compute",
        "category": "ai_compute",
        "required_capabilities": {"runtime": "RKNN-2"},
        "allowed_models": ["NPU-A1"],
        "required_inspections": ["thermal"],
    },
]


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 28, 8, 0, tzinfo=timezone.utc))
        self.service = ProvenanceService(self.connection, self.clock)
        for user_id, role in (
            ("hw1", "hardware"), ("hw2", "hardware"),
            ("sw1", "software"), ("sw2", "software"),
            ("q1", "quality"), ("q2", "quality"),
            ("op1", "operator"), ("au1", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.service.register_model("hw1", "MCU-G1", "controller", "华芯微", "国产控制器")
        self.service.register_model("hw1", "MCU-G2", "controller", "华芯微", "国产控制器替代料")
        self.service.register_model("hw1", "NPU-A1", "ai_compute", "燧核", "国产 AI 计算单元")
        self.service.publish_architecture("hw1", "ARCH-R1", 1, "R1 架构", SLOTS)

    def tearDown(self) -> None:
        self.connection.close()

    def _evidence(self, confirm: bool = True) -> dict[str, int]:
        s = self.service
        s.register_declaration("hw1", "DECL-MCU-G1", 1, "MCU-G1", "华芯微", {"origin": "国产"})
        s.register_declaration("hw1", "DECL-NPU-A1", 1, "NPU-A1", "燧核", {"origin": "国产"})
        s.register_firmware("sw1", "FW-MCU1", 1, "MCU-G1", "a" * 64, "基线")
        s.register_firmware("sw1", "FW-NPU", 1, "NPU-A1", "d" * 64, "基线")
        s.register_capability("hw1", "CAP-MCU-G1", 1, "MCU-G1", "FW-MCU1", 1,
                              {"bus": "CAN-FD", "voltage": "3.3V"})
        s.register_capability("hw1", "CAP-NPU-A1", 1, "NPU-A1", "FW-NPU", 1, {"runtime": "RKNN-2"})
        s.register_batch("op1", "LOT-MCU-001", "MCU-G1", "华芯微", "L1")
        s.register_batch("op1", "LOT-NPU-001", "NPU-A1", "燧核", "L2")
        s.register_serials("op1", "LOT-MCU-001", ["SN-MCU-001", "SN-MCU-002"])
        s.register_serials("op1", "LOT-NPU-001", ["SN-NPU-001"])
        inspection_ids = {}
        for batch_id, inspection_type in (("LOT-MCU-001", "ict"), ("LOT-NPU-001", "thermal")):
            recorded = s.record_inspection("q1", batch_id, inspection_type, "pass", f"r-{batch_id}")
            inspection_ids[f"{batch_id}:{inspection_type}"] = recorded["inspection_id"]
        if confirm:
            s.confirm_evidence("hw2", "vendor_declaration", "DECL-MCU-G1", 1, "一致")
            s.confirm_evidence("hw2", "vendor_declaration", "DECL-NPU-A1", 1, "一致")
            s.confirm_evidence("sw2", "firmware_baseline", "FW-MCU1", 1, "一致")
            s.confirm_evidence("sw2", "firmware_baseline", "FW-NPU", 1, "一致")
            s.confirm_evidence("hw2", "interface_capability", "CAP-MCU-G1", 1, "一致")
            s.confirm_evidence("hw2", "interface_capability", "CAP-NPU-A1", 1, "一致")
            for inspection_id in inspection_ids.values():
                s.confirm_evidence("q2", "inspection", str(inspection_id), 1, "复核无误")
        return inspection_ids

    def _config(self, config_id: str = "CFG-1", mcu_serial: str = "SN-MCU-001", npu_serial: str = "SN-NPU-001") -> None:
        self.service.create_config("op1", config_id, "R1 机器人", "ARCH-R1", 1, [
            {"slot_id": "controller", "model_id": "MCU-G1", "batch_id": "LOT-MCU-001",
             "firmware_id": "FW-MCU1", "firmware_version": 1},
            {"slot_id": "ai_compute", "model_id": "NPU-A1", "batch_id": "LOT-NPU-001",
             "firmware_id": "FW-NPU", "firmware_version": 1},
        ])
        self.service.assemble_config("op1", config_id,
                                     {"controller": mcu_serial, "ai_compute": npu_serial})

    def test_full_release_flow_and_explain(self) -> None:
        self._evidence()
        self._config()
        release = self.service.release_config("q1", "CFG-1")
        self.assertEqual(release["conclusion"], "released")
        explain = self.service.explain_config("au1", "CFG-1")
        self.assertTrue(explain["release_valid"])
        controller = next(s for s in explain["evaluation"]["slots"] if s["slot_id"] == "controller")
        self.assertEqual(controller["verdict"], "pass")
        self.assertEqual(controller["pin"]["batch_id"], "LOT-MCU-001")
        kinds = {ref["kind"] for ref in explain["evaluation"]["evidence_refs"]}
        self.assertEqual(
            kinds,
            {"batch", "vendor_declaration", "firmware_baseline", "interface_capability", "inspection"},
        )
        shipped = self.service.ship_config("op1", "CFG-1")
        self.assertEqual(shipped["state"], "shipped")
        trace = self.service.serial_trace("au1", "SN-MCU-001")
        self.assertEqual(trace["current"]["state"], "shipped")
        self.assertEqual([e["event_type"] for e in trace["events"]], ["registered", "installed", "shipped"])

    def test_pending_items_track_missing_signatures_and_inspections(self) -> None:
        inspection_ids = self._evidence(confirm=False)
        self._config()
        pending = self.service.pending_items("q1", "CFG-1")
        self.assertFalse(pending["complete"])
        messages = [item["message"] for item in pending["items"]]
        self.assertTrue(any("待硬件确认" in message for message in messages))
        self.assertTrue(any("待软件确认" in message for message in messages))
        self.assertTrue(any("待质量确认" in message for message in messages))
        self.assertIn("检验", "".join(messages))
        release = self.service.release_config("q1", "CFG-1")
        self.assertEqual(release["conclusion"], "blocked")
        s = self.service
        s.confirm_evidence("hw2", "vendor_declaration", "DECL-MCU-G1", 1, "一致")
        s.confirm_evidence("hw2", "vendor_declaration", "DECL-NPU-A1", 1, "一致")
        s.confirm_evidence("sw2", "firmware_baseline", "FW-MCU1", 1, "一致")
        s.confirm_evidence("sw2", "firmware_baseline", "FW-NPU", 1, "一致")
        s.confirm_evidence("hw2", "interface_capability", "CAP-MCU-G1", 1, "一致")
        s.confirm_evidence("hw2", "interface_capability", "CAP-NPU-A1", 1, "一致")
        for inspection_id in inspection_ids.values():
            s.confirm_evidence("q2", "inspection", str(inspection_id), 1, "复核无误")
        self.assertTrue(self.service.pending_items("q1", "CFG-1")["complete"])
        self.assertEqual(self.service.release_config("q1", "CFG-1")["conclusion"], "released")

    def test_evidence_versions_are_append_only(self) -> None:
        self._evidence()
        with self.assertRaises(Conflict):
            self.service.register_declaration("hw1", "DECL-MCU-G1", 1, "MCU-G1", "华芯微", {"origin": "改写"})
        with self.assertRaises(Conflict):
            self.service.register_firmware("sw1", "FW-MCU1", 3, "MCU-G1", "e" * 64, "跳版本")
        registered = self.service.register_firmware("sw1", "FW-MCU1", 2, "MCU-G1", "f" * 64, "第二版")
        self.assertEqual(registered["version"], 2)
        row = self.connection.execute(
            "SELECT digest_sha256 FROM firmware_baselines WHERE firmware_id='FW-MCU1' AND version=1"
        ).fetchone()
        self.assertEqual(row["digest_sha256"], "a" * 64)
        with self.assertRaises(Conflict):
            self.service.register_firmware("sw1", "FW-MCU1", 2, "MCU-G1", "0" * 64, "覆盖")

    def test_role_separation_and_self_confirmation_ban(self) -> None:
        self._evidence(confirm=False)
        with self.assertRaises(Forbidden):
            self.service.confirm_evidence("sw2", "vendor_declaration", "DECL-MCU-G1", 1, "越权")
        with self.assertRaises(Forbidden):
            self.service.confirm_evidence("hw1", "vendor_declaration", "DECL-MCU-G1", 1, "自证")
        with self.assertRaises(Forbidden):
            self.service.confirm_evidence("q2", "firmware_baseline", "FW-MCU1", 1, "越权")
        with self.assertRaises(Forbidden):
            self.service.release_config("op1", "CFG-1")
        with self.assertRaises(Forbidden):
            self.service.invalidate_evidence("hw2", "batch", "LOT-MCU-001", 0, "越权")
        with self.assertRaises(Forbidden):
            self.service.register_firmware("hw1", "FW-X", 1, "MCU-G1", "0" * 64, "越权")

    def test_invalidation_scopes_to_unshipped_only(self) -> None:
        inspection_ids = self._evidence()
        self._config("CFG-1")
        self.service.release_config("q1", "CFG-1")
        self.service.ship_config("op1", "CFG-1")
        self.service.register_serials("op1", "LOT-NPU-001", ["SN-NPU-002"])
        self._config("CFG-2", "SN-MCU-002", "SN-NPU-002")
        self.service.release_config("q1", "CFG-2")
        thermal = inspection_ids["LOT-NPU-001:thermal"]
        impact = self.service.invalidate_evidence("q1", "inspection", str(thermal), 1, "设备校准超期")["impact"]
        self.assertEqual(impact["affected_open_configs"], ["CFG-2"])
        self.assertEqual(impact["shipped_configs_advisory_only"], ["CFG-1"])
        shipped = self.service.explain_config("au1", "CFG-1")
        self.assertEqual(shipped["config"]["state"], "shipped")
        self.assertTrue(shipped["release_valid"])
        self.assertEqual(len(shipped["post_shipment_advisories"]), 1)
        self.assertEqual(shipped["latest_release"]["conclusion"], "released")
        open_config = self.service.explain_config("q1", "CFG-2")
        self.assertFalse(open_config["release_valid"])
        self.assertTrue(any("已失效" in issue for issue in open_config["release_issues"]))
        with self.assertRaises(InvalidState):
            self.service.ship_config("op1", "CFG-2")
        blocked = self.service.release_config("q1", "CFG-2")
        self.assertEqual(blocked["conclusion"], "blocked")

    def test_release_replay_is_idempotent(self) -> None:
        self._evidence()
        self._config()
        first = self.service.release_config("q1", "CFG-1")
        second = self.service.release_config("q1", "CFG-1")
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["release_id"], second["release_id"])
        count = self.connection.execute("SELECT count(*) FROM assembly_releases").fetchone()[0]
        self.assertEqual(count, 1)

    def test_capability_mismatch_blocks_release(self) -> None:
        self._evidence()
        self.service.register_capability("hw1", "CAP-MCU-G1", 2, "MCU-G1", "FW-MCU1", 1,
                                         {"bus": "CAN-FD", "voltage": "5V"})
        self.service.confirm_evidence("hw2", "interface_capability", "CAP-MCU-G1", 2, "更新")
        self._config()
        release = self.service.release_config("q1", "CFG-1")
        self.assertEqual(release["conclusion"], "blocked")
        pending = self.service.pending_items("q1", "CFG-1")
        self.assertTrue(any(item["status"] == "mismatch" for item in pending["items"]))

    def test_batch_split_genealogy_and_serial_whereabouts(self) -> None:
        self._evidence()
        split = self.service.split_batch("op1", "LOT-MCU-001", [
            {"batch_id": "LOT-MCU-001A", "lot_code": "L1-A", "serial_ids": ["SN-MCU-002"], "note": "分线"},
        ])
        self.assertEqual(split["children"][0]["batch_id"], "LOT-MCU-001A")
        genealogy = self.service.batch_genealogy("au1", "LOT-MCU-001A")
        self.assertEqual([a["batch_id"] for a in genealogy["ancestors"]], ["LOT-MCU-001"])
        self.assertEqual(genealogy["serial_counts"], {"in_stock": 1})
        parent = self.service.batch_genealogy("au1", "LOT-MCU-001")
        self.assertEqual([c["batch_id"] for c in parent["children"]], ["LOT-MCU-001A"])
        trace = self.service.serial_trace("au1", "SN-MCU-002")
        self.assertEqual(trace["current"]["batch_id"], "LOT-MCU-001A")
        self.assertEqual([e["event_type"] for e in trace["events"]], ["registered", "split_moved"])
        with self.assertRaises(Conflict):
            self.service.split_batch("op1", "LOT-MCU-001", [
                {"batch_id": "LOT-MCU-001B", "lot_code": "L1-B", "serial_ids": ["SN-MCU-002"], "note": "越界"},
            ])

    def test_rework_clears_slot_and_keeps_trace(self) -> None:
        self._evidence()
        self._config()
        self.service.release_config("q1", "CFG-1")
        reworked = self.service.rework_serial("op1", "SN-MCU-001", "焊点复检")
        self.assertEqual(reworked["config_id"], "CFG-1")
        config = self.service.explain_config("q1", "CFG-1")
        self.assertEqual(config["config"]["state"], "assembled")
        pending = self.service.pending_items("q1", "CFG-1")
        self.assertTrue(any("序列号" in item["message"] for item in pending["items"]))
        returned = self.service.return_serial("op1", "SN-MCU-001", "复检合格")
        self.assertEqual(returned["state"], "in_stock")
        trace = self.service.serial_trace("au1", "SN-MCU-001")
        self.assertEqual(
            [e["event_type"] for e in trace["events"]],
            ["registered", "installed", "rework_out", "rework_return"],
        )
        self.service.assemble_config("op1", "CFG-1", {"controller": "SN-MCU-001"})
        self.assertEqual(self.service.release_config("q1", "CFG-1")["conclusion"], "released")

    def test_replace_serial_keeps_both_sides_traceable(self) -> None:
        self._evidence()
        self._config()
        self.service.release_config("q1", "CFG-1")
        replaced = self.service.replace_serial("op1", "CFG-1", "controller", "SN-MCU-002", "rework", "来料复测")
        self.assertEqual(replaced["state"], "assembled")
        self.assertEqual(replaced["old_serial"], {"serial_id": "SN-MCU-001", "disposition": "rework"})
        old_trace = self.service.serial_trace("au1", "SN-MCU-001")
        self.assertEqual([e["event_type"] for e in old_trace["events"]],
                         ["registered", "installed", "replaced_out"])
        self.assertEqual(old_trace["current"]["state"], "rework")
        new_trace = self.service.serial_trace("au1", "SN-MCU-002")
        self.assertEqual(new_trace["current"]["config_id"], "CFG-1")
        self.assertEqual(new_trace["events"][-1]["event_type"], "replaced_in")
        with self.assertRaises(InvalidState):
            self.service.ship_config("op1", "CFG-1")
        self.assertEqual(self.service.release_config("q1", "CFG-1")["conclusion"], "released")
        self.service.ship_config("op1", "CFG-1")
        with self.assertRaises(InvalidState):
            self.service.replace_serial("op1", "CFG-1", "controller", "SN-MCU-001", "scrapped", "出厂后")
        with self.assertRaises(InvalidState):
            self.service.rework_serial("op1", "SN-MCU-002", "出厂后返工")

    def test_substitution_coverage_and_invalidation(self) -> None:
        self._evidence()
        self.service.register_declaration("hw1", "DECL-MCU-G2", 1, "MCU-G2", "华芯微", {"origin": "国产"})
        self.service.confirm_evidence("hw2", "vendor_declaration", "DECL-MCU-G2", 1, "一致")
        self.service.register_firmware("sw1", "FW-MCU2", 1, "MCU-G2", "b" * 64, "基线")
        self.service.confirm_evidence("sw2", "firmware_baseline", "FW-MCU2", 1, "一致")
        self.service.register_capability("hw1", "CAP-MCU-G2", 1, "MCU-G2", "FW-MCU2", 1,
                                         {"bus": "CAN-FD", "voltage": "3.3V"})
        self.service.confirm_evidence("hw2", "interface_capability", "CAP-MCU-G2", 1, "一致")
        self.service.register_batch("op1", "LOT-MCU2-001", "MCU-G2", "华芯微", "L3")
        self.service.register_serials("op1", "LOT-MCU2-001", ["SN-MCU2-001"])
        self.service.record_inspection("q1", "LOT-MCU2-001", "ict", "pass", "r-L3")
        inspection_id = self.connection.execute(
            "SELECT inspection_id FROM inspections WHERE batch_id='LOT-MCU2-001'"
        ).fetchone()["inspection_id"]
        self.service.confirm_evidence("q2", "inspection", str(inspection_id), 1, "复核无误")
        self.service.propose_substitution("hw1", "SUB-G2", 1, "ARCH-R1", 1, "controller",
                                          "MCU-G1", "MCU-G2", {"reason": "国产替代"})
        self.service.create_config("op1", "CFG-9", "R1 机器人", "ARCH-R1", 1, [
            {"slot_id": "controller", "model_id": "MCU-G2", "batch_id": "LOT-MCU2-001",
             "firmware_id": "FW-MCU2", "firmware_version": 1},
            {"slot_id": "ai_compute", "model_id": "NPU-A1", "batch_id": "LOT-NPU-001",
             "firmware_id": "FW-NPU", "firmware_version": 1},
        ])
        self.service.assemble_config("op1", "CFG-9",
                                     {"controller": "SN-MCU2-001", "ai_compute": "SN-NPU-001"})
        blocked = self.service.release_config("q1", "CFG-9")
        self.assertEqual(blocked["conclusion"], "blocked")
        self.assertTrue(any("替代关系" in i["message"] for i in self.service.pending_items("q1", "CFG-9")["items"]))
        self.service.confirm_evidence("q2", "substitution", "SUB-G2", 1, "替代验证通过")
        self.assertEqual(self.service.release_config("q1", "CFG-9")["conclusion"], "released")
        coverage = self.service.substitution_coverage("au1", "SUB-G2")
        self.assertEqual(coverage["status"], "ok")
        self.assertEqual([c["config_id"] for c in coverage["dependent_configs"]], ["CFG-9"])
        self.assertEqual(coverage["open_configs_blocked_if_invalidated"], ["CFG-9"])
        impact = self.service.invalidate_evidence("q1", "substitution", "SUB-G2", 1, "替代验证报告撤回")["impact"]
        self.assertEqual(impact["affected_open_configs"], ["CFG-9"])
        self.assertEqual(self.service.release_config("q1", "CFG-9")["conclusion"], "blocked")

    def test_unknown_references_raise_not_found(self) -> None:
        with self.assertRaises(NotFound):
            self.service.explain_config("q1", "CFG-X")
        with self.assertRaises(NotFound):
            self.service.batch_genealogy("q1", "LOT-X")
        with self.assertRaises(NotFound):
            self.service.serial_trace("q1", "SN-X")
        with self.assertRaises(NotFound):
            self.service.substitution_coverage("q1", "SUB-X")
        with self.assertRaises(NotFound):
            self.service.confirm_evidence("hw2", "vendor_declaration", "DECL-X", 1, "不存在")

    def test_config_requires_complete_slots_and_matching_batch(self) -> None:
        self._evidence()
        with self.assertRaises(ValidationFailed):
            self.service.create_config("op1", "CFG-BAD", "R1", "ARCH-R1", 1, [
                {"slot_id": "controller", "model_id": "MCU-G1", "batch_id": "LOT-MCU-001",
                 "firmware_id": "FW-MCU1", "firmware_version": 1},
            ])
        with self.assertRaises(ValidationFailed):
            self.service.create_config("op1", "CFG-BAD2", "R1", "ARCH-R1", 1, [
                {"slot_id": "controller", "model_id": "MCU-G1", "batch_id": "LOT-NPU-001",
                 "firmware_id": "FW-MCU1", "firmware_version": 1},
                {"slot_id": "ai_compute", "model_id": "NPU-A1", "batch_id": "LOT-NPU-001",
                 "firmware_id": "FW-NPU", "firmware_version": 1},
            ])

    def test_audit_chain_is_valid_and_sealed(self) -> None:
        self._evidence()
        self._config()
        self.service.release_config("q1", "CFG-1")
        audit = self.service.audit_chain("au1")
        self.assertTrue(audit["valid"])
        self.assertGreater(audit["events"], 10)
        with self.assertRaises(Forbidden):
            self.service.audit_chain("op1")

    def test_offline_acceptance(self) -> None:
        result = acceptance_run(ROOT)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["cfg1_state"], "shipped")
        self.assertEqual(result["cfg2_state"], "shipped")
        self.assertEqual(result["invalidation_impact"]["affected_open_configs"], ["CFG-0002"])
        self.assertEqual(result["invalidation_impact"]["shipped_configs_advisory_only"], ["CFG-0001"])
        self.assertEqual(result["cfg1_post_shipment_advisories"], 1)
        self.assertTrue(result["audit"]["valid"])
        self.assertEqual(result["schema"]["missing_tables"], [])


if __name__ == "__main__":
    unittest.main()
