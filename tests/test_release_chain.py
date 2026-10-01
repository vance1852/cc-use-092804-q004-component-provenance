from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone

from release_chain.clock import FrozenClock
from release_chain.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from release_chain.service import ReleaseChainService


class ReleaseChainTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc))
        self.service = ReleaseChainService(self.connection, self.clock)
        self.service.bootstrap_admin()
        for uid, role in (
            ("hw", "hardware"), ("hw2", "hardware"),
            ("sw", "software"), ("sw2", "software"),
            ("qa", "quality"), ("qa2", "quality"),
            ("auditor", "auditor"),
        ):
            self.service.create_user("admin", uid, uid, role)
        self.service.register_part("hw", "CTRL-A1", "controller", "名义控制器")
        self.service.register_part("hw", "CTRL-K2", "controller", "国产替代控制器")
        self.arch = self.service.publish_architecture("hw", "arch-a", {
            "revision": "R1",
            "requirements": {
                "ctrl": {
                    "kind": "controller", "part_no": "CTRL-A1",
                    "min_firmware": "2.4.0",
                    "required_bus_protocols": ["ethercat"],
                },
            },
        })

    def tearDown(self) -> None:
        self.connection.close()

    def evidence(self, actor: str, part_no: str, kind: str, payload: dict | None = None) -> dict:
        payloads = {
            "vendor_declaration": {"vendor": "厂", "document_ref": "D1", "document_sha256": "a" * 64},
            "lineage": {"manufacturing_batch": "B1", "date_code": "2026-09-30", "parent_lot_id": None},
            "firmware_digest": {"firmware_baseline": "2.4.1", "image_sha256": "c" * 64},
            "interface_capability": {"bus_protocols": ["ethercat"], "electrical": {"v": 24}},
            "inspection": {"result": "pass", "report_ref": "Q1", "report_sha256": "d" * 64, "findings": []},
        }
        return self.service.submit_evidence(actor, part_no, kind, payload or payloads[kind])

    def full_evidence(self, part_no: str, *, inspection: str = "pass") -> dict[str, int]:
        ids = {
            "vendor_declaration": self.evidence("hw", part_no, "vendor_declaration")["evidence_id"],
            "lineage": self.evidence("hw", part_no, "lineage")["evidence_id"],
            "firmware_digest": self.evidence("sw", part_no, "firmware_digest")["evidence_id"],
            "interface_capability": self.evidence("sw", part_no, "interface_capability")["evidence_id"],
            "inspection": self.evidence("qa", part_no, "inspection", {
                "result": inspection, "report_ref": "Q1",
                "report_sha256": "d" * 64, "findings": [],
            })["evidence_id"],
        }
        return ids

    def sign_all(self, ids: dict[str, int]) -> None:
        self.service.sign_evidence("hw2", ids["vendor_declaration"], "confirmed")
        self.service.sign_evidence("hw2", ids["lineage"], "confirmed")
        self.service.sign_evidence("sw2", ids["firmware_digest"], "confirmed")
        self.service.sign_evidence("sw2", ids["interface_capability"], "confirmed")
        self.service.sign_evidence("qa2", ids["inspection"], "confirmed")

    def make_config(self, robot: str, part_no: str, serial: str, version: int = 1) -> str:
        result = self.service.register_configuration("hw", robot, "arch-a", version, {
            "ctrl": {"part_no": part_no, "serial_no": serial},
        })
        return result["config_sha256"]

    def install(self, serial: str, part_no: str, robot: str, digest: str) -> None:
        self.service.record_movement("hw", serial, part_no, "installed", robot, digest)

    def prepare_robot(self, robot: str, part_no: str, serial: str, **evidence_kwargs) -> str:
        ids = self.full_evidence(part_no, **evidence_kwargs)
        self.sign_all(ids)
        digest = self.make_config(robot, part_no, serial)
        self.install(serial, part_no, robot, digest)
        return digest


class RoleSeparationTests(ReleaseChainTestBase):
    def test_each_evidence_kind_is_owned_by_one_role(self) -> None:
        with self.assertRaises(Forbidden):
            self.evidence("sw", "CTRL-A1", "vendor_declaration")
        with self.assertRaises(Forbidden):
            self.evidence("qa", "CTRL-A1", "firmware_digest")
        with self.assertRaises(Forbidden):
            self.evidence("hw", "CTRL-A1", "inspection")
        eid = self.evidence("hw", "CTRL-A1", "vendor_declaration")["evidence_id"]
        with self.assertRaises(Forbidden):
            self.service.sign_evidence("sw2", eid, "confirmed")
        with self.assertRaises(Forbidden):
            self.service.sign_evidence("qa2", eid, "confirmed")

    def test_submitter_cannot_confirm_own_evidence(self) -> None:
        eid = self.evidence("hw", "CTRL-A1", "vendor_declaration")["evidence_id"]
        with self.assertRaises(Forbidden):
            self.service.sign_evidence("hw", eid, "confirmed")
        # 另一名硬件工程师可以确认
        self.service.sign_evidence("hw2", eid, "confirmed")

    def test_quality_alone_controls_substitution_and_release(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.approve_substitution(
                "hw", "S1", "CTRL-A1", "CTRL-K2", "理由", "arch-a", 1, 1)
        with self.assertRaises(Forbidden):
            self.service.approve_substitution(
                "sw", "S1", "CTRL-A1", "CTRL-K2", "理由", "arch-a", 1, 1)


class EvidenceChainTests(ReleaseChainTestBase):
    def test_evidence_is_versioned_and_supersedes_previous(self) -> None:
        first = self.evidence("sw", "CTRL-A1", "firmware_digest")
        second = self.service.submit_evidence(
            "sw", "CTRL-A1", "firmware_digest",
            {"firmware_baseline": "2.5.0", "image_sha256": "f" * 64})
        self.assertEqual((first["version"], second["version"]), (1, 2))
        row = self.connection.execute(
            "SELECT superseded_version FROM part_evidence WHERE evidence_id=?",
            (second["evidence_id"],)).fetchone()
        self.assertEqual(row["superseded_version"], first["evidence_id"])

    def test_old_versions_remain_readable_after_new_version(self) -> None:
        first = self.evidence("sw", "CTRL-A1", "firmware_digest")
        self.service.submit_evidence(
            "sw", "CTRL-A1", "firmware_digest",
            {"firmware_baseline": "2.5.0", "image_sha256": "f" * 64})
        detail = self.service.get_evidence("auditor", first["evidence_id"])
        self.assertEqual(detail["version"], 1)
        self.assertEqual(detail["payload"]["firmware_baseline"], "2.4.1")

    def test_evidence_rows_cannot_be_overwritten_or_deleted(self) -> None:
        eid = self.evidence("sw", "CTRL-A1", "firmware_digest")["evidence_id"]
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE part_evidence SET payload_json='{}' WHERE evidence_id=?", (eid,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("DELETE FROM part_evidence WHERE evidence_id=?", (eid,))

    def test_signoffs_cannot_be_overwritten(self) -> None:
        eid = self.evidence("sw", "CTRL-A1", "firmware_digest")["evidence_id"]
        self.service.sign_evidence("sw2", eid, "confirmed")
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE evidence_signoffs SET decision='rejected' WHERE evidence_id=?", (eid,))

    def test_revoked_evidence_cannot_be_signed_and_revocation_is_one_way(self) -> None:
        eid = self.evidence("sw", "CTRL-A1", "firmware_digest")["evidence_id"]
        self.service.revoke_evidence("qa", eid, "摘要复核不符")
        with self.assertRaises(InvalidState):
            self.service.sign_evidence("sw2", eid, "confirmed")
        with self.assertRaises(InvalidState):
            self.service.revoke_evidence("qa", eid, "再次失效")
        # 撤销不能借 UPDATE 通道改回
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE part_evidence SET revoked=0 WHERE evidence_id=?", (eid,))


class CompatibilityGateTests(ReleaseChainTestBase):
    def test_blocked_when_evidence_or_signoffs_missing(self) -> None:
        digest = self.make_config("R1", "CTRL-A1", "SN1")
        self.install("SN1", "CTRL-A1", "R1", digest)
        result = self.service.evaluate_configuration("qa", digest)
        self.assertEqual(result["gate"], "blocked")
        self.assertTrue(any("vendor_declaration" in p for p in result["pending"]))
        with self.assertRaises(InvalidState):
            self.service.decide_release("qa", digest, "released", "强行放行")

    def test_blocked_when_signoff_rejected(self) -> None:
        ids = self.full_evidence("CTRL-A1")
        self.service.sign_evidence("hw2", ids["vendor_declaration"], "confirmed")
        self.service.sign_evidence("hw2", ids["lineage"], "confirmed")
        self.service.sign_evidence("sw2", ids["firmware_digest"], "confirmed")
        self.service.sign_evidence("sw2", ids["interface_capability"], "confirmed")
        self.service.sign_evidence("qa2", ids["inspection"], "rejected", "抽检异常")
        digest = self.make_config("R1", "CTRL-A1", "SN1")
        self.install("SN1", "CTRL-A1", "R1", digest)
        result = self.service.evaluate_configuration("qa", digest)
        self.assertEqual(result["gate"], "blocked")
        self.assertTrue(any("驳回" in b for b in result["blockers"]))

    def test_firmware_below_architecture_minimum_blocks(self) -> None:
        ids = self.full_evidence("CTRL-A1")
        self.sign_all(ids)
        digest = self.make_config("R1", "CTRL-A1", "SN1")
        self.install("SN1", "CTRL-A1", "R1", digest)
        self.assertTrue(self.service.evaluate_configuration("qa", digest)["gate"] == "released")
        # 架构 v2 抬高固件基线到 3.0.0
        self.service.publish_architecture("hw", "arch-a", {
            "revision": "R2",
            "requirements": {
                "ctrl": {"kind": "controller", "part_no": "CTRL-A1",
                         "min_firmware": "3.0.0", "required_bus_protocols": ["ethercat"]},
            },
        })
        digest2 = self.make_config("R2", "CTRL-A1", "SN2", version=2)
        self.install("SN2", "CTRL-A1", "R2", digest2)
        result = self.service.evaluate_configuration("qa", digest2)
        self.assertEqual(result["gate"], "blocked")
        self.assertTrue(any("低于架构要求" in b for b in result["blockers"]))

    def test_missing_bus_protocol_blocks(self) -> None:
        ids = self.full_evidence("CTRL-A1")
        # 用只支持 can-fd 的能力证据覆盖最新版本
        self.evidence("sw", "CTRL-A1", "interface_capability", {
            "bus_protocols": ["can-fd"], "electrical": {}})
        self.sign_all(ids)
        digest = self.make_config("R1", "CTRL-A1", "SN1")
        self.install("SN1", "CTRL-A1", "R1", digest)
        result = self.service.evaluate_configuration("qa", digest)
        self.assertTrue(any("ethercat" in b for b in result["blockers"]))

    def test_inspection_must_pass(self) -> None:
        for result_text in ("conditional", "fail"):
            ids = self.full_evidence("CTRL-A1", inspection=result_text)
            self.sign_all(ids)
            digest = self.make_config(f"R-{result_text}", "CTRL-A1", f"SN-{result_text}")
            self.install(f"SN-{result_text}", "CTRL-A1", f"R-{result_text}", digest)
            self.assertEqual(self.service.evaluate_configuration("qa", digest)["gate"], "blocked")

    def test_unsubstituted_part_is_rejected(self) -> None:
        ids = self.full_evidence("CTRL-K2")
        self.sign_all(ids)
        digest = self.make_config("R1", "CTRL-K2", "SNK")
        self.install("SNK", "CTRL-K2", "R1", digest)
        result = self.service.evaluate_configuration("qa", digest)
        self.assertEqual(result["gate"], "blocked")
        self.assertTrue(any("替代料批准" in b for b in result["blockers"]))

    def test_substitution_scope_must_cover_architecture_version(self) -> None:
        ids = self.full_evidence("CTRL-K2")
        self.sign_all(ids)
        # 仅覆盖 v1
        self.service.approve_substitution(
            "qa", "SUB-1", "CTRL-A1", "CTRL-K2", "等效验证通过", "arch-a", 1, 1)
        self.service.publish_architecture("hw", "arch-a", {
            "revision": "R2",
            "requirements": {
                "ctrl": {"kind": "controller", "part_no": "CTRL-A1",
                         "min_firmware": "2.4.0", "required_bus_protocols": ["ethercat"]},
            },
        })
        digest = self.make_config("R2", "CTRL-K2", "SNK", version=2)
        self.install("SNK", "CTRL-K2", "R2", digest)
        result = self.service.evaluate_configuration("qa", digest)
        self.assertEqual(result["gate"], "blocked")
        self.assertTrue(any("替代料批准" in b for b in result["blockers"]))

    def test_revoked_substitution_blocks_pending(self) -> None:
        ids = self.full_evidence("CTRL-K2")
        self.sign_all(ids)
        self.service.approve_substitution(
            "qa", "SUB-1", "CTRL-A1", "CTRL-K2", "等效", "arch-a", 1, 1)
        digest = self.make_config("R1", "CTRL-K2", "SNK")
        self.install("SNK", "CTRL-K2", "R1", digest)
        self.assertEqual(self.service.evaluate_configuration("qa", digest)["gate"], "released")
        self.service.revoke_substitution("qa", "SUB-1", "替代料批准撤销")
        self.assertEqual(self.service.evaluate_configuration("qa", digest)["gate"], "blocked")


class ReleaseFreezeTests(ReleaseChainTestBase):
    def test_shipped_conclusion_is_frozen_even_when_evidence_revoked(self) -> None:
        shipped = self.prepare_robot("ROBOT-S", "CTRL-A1", "SN-S")
        self.assertEqual(self.service.evaluate_configuration("qa", shipped)["gate"], "released")
        self.service.decide_release("qa", shipped, "released", "准予放行")
        self.service.ship_release("qa", shipped)

        pending = self.prepare_robot("ROBOT-P", "CTRL-A1", "SN-P")

        # 失效检验证据：影响待放行，不影响已出厂
        evidence_rows = self.connection.execute(
            "SELECT evidence_id FROM part_evidence WHERE part_no='CTRL-A1' AND kind='inspection' "
            "ORDER BY version DESC"
        ).fetchall()
        for row in evidence_rows:
            self.service.revoke_evidence("qa", row["evidence_id"], "检验设备失准")

        explanation = self.service.explain_robot("auditor", shipped)
        self.assertTrue(explanation["factory_sealed"])
        self.assertEqual(explanation["release_decision"], "released")
        self.assertEqual(self.service.evaluate_configuration("qa", pending)["gate"], "blocked")
        with self.assertRaises(InvalidState):
            self.service.evaluate_configuration("qa", shipped)
        with self.assertRaises(InvalidState):
            self.service.decide_release("qa", shipped, "rejected", "试图回写")
        # 数据库层面同样拒绝回写
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE assembly_releases SET decision='rejected' WHERE config_sha256=?", (shipped,))

    def test_only_released_can_ship(self) -> None:
        digest = self.make_config("R1", "CTRL-A1", "SN1")
        self.install("SN1", "CTRL-A1", "R1", digest)
        self.service.evaluate_configuration("qa", digest)
        with self.assertRaises(InvalidState):
            self.service.ship_release("qa", digest)

    def test_configuration_is_immutable(self) -> None:
        digest = self.make_config("R1", "CTRL-A1", "SN1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE robot_configurations SET robot_serial='X' WHERE config_sha256=?", (digest,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("DELETE FROM robot_configurations WHERE config_sha256=?", (digest,))


class SerialTraceTests(ReleaseChainTestBase):
    def test_movement_state_machine_and_trace(self) -> None:
        digest = self.prepare_robot("R1", "CTRL-A1", "SN1")
        # 已安装不能重复安装
        with self.assertRaises(InvalidState):
            self.install("SN1", "CTRL-A1", "R1", digest)
        self.service.record_movement("hw", "SN1", "CTRL-A1", "removed", "R1", digest, "拆出")
        self.service.record_movement("hw", "SN1", "CTRL-A1", "reworked", note="返修")
        self.service.record_movement("hw", "SN1", "CTRL-A1", "installed", "R1", digest, "装回")
        trace = self.service.serial_trace("auditor", "SN1")
        self.assertEqual(
            [m["event"] for m in trace["movements"]],
            ["installed", "removed", "reworked", "installed"])
        self.assertEqual(trace["state"], "installed")
        self.assertEqual(trace["location"]["robot_serial"], "R1")

    def test_install_requires_serial_listed_in_configuration(self) -> None:
        digest = self.make_config("R1", "CTRL-A1", "SN1")
        with self.assertRaises(ValidationFailed):
            self.install("SN-OTHER", "CTRL-A1", "R1", digest)

    def test_scrapped_serial_has_terminal_state(self) -> None:
        digest = self.prepare_robot("R1", "CTRL-A1", "SN1")
        self.service.record_movement("hw", "SN1", "CTRL-A1", "scrapped", note="报废")
        with self.assertRaises(InvalidState):
            self.service.record_movement("hw", "SN1", "CTRL-A1", "installed", "R1", digest)
        trace = self.service.serial_trace("auditor", "SN1")
        self.assertTrue(trace["scrapped"])
        self.assertIsNone(trace["location"])

    def test_movement_rows_are_immutable(self) -> None:
        self.prepare_robot("R1", "CTRL-A1", "SN1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("UPDATE serial_movements SET event='scrapped'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("DELETE FROM serial_movements")


class ExplanationTests(ReleaseChainTestBase):
    def test_explain_why_part_lot_is_allowed(self) -> None:
        ids = self.full_evidence("CTRL-K2")
        self.sign_all(ids)
        self.service.approve_substitution(
            "qa", "SUB-1", "CTRL-A1", "CTRL-K2", "国产替代等效验证", "arch-a", 1, 1)
        digest = self.make_config("R1", "CTRL-K2", "SNK")
        self.install("SNK", "CTRL-K2", "R1", digest)
        self.service.evaluate_configuration("qa", digest)
        explanation = self.service.explain_robot("hw", digest)
        slot = explanation["slots"][0]
        self.assertEqual(slot["nominal_part_no"], "CTRL-A1")
        self.assertEqual(slot["substitution"]["substitution_id"], "SUB-1")
        self.assertEqual(slot["evidence"]["lineage"]["manufacturing_batch"], "B1")
        self.assertEqual(slot["evidence"]["firmware_digest"]["confirmed_by"], "sw2")
        self.assertEqual(explanation["blockers"], [])

    def test_explain_lists_outstanding_signoffs(self) -> None:
        self.full_evidence("CTRL-A1")  # 全部未签署
        digest = self.make_config("R1", "CTRL-A1", "SN1")
        self.install("SN1", "CTRL-A1", "R1", digest)
        self.service.evaluate_configuration("qa", digest)
        explanation = self.service.explain_robot("qa2", digest)
        pending_text = "\n".join(explanation["pending"])
        self.assertIn("hardware", pending_text)
        self.assertIn("software", pending_text)
        self.assertIn("quality", pending_text)


class CoverageTests(ReleaseChainTestBase):
    def test_coverage_separates_pending_and_factory_configurations(self) -> None:
        shipped = self.prepare_robot("ROBOT-S", "CTRL-A1", "SN-S")
        self.service.evaluate_configuration("qa", shipped)
        self.service.decide_release(
            "qa", shipped, "released", "ok")
        self.service.ship_release("qa", shipped)

        ids = self.full_evidence("CTRL-K2")
        self.sign_all(ids)
        self.service.approve_substitution(
            "qa", "SUB-1", "CTRL-A1", "CTRL-K2", "等效", "arch-a", 1, 1)
        pending = self.make_config("ROBOT-P", "CTRL-K2", "SNK")
        self.install("SNK", "CTRL-K2", "ROBOT-P", pending)

        coverage = self.service.substitution_coverage("auditor", "SUB-1")
        affected = {item["config_sha256"] for item in coverage["affects_pending_configurations"]}
        frozen = {item["config_sha256"] for item in coverage["frozen_factory_configurations"]}
        self.assertEqual(affected, {pending})
        self.assertEqual(frozen, set())

    def test_substitution_same_id_keeps_part_pair_and_is_versioned(self) -> None:
        self.service.approve_substitution(
            "qa", "SUB-1", "CTRL-A1", "CTRL-K2", "v1 理由", "arch-a", 1, 1)
        # 架构发布 v2 后，替代决定新版本扩展覆盖范围
        self.service.publish_architecture("hw", "arch-a", {
            "revision": "R2",
            "requirements": {
                "ctrl": {"kind": "controller", "part_no": "CTRL-A1",
                         "min_firmware": "2.4.0", "required_bus_protocols": ["ethercat"]},
            },
        })
        self.service.approve_substitution(
            "qa", "SUB-1", "CTRL-A1", "CTRL-K2", "v2 扩展范围", "arch-a", 1, 2)
        coverage = self.service.substitution_coverage("auditor", "SUB-1")
        self.assertEqual(coverage["latest_version"], 2)
        self.assertEqual(coverage["coverage"]["applies_to_version"], 2)
        with self.assertRaises(ValidationFailed):
            self.service.approve_substitution("qa", "SUB-1", "CTRL-A1", "CTRL-A1", "换料号")


class ArchitectureTests(ReleaseChainTestBase):
    def test_identical_content_cannot_create_new_version(self) -> None:
        with self.assertRaises(Conflict):
            self.service.publish_architecture("hw", "arch-a", {
                "revision": "R1",
                "requirements": {
                    "ctrl": {"kind": "controller", "part_no": "CTRL-A1",
                             "min_firmware": "2.4.0", "required_bus_protocols": ["ethercat"]},
                },
            })

    def test_configuration_slots_must_match_architecture(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.register_configuration("hw", "R9", "arch-a", 1, {
                "ctrl": {"part_no": "CTRL-A1", "serial_no": "SN1"},
                "extra": {"part_no": "CTRL-A1", "serial_no": "SN2"},
            })


if __name__ == "__main__":
    unittest.main()
