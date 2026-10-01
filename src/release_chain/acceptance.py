"""部件来源与兼容放行链的完整离线验收。

故事线：
1. 硬件/软件/质量分别登记部件、提交并确认各自证据；
2. 同一架构版本内，国产替代料经批准后覆盖待放行配置；
3. 一台机器人完成签署与检验后放行出厂；
4. 出厂后证据失效：出厂结论冻结不可回写，新配置被阻断；
5. 换件返工保持序列号去向可追。
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .service import ReleaseChainService
from .storage import connect, inspect_schema


def _submit_all_evidence(service: ReleaseChainService, part_no: str, *, inspection: str = "pass") -> dict[str, str]:
    ids: dict[str, str] = {}
    ids["vendor_declaration"] = service.submit_evidence(
        "hw", part_no, "vendor_declaration",
        {"vendor": "国产控制器厂", "document_ref": f"DOC-{part_no}",
         "document_sha256": "a" * 64})["evidence_id"]
    ids["lineage"] = service.submit_evidence(
        "hw", part_no, "lineage",
        {"manufacturing_batch": f"B-{part_no}-2026w38", "date_code": "2026-09-18",
         "parent_lot_id": None})["evidence_id"]
    ids["firmware_digest"] = service.submit_evidence(
        "sw", part_no, "firmware_digest",
        {"firmware_baseline": "2.4.1", "image_sha256": "c" * 64})["evidence_id"]
    ids["interface_capability"] = service.submit_evidence(
        "sw", part_no, "interface_capability",
        {"bus_protocols": ["ethercat", "can-fd"], "electrical": {"voltage_v": 24}})["evidence_id"]
    ids["inspection"] = service.submit_evidence(
        "qa", part_no, "inspection",
        {"result": inspection, "report_ref": f"QAR-{part_no}",
         "report_sha256": "d" * 64, "findings": []})["evidence_id"]
    return ids


def _sign_all(service: ReleaseChainService, ids: dict[str, str]) -> None:
    # 提交人与确认人不同角色；硬件、软件、质量各司其职
    service.sign_evidence("hw2", ids["vendor_declaration"], "confirmed", "声明文件齐套")
    service.sign_evidence("hw2", ids["lineage"], "confirmed", "批次谱系可追溯")
    service.sign_evidence("sw2", ids["firmware_digest"], "confirmed", "固件摘要复核一致")
    service.sign_evidence("sw2", ids["interface_capability"], "confirmed", "接口能力满足架构")
    service.sign_evidence("qa2", ids["inspection"], "confirmed", "入厂检验合格")


def run(workspace: Path | None = None) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="release-chain-") as temporary:
        connection = connect(Path(temporary) / "release-chain.sqlite3")
        try:
            service = ReleaseChainService(connection)
            service.bootstrap_admin()

            # 角色账号：硬件、软件、质量各两名（提交与确认分离），审计一名
            for uid, name, role in (
                ("hw", "硬件工程师甲", "hardware"), ("hw2", "硬件工程师乙", "hardware"),
                ("sw", "软件工程师甲", "software"), ("sw2", "软件工程师乙", "software"),
                ("qa", "质量工程师甲", "quality"), ("qa2", "质量工程师乙", "quality"),
                ("auditor", "审计员", "auditor"),
            ):
                service.create_user("admin", uid, name, role)

            # 部件主数据：名义控制器与国产替代控制器
            service.register_part("hw", "CTRL-A1", "controller", "名义型号运动控制器")
            service.register_part("hw", "CTRL-K2", "controller", "国产替代运动控制器")

            # 架构版本 v1：槽位要求名义料号、固件 >=2.4.0、EtherCAT
            arch = service.publish_architecture("hw", "humanoid-arch", {
                "revision": "EA-2026.1",
                "requirements": {
                    "main_controller": {
                        "kind": "controller", "part_no": "CTRL-A1",
                        "min_firmware": "2.4.0",
                        "required_bus_protocols": ["ethercat"],
                    },
                },
            })

            # --- 第一台机器人：使用名义料号，走完整证据与签署链 ---
            ids_a1 = _submit_all_evidence(service, "CTRL-A1")

            config1 = service.register_configuration("hw", "ROBOT-0001", "humanoid-arch", 1, {
                "main_controller": {"part_no": "CTRL-A1", "serial_no": "SN-A1-0001"},
            })
            for serial, part_no, robot, digest in (
                ("SN-A1-0001", "CTRL-A1", "ROBOT-0001", config1["config_sha256"]),
            ):
                service.record_movement("hw", serial, part_no, "installed", robot, digest, "首次装配")

            # 证据未签署时评估：必须被阻断并列出未完成签署
            blocked = service.evaluate_configuration("qa", config1["config_sha256"])
            assert blocked["gate"] == "blocked" and blocked["pending"], blocked

            _sign_all(service, ids_a1)
            evaluation = service.evaluate_configuration("qa", config1["config_sha256"])
            assert evaluation["gate"] == "released", evaluation["blockers"]
            service.decide_release("qa", config1["config_sha256"], "released", "证据与签署齐全，准予装配放行")
            service.ship_release("qa", config1["config_sha256"])

            # --- 第二台机器人：使用国产替代料，批准覆盖架构 v1 ---
            ids_k2 = _submit_all_evidence(service, "CTRL-K2")
            _sign_all(service, ids_k2)
            substitution = service.approve_substitution(
                "qa", "SUB-CTRL-01", "CTRL-A1", "CTRL-K2",
                "国产替代料完成等效性验证",
                architecture_id="humanoid-arch", applies_from_version=1, applies_to_version=1)
            config2 = service.register_configuration("hw", "ROBOT-0002", "humanoid-arch", 1, {
                "main_controller": {"part_no": "CTRL-K2", "serial_no": "SN-K2-0007"},
            })
            service.record_movement("hw", "SN-K2-0007", "CTRL-K2", "installed",
                                    "ROBOT-0002", config2["config_sha256"], "替代料装配")
            eval2 = service.evaluate_configuration("qa", config2["config_sha256"])
            assert eval2["gate"] == "released", eval2["blockers"]
            coverage = service.substitution_coverage("auditor", "SUB-CTRL-01")
            assert coverage["active"] and coverage["affects_pending_configurations"], coverage

            # --- 出厂后证据失效：ROBOT-0001 结论冻结，待放行的替代料配置被阻断 ---
            service.revoke_evidence("qa", ids_k2["firmware_digest"], "复测发现固件摘要与声明基线不符")
            frozen_explain = service.explain_robot("auditor", config1["config_sha256"])
            assert frozen_explain["factory_sealed"] is True
            assert frozen_explain["release_decision"] == "released"
            reeval = service.evaluate_configuration("qa", config2["config_sha256"])
            assert reeval["gate"] == "blocked", reeval
            assert any("已失效" in item for item in reeval["blockers"]), reeval["blockers"]
            # 出厂配置不能重新评估，数据库触发器也拒绝回写
            try:
                service.evaluate_configuration("qa", config1["config_sha256"])
                raise AssertionError("出厂配置不应允许重新评估")
            except Exception as exc:
                assert "冻结" in str(exc)

            # --- 返工换件：SN-K2-0007 拆出、返修后装回，去向链完整 ---
            service.record_movement("hw", "SN-K2-0007", "CTRL-K2", "removed",
                                    "ROBOT-0002", config2["config_sha256"], "拆出等待合格固件")
            service.record_movement("hw", "SN-K2-0007", "CTRL-K2", "reworked", note="刷写合格固件并复测")
            new_fw = service.submit_evidence(
                "sw", "CTRL-K2", "firmware_digest",
                {"firmware_baseline": "2.4.2", "image_sha256": "e" * 64})
            service.sign_evidence("sw2", new_fw["evidence_id"], "confirmed", "复测摘要一致")
            service.record_movement("hw", "SN-K2-0007", "CTRL-K2", "installed",
                                    "ROBOT-0002", config2["config_sha256"], "返工后装回")
            eval3 = service.evaluate_configuration("qa", config2["config_sha256"])
            assert eval3["gate"] == "released", eval3["blockers"]
            trace = service.serial_trace("auditor", "SN-K2-0007")
            assert [m["event"] for m in trace["movements"]] == [
                "installed", "removed", "reworked", "installed"], trace

            why = service.explain_robot("auditor", config2["config_sha256"])
            schema = inspect_schema(connection)
        finally:
            connection.close()

    return {
        "status": "ok",
        "architecture": f"humanoid-arch@{arch['version']}",
        "shipped_robot": "ROBOT-0001",
        "substitution": f"SUB-CTRL-01@{substitution['version']}",
        "shipped_conclusion_after_revocation": frozen_explain["release_decision"],
        "pending_config_blocked_after_revocation": reeval["gate"],
        "reworked_serial_events": [m["event"] for m in trace["movements"]],
        "explanation_slots": len(why["slots"]),
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="部件来源与兼容放行链离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
