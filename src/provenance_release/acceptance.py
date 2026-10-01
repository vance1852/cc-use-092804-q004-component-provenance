"""贯通部件来源、证据签署、装配放行、失效隔离与序列号追溯的离线验收。"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .clock import FrozenClock
from .errors import InvalidState
from .service import ProvenanceService
from .storage import inspect_schema


ARCH_SLOTS = [
    {
        "slot_id": "controller",
        "category": "controller",
        "required_capabilities": {"bus": "CAN-FD", "voltage": "3.3V"},
        "allowed_models": ["MCU-G1"],
        "required_inspections": ["ict", "burn_in"],
    },
    {
        "slot_id": "bus_chip",
        "category": "bus_chip",
        "required_capabilities": {"protocol": "EtherCAT", "channels": "2"},
        "allowed_models": ["BUS-T1"],
        "required_inspections": ["ict"],
    },
    {
        "slot_id": "ai_compute",
        "category": "ai_compute",
        "required_capabilities": {"runtime": "RKNN-2", "pcie": "3.0"},
        "allowed_models": ["NPU-A1"],
        "required_inspections": ["ict", "thermal"],
    },
]


def _prepare_evidence(service: ProvenanceService) -> dict[str, int]:
    for model_id, category, vendor, description in (
        ("MCU-G1", "controller", "华芯微", "国产运动控制单元"),
        ("MCU-G2", "controller", "华芯微", "国产运动控制单元替代料"),
        ("BUS-T1", "bus_chip", "通微", "国产实时总线芯片"),
        ("NPU-A1", "ai_compute", "燧核", "国产 AI 计算单元"),
    ):
        service.register_model("hw1", model_id, category, vendor, description)
    service.publish_architecture("hw1", "ARCH-R1", 1, "R1 整机电子架构", ARCH_SLOTS)
    for declaration_id, model_id in (
        ("DECL-MCU-G1", "MCU-G1"), ("DECL-MCU-G2", "MCU-G2"),
        ("DECL-BUS-T1", "BUS-T1"), ("DECL-NPU-A1", "NPU-A1"),
    ):
        vendor = {"MCU-G1": "华芯微", "MCU-G2": "华芯微", "BUS-T1": "通微", "NPU-A1": "燧核"}[model_id]
        service.register_declaration("hw1", declaration_id, 1, model_id, vendor, {"rohs": "合规", "origin": "国产"})
        service.confirm_evidence("hw2", "vendor_declaration", declaration_id, 1, "声明与采购合同一致")
    for firmware_id, model_id, digest in (
        ("FW-MCU1", "MCU-G1", "a" * 64),
        ("FW-MCU2", "MCU-G2", "b" * 64),
        ("FW-BUS", "BUS-T1", "c" * 64),
        ("FW-NPU", "NPU-A1", "d" * 64),
    ):
        service.register_firmware("sw1", firmware_id, 1, model_id, digest, "量产基线")
        service.confirm_evidence("sw2", "firmware_baseline", firmware_id, 1, "摘要与发布包一致")
    for capability_id, model_id, firmware_id, capabilities in (
        ("CAP-MCU-G1", "MCU-G1", "FW-MCU1", {"bus": "CAN-FD", "voltage": "3.3V", "uart": "4"}),
        ("CAP-MCU-G2", "MCU-G2", "FW-MCU2", {"bus": "CAN-FD", "voltage": "3.3V"}),
        ("CAP-BUS-T1", "BUS-T1", "FW-BUS", {"protocol": "EtherCAT", "channels": "2"}),
        ("CAP-NPU-A1", "NPU-A1", "FW-NPU", {"runtime": "RKNN-2", "pcie": "3.0", "tops": "16"}),
    ):
        service.register_capability("hw1", capability_id, 1, model_id, firmware_id, 1, capabilities)
        service.confirm_evidence("hw2", "interface_capability", capability_id, 1, "能力与联调记录一致")
    for batch_id, model_id, vendor, lot_code in (
        ("LOT-MCU-001", "MCU-G1", "华芯微", "L2026-09-A"),
        ("LOT-MCU2-001", "MCU-G2", "华芯微", "L2026-09-B"),
        ("LOT-BUS-001", "BUS-T1", "通微", "L2026-09-C"),
        ("LOT-NPU-001", "NPU-A1", "燧核", "L2026-09-D"),
    ):
        service.register_batch("op1", batch_id, model_id, vendor, lot_code)
    for batch_id, serial_ids in (
        ("LOT-MCU-001", ["SN-MCU-001", "SN-MCU-002", "SN-MCU-003"]),
        ("LOT-MCU2-001", ["SN-MCU2-001", "SN-MCU2-002"]),
        ("LOT-BUS-001", ["SN-BUS-001", "SN-BUS-002"]),
        ("LOT-NPU-001", ["SN-NPU-001", "SN-NPU-002"]),
    ):
        service.register_serials("op1", batch_id, serial_ids)
    inspection_ids: dict[str, int] = {}
    for batch_id, inspection_type in (
        ("LOT-MCU-001", "ict"), ("LOT-MCU-001", "burn_in"),
        ("LOT-MCU2-001", "ict"), ("LOT-MCU2-001", "burn_in"),
        ("LOT-BUS-001", "ict"),
        ("LOT-NPU-001", "ict"), ("LOT-NPU-001", "thermal"),
    ):
        recorded = service.record_inspection("q1", batch_id, inspection_type, "pass", f"report-{batch_id}-{inspection_type}")
        service.confirm_evidence("q2", "inspection", str(recorded["inspection_id"]), 1, "检验报告复核无误")
        inspection_ids[f"{batch_id}:{inspection_type}"] = recorded["inspection_id"]
    service.propose_substitution("hw1", "SUB-MCU-G2", 1, "ARCH-R1", 1, "controller", "MCU-G1", "MCU-G2",
                                 {"reason": "同封装国产替代", "derating": "无"})
    service.confirm_evidence("q2", "substitution", "SUB-MCU-G2", 1, "替代验证报告齐全")
    return inspection_ids


def _create_cfg1(service: ProvenanceService) -> None:
    service.create_config("op1", "CFG-0001", "R1 人形机器人", "ARCH-R1", 1, [
        {"slot_id": "controller", "model_id": "MCU-G1", "batch_id": "LOT-MCU-001",
         "firmware_id": "FW-MCU1", "firmware_version": 1},
        {"slot_id": "bus_chip", "model_id": "BUS-T1", "batch_id": "LOT-BUS-001",
         "firmware_id": "FW-BUS", "firmware_version": 1},
        {"slot_id": "ai_compute", "model_id": "NPU-A1", "batch_id": "LOT-NPU-001",
         "firmware_id": "FW-NPU", "firmware_version": 1},
    ])
    service.assemble_config("op1", "CFG-0001",
                            {"controller": "SN-MCU-001", "bus_chip": "SN-BUS-001", "ai_compute": "SN-NPU-001"})


def _create_cfg2(service: ProvenanceService) -> None:
    service.create_config("op1", "CFG-0002", "R1 人形机器人", "ARCH-R1", 1, [
        {"slot_id": "controller", "model_id": "MCU-G2", "batch_id": "LOT-MCU2-001",
         "firmware_id": "FW-MCU2", "firmware_version": 1},
        {"slot_id": "bus_chip", "model_id": "BUS-T1", "batch_id": "LOT-BUS-001",
         "firmware_id": "FW-BUS", "firmware_version": 1},
        {"slot_id": "ai_compute", "model_id": "NPU-A1", "batch_id": "LOT-NPU-001",
         "firmware_id": "FW-NPU", "firmware_version": 1},
    ])
    service.assemble_config("op1", "CFG-0002",
                            {"controller": "SN-MCU2-001", "bus_chip": "SN-BUS-002", "ai_compute": "SN-NPU-002"})


def run(workspace: Path) -> dict[str, object]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    service = ProvenanceService(connection, FrozenClock(datetime(2026, 9, 28, 8, 0, tzinfo=timezone.utc)))
    try:
        for user_id, role in (
            ("hw1", "hardware"), ("hw2", "hardware"),
            ("sw1", "software"), ("sw2", "software"),
            ("q1", "quality"), ("q2", "quality"),
            ("op1", "operator"), ("au1", "auditor"),
        ):
            service.create_user(user_id, user_id, role)
        inspection_ids = _prepare_evidence(service)

        # 第一台整机：完整证据链 → 放行 → 出厂。
        _create_cfg1(service)
        pending_before = service.pending_items("q1", "CFG-0001")
        release1 = service.release_config("q1", "CFG-0001")
        ship1 = service.ship_config("op1", "CFG-0001")

        # 第二台整机：控制器走国产替代料，替代关系覆盖可查。
        _create_cfg2(service)
        release2 = service.release_config("q1", "CFG-0002")
        coverage = service.substitution_coverage("q1", "SUB-MCU-G2")

        # 批次拆分、返工与换件保持序列号去向可追。
        split = service.split_batch("op1", "LOT-MCU-001", [
            {"batch_id": "LOT-MCU-001A", "lot_code": "L2026-09-A1",
             "serial_ids": ["SN-MCU-002", "SN-MCU-003"], "note": "分线装配"},
        ])
        service.rework_serial("op1", "SN-MCU-002", "外观复检")
        service.return_serial("op1", "SN-MCU-002", "复检合格")
        replaced = service.replace_serial("op1", "CFG-0002", "controller", "SN-MCU2-002", "rework", "来料复测")
        service.release_config("q1", "CFG-0002")
        trace = service.serial_trace("au1", "SN-MCU2-001")

        # 证据失效只影响尚未出厂的配置；已出厂事实不回写。
        thermal_id = inspection_ids["LOT-NPU-001:thermal"]
        invalidation = service.invalidate_evidence("q1", "inspection", str(thermal_id), 1, "热测试设备校准超期")
        blocked_ship = False
        try:
            service.ship_config("op1", "CFG-0002")
        except InvalidState:
            blocked_ship = True
        cfg1_after = service.explain_config("au1", "CFG-0001")
        cfg2_pending = service.pending_items("q1", "CFG-0002")

        # 新检验证据登记并确认后，待放行配置恢复放行并出厂。
        renewed = service.record_inspection("q1", "LOT-NPU-001", "thermal", "pass", "report-LOT-NPU-001-thermal-r2")
        service.confirm_evidence("q2", "inspection", str(renewed["inspection_id"]), 1, "复测报告复核无误")
        release2b = service.release_config("q1", "CFG-0002")
        ship2 = service.ship_config("op1", "CFG-0002")

        audit = service.audit_chain("au1")
        schema = inspect_schema(connection)
    finally:
        connection.close()
    if schema["missing_tables"] or not audit["valid"] or not blocked_ship:
        raise RuntimeError("离线验收自检失败")
    return {
        "status": "ok",
        "cfg1_pending_complete": pending_before["complete"],
        "cfg1_release": release1["conclusion"],
        "cfg1_state": ship1["state"],
        "cfg2_release_via_substitution": release2["conclusion"],
        "substitution_dependents": [item["config_id"] for item in coverage["dependent_configs"]],
        "split_children": [child["batch_id"] for child in split["children"]],
        "replaced_state": replaced["state"],
        "replaced_out_events": [event["event_type"] for event in trace["events"]],
        "invalidation_impact": invalidation["impact"],
        "cfg1_post_shipment_advisories": len(cfg1_after["post_shipment_advisories"]),
        "cfg2_pending_after_invalidation": [item["message"] for item in cfg2_pending["items"]],
        "cfg2_rerelease": release2b["conclusion"],
        "cfg2_state": ship2["state"],
        "audit": audit,
        "schema": schema,
        "workspace": workspace.name,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行部件来源与兼容放行链离线验收")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(json.dumps(run(args.workspace), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
