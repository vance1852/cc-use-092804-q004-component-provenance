"""部件来源与兼容放行链的输入契约与校验。"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .errors import ValidationFailed


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
DIGEST64 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z._-]+)?$")

COMPONENT_KINDS = ("controller", "bus_chip", "ai_compute")
EVIDENCE_KINDS = (
    "vendor_declaration",
    "lineage",
    "firmware_digest",
    "interface_capability",
    "inspection",
)
# 证据类型 -> 负责确认该证据的角色
EVIDENCE_OWNER = {
    "vendor_declaration": "hardware",
    "lineage": "hardware",
    "firmware_digest": "software",
    "interface_capability": "software",
    "inspection": "quality",
}
SIGN_DECISIONS = ("confirmed", "rejected")
INSPECTION_RESULTS = ("pass", "fail", "conditional")
SERIAL_EVENTS = ("installed", "removed", "reworked", "scrapped")
RELEASE_DECISIONS = ("released", "rejected")


def required_text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field} 不能为空")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{field} 不能超过 {maximum} 个字符")
    return result


def optional_text(value: object, field: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return required_text(value, field, maximum)


def identifier(value: object, field: str) -> str:
    result = required_text(value, field, 64)
    if not IDENTIFIER.fullmatch(result):
        raise ValidationFailed(f"{field} 格式不正确")
    return result


def digest(value: object, field: str) -> str:
    result = required_text(value, field, 128).lower()
    if not DIGEST64.fullmatch(result):
        raise ValidationFailed(f"{field} 必须是 64 位十六进制 SHA-256 摘要")
    return result


def firmware_baseline(value: object) -> str:
    result = required_text(value, "firmware_baseline", 64)
    if not SEMVER.fullmatch(result):
        raise ValidationFailed("firmware_baseline 必须是语义化版本（如 2.4.1）")
    return result


def choice(value: object, field: str, choices: tuple[str, ...]) -> str:
    result = required_text(value, field, 32)
    if result not in choices:
        raise ValidationFailed(f"{field} 必须是 {', '.join(choices)} 之一")
    return result


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationFailed(f"{field} 必须是对象")
    return value


def validate_declaration(raw: Mapping[str, Any]) -> dict[str, Any]:
    vendor = required_text(raw.get("vendor"), "declaration.vendor", 128)
    doc_ref = required_text(raw.get("document_ref"), "declaration.document_ref", 128)
    digest_value = digest(raw.get("document_sha256"), "declaration.document_sha256")
    return {"vendor": vendor, "document_ref": doc_ref, "document_sha256": digest_value}


def validate_lineage(raw: Mapping[str, Any]) -> dict[str, Any]:
    batch_no = required_text(raw.get("manufacturing_batch"), "lineage.manufacturing_batch", 64)
    date_code = required_text(raw.get("date_code"), "lineage.date_code", 32)
    parent = optional_text(raw.get("parent_lot_id"), "lineage.parent_lot_id", 64)
    return {"manufacturing_batch": batch_no, "date_code": date_code, "parent_lot_id": parent}


def validate_firmware(raw: Mapping[str, Any]) -> dict[str, Any]:
    baseline = firmware_baseline(raw.get("firmware_baseline"))
    image_digest = digest(raw.get("image_sha256"), "firmware.image_sha256")
    return {"firmware_baseline": baseline, "image_sha256": image_digest}


def validate_capabilities(raw: Mapping[str, Any]) -> dict[str, Any]:
    protocols = raw.get("bus_protocols")
    if not isinstance(protocols, list) or not protocols or not all(
        isinstance(item, str) and item.strip() for item in protocols
    ):
        raise ValidationFailed("capabilities.bus_protocols 必须是非空字符串数组")
    electrical = _mapping(raw.get("electrical"), "capabilities.electrical")
    for key, value in electrical.items():
        if not isinstance(key, str) or not isinstance(value, (str, int, float, bool)):
            raise ValidationFailed("capabilities.electrical 只能包含标量值")
    return {
        "bus_protocols": [item.strip() for item in protocols],
        "electrical": {str(key).strip(): value for key, value in electrical.items()},
    }


def validate_inspection(raw: Mapping[str, Any]) -> dict[str, Any]:
    result = choice(raw.get("result"), "inspection.result", INSPECTION_RESULTS)
    report_ref = required_text(raw.get("report_ref"), "inspection.report_ref", 128)
    report_digest = digest(raw.get("report_sha256"), "inspection.report_sha256")
    findings = raw.get("findings", [])
    if not isinstance(findings, list) or not all(isinstance(item, str) for item in findings):
        raise ValidationFailed("inspection.findings 必须是字符串数组")
    return {
        "result": result,
        "report_ref": report_ref,
        "report_sha256": report_digest,
        "findings": list(findings),
    }


EVIDENCE_VALIDATORS = {
    "vendor_declaration": validate_declaration,
    "lineage": validate_lineage,
    "firmware_digest": validate_firmware,
    "interface_capability": validate_capabilities,
    "inspection": validate_inspection,
}


def validate_evidence(kind: str, raw: object) -> dict[str, Any]:
    if kind not in EVIDENCE_KINDS:
        raise ValidationFailed(f"未知证据类型: {kind}")
    return EVIDENCE_VALIDATORS[kind](_mapping(raw, "payload"))


def validate_architecture(raw: object) -> dict[str, Any]:
    mapping = _mapping(raw, "architecture_revision")
    revision = required_text(mapping.get("revision"), "architecture.revision", 32)
    requirements = mapping.get("requirements", {})
    if not isinstance(requirements, Mapping):
        raise ValidationFailed("architecture.requirements 必须是对象")
    normalized: dict[str, Any] = {}
    for slot, slot_req in requirements.items():
        slot_req = _mapping(slot_req, f"architecture.requirements.{slot}")
        kind = choice(slot_req.get("kind"), f"requirements.{slot}.kind", COMPONENT_KINDS)
        part_no = identifier(slot_req.get("part_no"), f"requirements.{slot}.part_no")
        firmware = slot_req.get("min_firmware")
        protocols = slot_req.get("required_bus_protocols", [])
        if firmware is not None:
            firmware = firmware_baseline(firmware)
        if not isinstance(protocols, list) or not all(isinstance(item, str) for item in protocols):
            raise ValidationFailed(f"requirements.{slot}.required_bus_protocols 必须是字符串数组")
        normalized[identifier(slot, "slot")] = {
            "kind": kind,
            "part_no": part_no,
            "min_firmware": firmware,
            "required_bus_protocols": list(protocols),
        }
    if not normalized:
        raise ValidationFailed("architecture.requirements 至少声明一个装配槽位")
    return {"revision": revision, "requirements": normalized}


def validate_position(raw: object) -> dict[str, str]:
    mapping = _mapping(raw, "configuration")
    position: dict[str, str] = {}
    for slot, ref in mapping.items():
        slot_id = identifier(slot, "slot")
        value = _mapping(ref, f"configuration.{slot}")
        part_no = identifier(value.get("part_no"), f"configuration.{slot}.part_no")
        serial = required_text(value.get("serial_no"), f"configuration.{slot}.serial_no", 64)
        position[slot_id] = {"part_no": part_no, "serial_no": serial}
    if not position:
        raise ValidationFailed("配置至少包含一个装配槽位")
    return position
