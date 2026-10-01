"""部件来源与兼容放行链的输入契约校验。"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .errors import ValidationFailed


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
CATEGORIES = {"controller", "bus_chip", "ai_compute"}
INSPECTION_RESULTS = {"pass", "fail"}
DISPOSITIONS = {"rework", "scrapped", "returned"}
EVIDENCE_KINDS = {
    "vendor_declaration",
    "firmware_baseline",
    "interface_capability",
    "inspection",
    "substitution",
}
INVALIDATABLE_KINDS = EVIDENCE_KINDS | {"batch"}


def required_text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field} 不能为空")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{field} 不能超过 {maximum} 个字符")
    return result


def identifier(value: object, field: str) -> str:
    result = required_text(value, field, 64)
    if not IDENTIFIER.fullmatch(result):
        raise ValidationFailed(f"{field} 格式不正确")
    return result


def positive_version(value: object, field: str = "version") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationFailed(f"{field} 必须是正整数")
    return value


def sha256_hex(value: object, field: str) -> str:
    result = required_text(value, field, 64).lower()
    if not SHA256_HEX.fullmatch(result):
        raise ValidationFailed(f"{field} 必须是 64 位十六进制 SHA-256")
    return result


def category(value: object, field: str = "category") -> str:
    result = required_text(value, field, 32)
    if result not in CATEGORIES:
        raise ValidationFailed(f"{field} 必须是 controller、bus_chip 或 ai_compute")
    return result


def capability_map(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ValidationFailed(f"{field} 必须是对象")
    if len(value) > 64:
        raise ValidationFailed(f"{field} 不能超过 64 项")
    result: dict[str, str] = {}
    for key, item in value.items():
        name = required_text(key, f"{field} 键", 64)
        result[name] = required_text(item, f"{field}.{name}", 128)
    return result


def identifier_list(value: object, field: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, list):
        raise ValidationFailed(f"{field} 必须是数组")
    if not value and not allow_empty:
        raise ValidationFailed(f"{field} 不能为空数组")
    result = [identifier(item, f"{field} 元素") for item in value]
    if len(set(result)) != len(result):
        raise ValidationFailed(f"{field} 不能含重复元素")
    return result


def slot_definitions(value: object) -> list[dict[str, Any]]:
    """校验架构版本的槽位定义数组。"""

    if not isinstance(value, list) or not value:
        raise ValidationFailed("slots 必须是非空数组")
    if len(value) > 32:
        raise ValidationFailed("slots 不能超过 32 个槽位")
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        field = f"slots[{index}]"
        if not isinstance(item, Mapping):
            raise ValidationFailed(f"{field} 必须是对象")
        slot_id = identifier(item.get("slot_id"), f"{field}.slot_id")
        if slot_id in seen:
            raise ValidationFailed(f"槽位编号重复: {slot_id}")
        seen.add(slot_id)
        result.append(
            {
                "slot_id": slot_id,
                "category": category(item.get("category"), f"{field}.category"),
                "required_capabilities": capability_map(
                    item.get("required_capabilities", {}), f"{field}.required_capabilities"
                ),
                "allowed_models": identifier_list(
                    item.get("allowed_models"), f"{field}.allowed_models", allow_empty=False
                ),
                "required_inspections": identifier_list(
                    item.get("required_inspections", []),
                    f"{field}.required_inspections",
                    allow_empty=True,
                ),
            }
        )
    return result


def config_slot_pins(value: object) -> list[dict[str, Any]]:
    """校验整机配置的槽位占位数组。"""

    if not isinstance(value, list) or not value:
        raise ValidationFailed("slots 必须是非空数组")
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        field = f"slots[{index}]"
        if not isinstance(item, Mapping):
            raise ValidationFailed(f"{field} 必须是对象")
        slot_id = identifier(item.get("slot_id"), f"{field}.slot_id")
        if slot_id in seen:
            raise ValidationFailed(f"槽位编号重复: {slot_id}")
        seen.add(slot_id)
        result.append(
            {
                "slot_id": slot_id,
                "model_id": identifier(item.get("model_id"), f"{field}.model_id"),
                "batch_id": identifier(item.get("batch_id"), f"{field}.batch_id"),
                "firmware_id": identifier(item.get("firmware_id"), f"{field}.firmware_id"),
                "firmware_version": positive_version(
                    item.get("firmware_version"), f"{field}.firmware_version"
                ),
            }
        )
    return result


def evidence_kind(value: object, *, allow_batch: bool = False) -> str:
    result = required_text(value, "evidence_kind", 64)
    allowed = INVALIDATABLE_KINDS if allow_batch else EVIDENCE_KINDS
    if result not in allowed:
        raise ValidationFailed(f"evidence_kind 必须是 {sorted(allowed)} 之一")
    return result


def inspection_result(value: object) -> str:
    result = required_text(value, "result", 16)
    if result not in INSPECTION_RESULTS:
        raise ValidationFailed("result 必须是 pass 或 fail")
    return result


def disposition(value: object) -> str:
    result = required_text(value, "disposition", 16)
    if result not in DISPOSITIONS:
        raise ValidationFailed("disposition 必须是 rework、scrapped 或 returned")
    return result


def json_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationFailed(f"{field} 必须是对象")
    return dict(value)
