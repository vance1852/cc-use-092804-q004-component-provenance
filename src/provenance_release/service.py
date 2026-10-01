"""部件来源与兼容放行链的领域用例。

证据（厂商声明、批次谱系、固件摘要、接口能力、检验结果、替代关系）以不可覆盖
版本保存，硬件、软件、质量角色分别确认自己负责的证据；装配放行针对确定的整机
配置生成结论；证据失效只影响尚未装配或待放行范围，不回写已经出厂的配置事实。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Mapping, Sequence

from .clock import SystemClock, utc_text
from .contracts import (
    capability_map,
    category,
    config_slot_pins,
    disposition,
    evidence_kind,
    identifier,
    identifier_list,
    inspection_result,
    json_object,
    positive_version,
    required_text,
    sha256_hex,
    slot_definitions,
)
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "hardware": {
        "model.register", "architecture.publish", "declaration.register",
        "capability.register", "substitution.propose", "evidence.confirm",
    },
    "software": {"firmware.register", "evidence.confirm"},
    "quality": {
        "inspection.record", "evidence.confirm", "release.issue", "evidence.invalidate",
    },
    "operator": {"batch.manage", "serial.manage", "config.write", "config.ship"},
    "auditor": {"audit.read"},
}

EVIDENCE_DOMAINS = {
    "vendor_declaration": "hardware",
    "interface_capability": "hardware",
    "firmware_baseline": "software",
    "inspection": "quality",
    "substitution": "quality",
}

EVIDENCE_LABELS = {
    "vendor_declaration": "厂商声明",
    "interface_capability": "接口能力",
    "firmware_baseline": "固件摘要",
    "inspection": "检验结果",
    "substitution": "替代关系",
    "batch": "批次",
}

DOMAIN_LABELS = {"hardware": "硬件", "software": "软件", "quality": "质量"}


class ProvenanceService:
    """在单个 SQLite 连接上提供部件来源与兼容放行链的全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return utc_text(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        previous = self.connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = "0" * 64 if previous is None else previous["event_hash"]
        body = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": payload,
            "created_at": self._now(),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,"
            "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                entity_type, entity_id, event_type, actor_id,
                canonical_json(payload), previous_hash, event_hash, body["created_at"],
            ),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    # ------------------------------------------------------------------
    # 基础资料：部件型号与架构版本
    # ------------------------------------------------------------------

    def register_model(self, actor_id: str, model_id: str, category_value: str, vendor: str, description: str) -> dict[str, Any]:
        self._require(actor_id, "model.register")
        model_id = identifier(model_id, "model_id")
        category_value = category(category_value)
        vendor = required_text(vendor, "vendor", 128)
        description = required_text(description, "description", 512)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO component_models(model_id,category,vendor,description,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (model_id, category_value, vendor, description, actor_id, self._now()),
                )
                self._audit("model", model_id, "model.registered", actor_id, {"category": category_value, "vendor": vendor})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"部件型号已存在: {model_id}") from exc
        return {"model_id": model_id, "category": category_value, "vendor": vendor}

    def _model(self, model_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM component_models WHERE model_id=?", (model_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"部件型号不存在: {model_id}")
        return row

    def publish_architecture(self, actor_id: str, arch_id: str, version: int, name: str, slots: Any) -> dict[str, Any]:
        self._require(actor_id, "architecture.publish")
        arch_id = identifier(arch_id, "arch_id")
        version = positive_version(version)
        name = required_text(name, "name", 256)
        parsed_slots = slot_definitions(slots)
        content = {"arch_id": arch_id, "version": version, "name": name, "slots": parsed_slots}
        digest = content_digest([content])
        latest = self.connection.execute(
            "SELECT max(version) AS latest FROM architectures WHERE arch_id=?", (arch_id,)
        ).fetchone()["latest"]
        expected = 1 if latest is None else latest + 1
        if version != expected:
            raise Conflict(f"架构版本必须连续登记，下一个版本应为 {expected}")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO architectures(arch_id,version,name,slots_json,content_sha256,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (arch_id, version, name, canonical_json(parsed_slots), digest, actor_id, self._now()),
                )
                self._audit("architecture", f"{arch_id}@{version}", "architecture.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("架构版本或内容摘要已经存在") from exc
        return {"arch_id": arch_id, "version": version, "sha256": digest}

    def _architecture(self, arch_id: str, version: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM architectures WHERE arch_id=? AND version=?", (arch_id, version)
        ).fetchone()
        if row is None:
            raise NotFound(f"架构版本不存在: {arch_id}@{version}")
        return row

    # ------------------------------------------------------------------
    # 证据登记：厂商声明、固件摘要、接口能力、检验结果、替代关系
    # ------------------------------------------------------------------

    def _next_version(self, table: str, key_column: str, key_value: str, label: str) -> int:
        latest = self.connection.execute(
            f"SELECT max(version) AS latest FROM {table} WHERE {key_column}=?", (key_value,)
        ).fetchone()["latest"]
        return 1 if latest is None else latest + 1

    @staticmethod
    def _check_version(version: int, expected: int, label: str) -> None:
        if version != expected:
            raise Conflict(f"{label}版本必须连续登记且不可覆盖，下一个版本应为 {expected}")

    def register_declaration(
        self, actor_id: str, declaration_id: str, version: int, model_id: str, vendor: str, statement: Any
    ) -> dict[str, Any]:
        self._require(actor_id, "declaration.register")
        declaration_id = identifier(declaration_id, "declaration_id")
        version = positive_version(version)
        model_id = identifier(model_id, "model_id")
        vendor = required_text(vendor, "vendor", 128)
        statement = json_object(statement, "statement")
        self._model(model_id)
        siblings = self.connection.execute(
            "SELECT DISTINCT declaration_id FROM vendor_declarations WHERE model_id=? AND vendor=?",
            (model_id, vendor),
        ).fetchall()
        if siblings and siblings[0]["declaration_id"] != declaration_id:
            raise Conflict(f"该型号与厂商已有声明系列 {siblings[0]['declaration_id']}，请在其上登记新版本")
        expected = self._next_version("vendor_declarations", "declaration_id", declaration_id, "厂商声明")
        self._check_version(version, expected, "厂商声明")
        if expected > 1:
            head = self.connection.execute(
                "SELECT model_id,vendor FROM vendor_declarations WHERE declaration_id=? AND version=1",
                (declaration_id,),
            ).fetchone()
            if head["model_id"] != model_id or head["vendor"] != vendor:
                raise Conflict("声明系列不允许变更型号或厂商")
        content = {"declaration_id": declaration_id, "version": version, "model_id": model_id, "vendor": vendor, "statement": statement}
        digest = content_digest([content])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO vendor_declarations(declaration_id,version,model_id,vendor,statement_json,"
                    "content_sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (declaration_id, version, model_id, vendor, canonical_json(statement), digest, actor_id, self._now()),
                )
                self._audit("vendor_declaration", f"{declaration_id}@{version}", "declaration.registered", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("厂商声明版本或内容摘要已经存在") from exc
        return {"declaration_id": declaration_id, "version": version, "sha256": digest}

    def register_firmware(
        self, actor_id: str, firmware_id: str, version: int, model_id: str, digest_sha256: str, notes: str
    ) -> dict[str, Any]:
        self._require(actor_id, "firmware.register")
        firmware_id = identifier(firmware_id, "firmware_id")
        version = positive_version(version)
        model_id = identifier(model_id, "model_id")
        digest_sha256 = sha256_hex(digest_sha256, "digest_sha256")
        notes = required_text(notes, "notes", 512)
        self._model(model_id)
        expected = self._next_version("firmware_baselines", "firmware_id", firmware_id, "固件基线")
        self._check_version(version, expected, "固件基线")
        if expected > 1:
            head = self.connection.execute(
                "SELECT model_id FROM firmware_baselines WHERE firmware_id=? AND version=1", (firmware_id,)
            ).fetchone()
            if head["model_id"] != model_id:
                raise Conflict("固件系列不允许变更适用型号")
        content = {"firmware_id": firmware_id, "version": version, "model_id": model_id, "digest_sha256": digest_sha256, "notes": notes}
        digest = content_digest([content])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO firmware_baselines(firmware_id,version,model_id,digest_sha256,notes,"
                    "content_sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (firmware_id, version, model_id, digest_sha256, notes, digest, actor_id, self._now()),
                )
                self._audit("firmware_baseline", f"{firmware_id}@{version}", "firmware.registered", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("固件基线版本或内容摘要已经存在") from exc
        return {"firmware_id": firmware_id, "version": version, "sha256": digest}

    def register_capability(
        self,
        actor_id: str,
        capability_id: str,
        version: int,
        model_id: str,
        firmware_id: str,
        firmware_version: int,
        capabilities: Any,
    ) -> dict[str, Any]:
        self._require(actor_id, "capability.register")
        capability_id = identifier(capability_id, "capability_id")
        version = positive_version(version)
        model_id = identifier(model_id, "model_id")
        firmware_id = identifier(firmware_id, "firmware_id")
        firmware_version = positive_version(firmware_version, "firmware_version")
        capabilities = capability_map(capabilities, "capabilities")
        if not capabilities:
            raise ValidationFailed("capabilities 不能为空对象")
        self._model(model_id)
        firmware = self.connection.execute(
            "SELECT * FROM firmware_baselines WHERE firmware_id=? AND version=?", (firmware_id, firmware_version)
        ).fetchone()
        if firmware is None:
            raise NotFound(f"固件基线不存在: {firmware_id}@{firmware_version}")
        if firmware["model_id"] != model_id:
            raise ValidationFailed("接口能力的型号与固件适用型号不一致")
        siblings = self.connection.execute(
            "SELECT DISTINCT capability_id FROM interface_capabilities "
            "WHERE model_id=? AND firmware_id=? AND firmware_version=?",
            (model_id, firmware_id, firmware_version),
        ).fetchall()
        if siblings and siblings[0]["capability_id"] != capability_id:
            raise Conflict(f"该型号与固件组合已有能力系列 {siblings[0]['capability_id']}，请在其上登记新版本")
        expected = self._next_version("interface_capabilities", "capability_id", capability_id, "接口能力")
        self._check_version(version, expected, "接口能力")
        content = {
            "capability_id": capability_id, "version": version, "model_id": model_id,
            "firmware_id": firmware_id, "firmware_version": firmware_version, "capabilities": capabilities,
        }
        digest = content_digest([content])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO interface_capabilities(capability_id,version,model_id,firmware_id,firmware_version,"
                    "capabilities_json,content_sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (capability_id, version, model_id, firmware_id, firmware_version,
                     canonical_json(capabilities), digest, actor_id, self._now()),
                )
                self._audit("interface_capability", f"{capability_id}@{version}", "capability.registered", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("接口能力版本或内容摘要已经存在") from exc
        return {"capability_id": capability_id, "version": version, "sha256": digest}

    def record_inspection(
        self, actor_id: str, batch_id: str, inspection_type: str, result: str, evidence_ref: str
    ) -> dict[str, Any]:
        self._require(actor_id, "inspection.record")
        batch_id = identifier(batch_id, "batch_id")
        inspection_type = identifier(inspection_type, "inspection_type")
        result = inspection_result(result)
        evidence_ref = required_text(evidence_ref, "evidence_ref", 256)
        self._batch(batch_id)
        content = {
            "batch_id": batch_id, "inspection_type": inspection_type,
            "result": result, "evidence_ref": evidence_ref, "recorded_by": actor_id,
        }
        digest = content_digest([content])
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO inspections(batch_id,inspection_type,result,evidence_ref,content_sha256,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (batch_id, inspection_type, result, evidence_ref, digest, actor_id, self._now()),
                )
                inspection_id = int(cursor.lastrowid)
                self._audit("inspection", str(inspection_id), "inspection.recorded", actor_id, {"batch_id": batch_id, "result": result})
        except sqlite3.IntegrityError as exc:
            raise Conflict("相同内容的检验记录已经存在") from exc
        return {"inspection_id": inspection_id, "batch_id": batch_id, "inspection_type": inspection_type, "result": result}

    def propose_substitution(
        self,
        actor_id: str,
        substitution_id: str,
        version: int,
        arch_id: str,
        arch_version: int,
        slot_id: str,
        from_model: str,
        to_model: str,
        conditions: Any,
    ) -> dict[str, Any]:
        self._require(actor_id, "substitution.propose")
        substitution_id = identifier(substitution_id, "substitution_id")
        version = positive_version(version)
        arch_id = identifier(arch_id, "arch_id")
        arch_version = positive_version(arch_version, "arch_version")
        slot_id = identifier(slot_id, "slot_id")
        from_model = identifier(from_model, "from_model")
        to_model = identifier(to_model, "to_model")
        conditions = json_object(conditions, "conditions")
        if from_model == to_model:
            raise ValidationFailed("替代关系的来源型号与目标型号不能相同")
        architecture = self._architecture(arch_id, arch_version)
        slots = json.loads(architecture["slots_json"])
        slot = next((item for item in slots if item["slot_id"] == slot_id), None)
        if slot is None:
            raise ValidationFailed(f"架构 {arch_id}@{arch_version} 没有槽位 {slot_id}")
        if from_model not in slot["allowed_models"]:
            raise ValidationFailed("来源型号必须在槽位允许清单内")
        target = self._model(to_model)
        if target["category"] != slot["category"]:
            raise ValidationFailed("目标型号类别与槽位类别不一致")
        expected = self._next_version("substitutions", "substitution_id", substitution_id, "替代关系")
        self._check_version(version, expected, "替代关系")
        content = {
            "substitution_id": substitution_id, "version": version, "arch_id": arch_id,
            "arch_version": arch_version, "slot_id": slot_id, "from_model": from_model,
            "to_model": to_model, "conditions": conditions,
        }
        digest = content_digest([content])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO substitutions(substitution_id,version,arch_id,arch_version,slot_id,from_model,"
                    "to_model,conditions_json,content_sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (substitution_id, version, arch_id, arch_version, slot_id, from_model,
                     to_model, canonical_json(conditions), digest, actor_id, self._now()),
                )
                self._audit("substitution", f"{substitution_id}@{version}", "substitution.proposed", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("替代关系版本或内容摘要已经存在") from exc
        return {"substitution_id": substitution_id, "version": version, "sha256": digest}

    # ------------------------------------------------------------------
    # 证据确认与失效
    # ------------------------------------------------------------------

    def _evidence_row(self, kind: str, evidence_id: str, version: int) -> sqlite3.Row | None:
        if kind == "vendor_declaration":
            return self.connection.execute(
                "SELECT * FROM vendor_declarations WHERE declaration_id=? AND version=?", (evidence_id, version)
            ).fetchone()
        if kind == "firmware_baseline":
            return self.connection.execute(
                "SELECT * FROM firmware_baselines WHERE firmware_id=? AND version=?", (evidence_id, version)
            ).fetchone()
        if kind == "interface_capability":
            return self.connection.execute(
                "SELECT * FROM interface_capabilities WHERE capability_id=? AND version=?", (evidence_id, version)
            ).fetchone()
        if kind == "inspection":
            if version != 1:
                return None
            return self.connection.execute(
                "SELECT * FROM inspections WHERE inspection_id=?", (int(evidence_id),)
            ).fetchone()
        if kind == "substitution":
            return self.connection.execute(
                "SELECT * FROM substitutions WHERE substitution_id=? AND version=?", (evidence_id, version)
            ).fetchone()
        if kind == "batch":
            if version != 0:
                return None
            return self.connection.execute(
                "SELECT * FROM part_batches WHERE batch_id=?", (evidence_id,)
            ).fetchone()
        return None

    def _is_confirmed(self, kind: str, evidence_id: str, version: int) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM evidence_confirmations WHERE evidence_kind=? AND evidence_id=? AND evidence_version=?",
            (kind, evidence_id, version),
        ).fetchone() is not None

    def _is_invalidated(self, kind: str, evidence_id: str, version: int) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM evidence_invalidations WHERE evidence_kind=? AND evidence_id=? AND evidence_version=?",
            (kind, evidence_id, version),
        ).fetchone() is not None

    def _evidence_status(self, kind: str, evidence_id: str, version: int) -> str:
        if self._is_invalidated(kind, evidence_id, version):
            return "invalid"
        if not self._is_confirmed(kind, evidence_id, version):
            return "pending_confirmation"
        return "ok"

    def confirm_evidence(self, actor_id: str, kind: str, evidence_id: str, version: int, statement: str) -> dict[str, Any]:
        actor = self._require(actor_id, "evidence.confirm")
        kind = evidence_kind(kind)
        evidence_id = identifier(evidence_id, "evidence_id") if kind != "inspection" else required_text(evidence_id, "evidence_id", 64)
        version = positive_version(version, "evidence_version")
        statement = required_text(statement, "statement", 512)
        domain = EVIDENCE_DOMAINS[kind]
        if actor["role"] != domain:
            raise Forbidden(f"{EVIDENCE_LABELS[kind]}应由{DOMAIN_LABELS[domain]}角色确认")
        row = self._evidence_row(kind, evidence_id, version)
        if row is None:
            raise NotFound(f"证据不存在: {kind} {evidence_id}@{version}")
        if row["created_by"] == actor_id:
            raise Forbidden("登记人不能确认自己提交的证据")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_confirmations(evidence_kind,evidence_id,evidence_version,domain,"
                    "statement,confirmed_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (kind, evidence_id, version, domain, statement, actor_id, self._now()),
                )
                self._audit(kind, f"{evidence_id}@{version}", "evidence.confirmed", actor_id, {"domain": domain})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"{EVIDENCE_LABELS[kind]} {evidence_id}@{version} 已经确认") from exc
        return {"evidence_kind": kind, "evidence_id": evidence_id, "evidence_version": version, "domain": domain}

    def invalidate_evidence(self, actor_id: str, kind: str, evidence_id: str, version: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "evidence.invalidate")
        kind = evidence_kind(kind, allow_batch=True)
        evidence_id = identifier(evidence_id, "evidence_id") if kind != "inspection" else required_text(evidence_id, "evidence_id", 64)
        version = positive_version(version, "evidence_version") if kind != "batch" else 0
        reason = required_text(reason, "reason", 512)
        if self._evidence_row(kind, evidence_id, version) is None:
            raise NotFound(f"证据不存在: {kind} {evidence_id}@{version}")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO evidence_invalidations(evidence_kind,evidence_id,evidence_version,reason,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?)",
                    (kind, evidence_id, version, reason, actor_id, self._now()),
                )
                invalidation_id = int(cursor.lastrowid)
                impact = self._invalidation_impact(kind, evidence_id, version)
                self._audit(kind, f"{evidence_id}@{version}", "evidence.invalidated", actor_id, {"reason": reason, "impact": impact})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"{EVIDENCE_LABELS[kind]} {evidence_id}@{version} 已经失效") from exc
        return {
            "invalidation_id": invalidation_id,
            "evidence_kind": kind,
            "evidence_id": evidence_id,
            "evidence_version": version,
            "impact": impact,
        }

    def _invalidation_impact(self, kind: str, evidence_id: str, version: int) -> dict[str, Any]:
        """失效只影响尚未装配或待放行范围；已出厂配置事实保持不变，仅列为通告。"""

        open_configs: list[str] = []
        rows = self.connection.execute(
            "SELECT config_id FROM machine_configs WHERE state != 'shipped' ORDER BY config_id"
        ).fetchall()
        for row in rows:
            evaluation = self._evaluate_config(self._config(row["config_id"]))
            for slot in evaluation["slots"]:
                for check in slot["checks"]:
                    evidence = check.get("evidence")
                    if (
                        check["status"] == "invalid"
                        and evidence is not None
                        and evidence["kind"] == kind
                        and evidence["id"] == evidence_id
                        and evidence["version"] == version
                    ):
                        open_configs.append(row["config_id"])
                        break
                else:
                    continue
                break
        shipped_advisories: list[str] = []
        shipped = self.connection.execute(
            "SELECT s.config_id, r.detail_json FROM shipments s "
            "JOIN assembly_releases r ON r.release_id=s.release_id ORDER BY s.config_id"
        ).fetchall()
        for row in shipped:
            refs = json.loads(row["detail_json"])["evidence_refs"]
            if any(ref["kind"] == kind and ref["id"] == evidence_id and ref["version"] == version for ref in refs):
                shipped_advisories.append(row["config_id"])
        return {
            "affected_open_configs": open_configs,
            "shipped_configs_advisory_only": shipped_advisories,
        }

    # ------------------------------------------------------------------
    # 批次谱系与序列号
    # ------------------------------------------------------------------

    def register_batch(self, actor_id: str, batch_id: str, model_id: str, vendor: str, lot_code: str) -> dict[str, Any]:
        self._require(actor_id, "batch.manage")
        batch_id = identifier(batch_id, "batch_id")
        model_id = identifier(model_id, "model_id")
        vendor = required_text(vendor, "vendor", 128)
        lot_code = required_text(lot_code, "lot_code", 64)
        self._model(model_id)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO part_batches(batch_id,model_id,vendor,lot_code,parent_batch_id,split_note,"
                    "created_by,created_at) VALUES(?,?,?,?,NULL,'',?,?)",
                    (batch_id, model_id, vendor, lot_code, actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.registered", actor_id, {"model_id": model_id, "vendor": vendor})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"部件批次已存在: {batch_id}") from exc
        return {"batch_id": batch_id, "model_id": model_id, "vendor": vendor, "lot_code": lot_code}

    def _batch(self, batch_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM part_batches WHERE batch_id=?", (batch_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"部件批次不存在: {batch_id}")
        return row

    def register_serials(self, actor_id: str, batch_id: str, serial_ids: Any) -> dict[str, Any]:
        self._require(actor_id, "serial.manage")
        batch_id = identifier(batch_id, "batch_id")
        serial_ids = identifier_list(serial_ids, "serial_ids", allow_empty=False)
        self._batch(batch_id)
        try:
            with transaction(self.connection, immediate=True):
                for serial_id in serial_ids:
                    self.connection.execute(
                        "INSERT INTO serials(serial_id,batch_id,state,created_at) VALUES(?,?,?,?)",
                        (serial_id, batch_id, "in_stock", self._now()),
                    )
                    self._serial_event(serial_id, "registered", None, batch_id, None, None, "", actor_id)
                self._audit("batch", batch_id, "serials.registered", actor_id, {"count": len(serial_ids)})
        except sqlite3.IntegrityError as exc:
            raise Conflict("序列号已经存在") from exc
        return {"batch_id": batch_id, "registered": len(serial_ids)}

    def _serial(self, serial_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM serials WHERE serial_id=?", (serial_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"序列号不存在: {serial_id}")
        return row

    def _serial_event(
        self,
        serial_id: str,
        event_type: str,
        from_batch: str | None,
        to_batch: str | None,
        config_id: str | None,
        slot_id: str | None,
        note: str,
        actor_id: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO serial_events(serial_id,event_type,from_batch_id,to_batch_id,config_id,slot_id,"
            "note,actor_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (serial_id, event_type, from_batch, to_batch, config_id, slot_id, note, actor_id, self._now()),
        )

    def split_batch(self, actor_id: str, batch_id: str, children: Any) -> dict[str, Any]:
        self._require(actor_id, "batch.manage")
        batch_id = identifier(batch_id, "batch_id")
        parent = self._batch(batch_id)
        if not isinstance(children, list) or not children:
            raise ValidationFailed("children 必须是非空数组")
        parsed: list[dict[str, Any]] = []
        seen_children: set[str] = set()
        seen_serials: set[str] = set()
        for index, item in enumerate(children):
            field = f"children[{index}]"
            if not isinstance(item, Mapping):
                raise ValidationFailed(f"{field} 必须是对象")
            child_id = identifier(item.get("batch_id"), f"{field}.batch_id")
            if child_id == batch_id or child_id in seen_children:
                raise ValidationFailed(f"子批次编号重复或与父批次相同: {child_id}")
            seen_children.add(child_id)
            serial_ids = identifier_list(item.get("serial_ids"), f"{field}.serial_ids", allow_empty=False)
            overlap = seen_serials.intersection(serial_ids)
            if overlap:
                raise ValidationFailed(f"序列号在拆分目标中重复: {sorted(overlap)}")
            seen_serials.update(serial_ids)
            parsed.append({
                "batch_id": child_id,
                "lot_code": required_text(item.get("lot_code"), f"{field}.lot_code", 64),
                "note": required_text(item.get("note", "拆分"), f"{field}.note", 256),
                "serial_ids": serial_ids,
            })
        for serial_id in sorted(seen_serials):
            serial = self._serial(serial_id)
            if serial["batch_id"] != batch_id:
                raise Conflict(f"序列号 {serial_id} 不属于批次 {batch_id}")
            if serial["state"] != "in_stock":
                raise InvalidState(f"序列号 {serial_id} 状态为 {serial['state']}，只有库存序列号可以拆分")
        with transaction(self.connection, immediate=True):
            for child in parsed:
                self.connection.execute(
                    "INSERT INTO part_batches(batch_id,model_id,vendor,lot_code,parent_batch_id,split_note,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (child["batch_id"], parent["model_id"], parent["vendor"], child["lot_code"],
                     batch_id, child["note"], actor_id, self._now()),
                )
                for serial_id in child["serial_ids"]:
                    self.connection.execute(
                        "UPDATE serials SET batch_id=? WHERE serial_id=?", (child["batch_id"], serial_id)
                    )
                    self._serial_event(serial_id, "split_moved", batch_id, child["batch_id"], None, None, child["note"], actor_id)
                self._audit("batch", child["batch_id"], "batch.split_created", actor_id,
                            {"parent_batch_id": batch_id, "serials": len(child["serial_ids"])})
            self._audit("batch", batch_id, "batch.split", actor_id,
                        {"children": [child["batch_id"] for child in parsed]})
        return {"batch_id": batch_id, "children": [{"batch_id": c["batch_id"], "serials": len(c["serial_ids"])} for c in parsed]}

    def batch_genealogy(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        self._user(actor_id)
        batch = self._batch(identifier(batch_id, "batch_id"))
        ancestors: list[dict[str, Any]] = []
        current = batch
        while current["parent_batch_id"] is not None:
            current = self._batch(current["parent_batch_id"])
            ancestors.append({
                "batch_id": current["batch_id"],
                "lot_code": current["lot_code"],
                "model_id": current["model_id"],
            })
        children = self.connection.execute(
            "SELECT batch_id,lot_code,split_note,created_at FROM part_batches WHERE parent_batch_id=? ORDER BY batch_id",
            (batch["batch_id"],),
        ).fetchall()
        serial_counts = self.connection.execute(
            "SELECT state,count(*) AS count FROM serials WHERE batch_id=? GROUP BY state ORDER BY state",
            (batch["batch_id"],),
        ).fetchall()
        return {
            "batch": dict(batch),
            "ancestors": ancestors,
            "children": [dict(row) for row in children],
            "serial_counts": {row["state"]: row["count"] for row in serial_counts},
        }

    def serial_trace(self, actor_id: str, serial_id: str) -> dict[str, Any]:
        self._user(actor_id)
        serial = self._serial(identifier(serial_id, "serial_id"))
        events = self.connection.execute(
            "SELECT * FROM serial_events WHERE serial_id=? ORDER BY event_id", (serial["serial_id"],)
        ).fetchall()
        installed = self.connection.execute(
            "SELECT config_id,slot_id FROM config_slots WHERE serial_id=?", (serial["serial_id"],)
        ).fetchone()
        current = {
            "state": serial["state"],
            "batch_id": serial["batch_id"],
            "config_id": None if installed is None else installed["config_id"],
            "slot_id": None if installed is None else installed["slot_id"],
        }
        return {
            "serial_id": serial["serial_id"],
            "current": current,
            "events": [dict(row) for row in events],
        }

    # ------------------------------------------------------------------
    # 整机配置、装配、放行与出厂
    # ------------------------------------------------------------------

    def create_config(
        self,
        actor_id: str,
        config_id: str,
        robot_model: str,
        arch_id: str,
        arch_version: int,
        slots: Any,
    ) -> dict[str, Any]:
        self._require(actor_id, "config.write")
        config_id = identifier(config_id, "config_id")
        robot_model = required_text(robot_model, "robot_model", 128)
        arch_id = identifier(arch_id, "arch_id")
        arch_version = positive_version(arch_version, "arch_version")
        pins = config_slot_pins(slots)
        architecture = self._architecture(arch_id, arch_version)
        slot_defs = {item["slot_id"]: item for item in json.loads(architecture["slots_json"])}
        if {pin["slot_id"] for pin in pins} != set(slot_defs):
            raise ValidationFailed("配置槽位必须与架构版本定义的槽位完全一致")
        for pin in pins:
            model = self._model(pin["model_id"])
            slot_def = slot_defs[pin["slot_id"]]
            if model["category"] != slot_def["category"]:
                raise ValidationFailed(f"槽位 {pin['slot_id']} 的型号类别与架构定义不一致")
            batch = self._batch(pin["batch_id"])
            if batch["model_id"] != pin["model_id"]:
                raise ValidationFailed(f"槽位 {pin['slot_id']} 的批次不属于型号 {pin['model_id']}")
            firmware = self.connection.execute(
                "SELECT model_id FROM firmware_baselines WHERE firmware_id=? AND version=?",
                (pin["firmware_id"], pin["firmware_version"]),
            ).fetchone()
            if firmware is None:
                raise NotFound(f"固件基线不存在: {pin['firmware_id']}@{pin['firmware_version']}")
            if firmware["model_id"] != pin["model_id"]:
                raise ValidationFailed(f"槽位 {pin['slot_id']} 的固件不适用于型号 {pin['model_id']}")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO machine_configs(config_id,robot_model,arch_id,arch_version,state,revision,"
                    "created_by,created_at,updated_at) VALUES(?,?,?,?,'draft',1,?,?,?)",
                    (config_id, robot_model, arch_id, arch_version, actor_id, now, now),
                )
                for pin in pins:
                    self.connection.execute(
                        "INSERT INTO config_slots(config_id,slot_id,model_id,batch_id,firmware_id,firmware_version,"
                        "serial_id) VALUES(?,?,?,?,?,?,NULL)",
                        (config_id, pin["slot_id"], pin["model_id"], pin["batch_id"],
                         pin["firmware_id"], pin["firmware_version"]),
                    )
                self._audit("config", config_id, "config.created", actor_id,
                            {"arch_id": arch_id, "arch_version": arch_version})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"整机配置已存在: {config_id}") from exc
        return {"config_id": config_id, "state": "draft", "revision": 1}

    def _config(self, config_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM machine_configs WHERE config_id=?", (config_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"整机配置不存在: {config_id}")
        return row

    def _config_slots(self, config_id: str) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM config_slots WHERE config_id=? ORDER BY slot_id", (config_id,)
        ).fetchall()

    def _bump_config(self, config_id: str, state: str | None = None) -> None:
        if state is None:
            self.connection.execute(
                "UPDATE machine_configs SET revision=revision+1,updated_at=? WHERE config_id=?",
                (self._now(), config_id),
            )
        else:
            self.connection.execute(
                "UPDATE machine_configs SET revision=revision+1,state=?,updated_at=? WHERE config_id=?",
                (state, self._now(), config_id),
            )

    def assemble_config(self, actor_id: str, config_id: str, assignments: Any) -> dict[str, Any]:
        self._require(actor_id, "config.write")
        config = self._config(identifier(config_id, "config_id"))
        if config["state"] not in {"draft", "assembled"}:
            raise InvalidState("只有草稿或已装配状态的配置可以装配序列号")
        if not isinstance(assignments, Mapping) or not assignments:
            raise ValidationFailed("assignments 必须是非空对象")
        parsed = {
            identifier(slot, "assignments 键"): identifier(serial, f"assignments.{slot}")
            for slot, serial in assignments.items()
        }
        slots = {row["slot_id"]: row for row in self._config_slots(config["config_id"])}
        unknown = set(parsed) - set(slots)
        if unknown:
            raise ValidationFailed(f"配置没有槽位: {sorted(unknown)}")
        merged = {slot_id: row["serial_id"] for slot_id, row in slots.items()}
        for slot_id, serial_id in parsed.items():
            if slots[slot_id]["serial_id"] is not None and slots[slot_id]["serial_id"] != serial_id:
                raise Conflict(f"槽位 {slot_id} 已装配序列号，请使用换件接口")
            merged[slot_id] = serial_id
        missing = [slot_id for slot_id, serial_id in merged.items() if serial_id is None]
        if missing:
            raise ValidationFailed(f"装配后仍有槽位缺少序列号: {sorted(missing)}")
        for slot_id, serial_id in parsed.items():
            serial = self._serial(serial_id)
            if serial["state"] != "in_stock":
                raise InvalidState(f"序列号 {serial_id} 状态为 {serial['state']}，不能装配")
            if serial["batch_id"] != slots[slot_id]["batch_id"]:
                raise Conflict(f"序列号 {serial_id} 不属于槽位 {slot_id} 绑定的批次")
        with transaction(self.connection, immediate=True):
            for slot_id, serial_id in parsed.items():
                if slots[slot_id]["serial_id"] == serial_id:
                    continue
                self.connection.execute(
                    "UPDATE config_slots SET serial_id=? WHERE config_id=? AND slot_id=?",
                    (serial_id, config["config_id"], slot_id),
                )
                self.connection.execute(
                    "UPDATE serials SET state='installed' WHERE serial_id=?", (serial_id,)
                )
                self._serial_event(serial_id, "installed", slots[slot_id]["batch_id"], None,
                                   config["config_id"], slot_id, "", actor_id)
            self._bump_config(config["config_id"], state="assembled")
            self._audit("config", config["config_id"], "config.assembled", actor_id, {"assignments": parsed})
        return {"config_id": config["config_id"], "state": "assembled"}

    # ------------------------------------------------------------------
    # 兼容评估与装配放行
    # ------------------------------------------------------------------

    def _latest_declaration(self, model_id: str, vendor: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM vendor_declarations WHERE model_id=? AND vendor=? "
            "ORDER BY version DESC, declaration_id DESC LIMIT 1",
            (model_id, vendor),
        ).fetchone()

    def _latest_capability(self, model_id: str, firmware_id: str, firmware_version: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM interface_capabilities WHERE model_id=? AND firmware_id=? AND firmware_version=? "
            "ORDER BY version DESC, capability_id DESC LIMIT 1",
            (model_id, firmware_id, firmware_version),
        ).fetchone()

    def _latest_inspection(self, batch_id: str, inspection_type: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM inspections WHERE batch_id=? AND inspection_type=? "
            "ORDER BY inspection_id DESC LIMIT 1",
            (batch_id, inspection_type),
        ).fetchone()

    def _substitution_candidates(
        self, arch_id: str, arch_version: int, slot_id: str, to_model: str, allowed_models: Sequence[str]
    ) -> list[sqlite3.Row]:
        rows = self.connection.execute(
            "SELECT * FROM substitutions WHERE arch_id=? AND arch_version=? AND slot_id=? AND to_model=? "
            "ORDER BY substitution_id, version",
            (arch_id, arch_version, slot_id, to_model),
        ).fetchall()
        latest: dict[str, sqlite3.Row] = {}
        for row in rows:
            if row["from_model"] not in allowed_models:
                continue
            latest[row["substitution_id"]] = row
        return [latest[key] for key in sorted(latest)]

    @staticmethod
    def _check(name: str, ok: bool, status: str, message: str, evidence: dict[str, Any] | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        entry: dict[str, Any] = {"check": name, "ok": ok, "status": status, "message": message}
        if evidence is not None:
            entry["evidence"] = evidence
        if extra:
            entry.update(extra)
        return entry

    def _evaluate_slot(self, architecture: sqlite3.Row, slot_def: Mapping[str, Any], slot_row: sqlite3.Row) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        refs: list[dict[str, Any]] = []
        slot_id = slot_def["slot_id"]
        model = self._model(slot_row["model_id"])
        batch = self._batch(slot_row["batch_id"])

        ok = model["category"] == slot_def["category"]
        checks.append(self._check(
            "category", ok, "ok" if ok else "mismatch",
            f"型号类别 {model['category']} 与槽位类别 {slot_def['category']} " + ("一致" if ok else "不一致"),
        ))

        batch_ref = {"kind": "batch", "id": batch["batch_id"], "version": 0}
        refs.append(batch_ref)
        if batch["model_id"] != model["model_id"]:
            checks.append(self._check("batch", False, "mismatch",
                                      f"批次 {batch['batch_id']} 属于型号 {batch['model_id']}，与槽位型号不一致", batch_ref))
        elif self._is_invalidated("batch", batch["batch_id"], 0):
            checks.append(self._check("batch", False, "invalid", f"批次 {batch['batch_id']} 已失效", batch_ref))
        else:
            checks.append(self._check("batch", True, "ok", f"批次 {batch['batch_id']} 谱系有效", batch_ref))

        if model["model_id"] in slot_def["allowed_models"]:
            checks.append(self._check("model_allowed", True, "ok",
                                      f"型号 {model['model_id']} 在架构允许清单内"))
        else:
            candidates = self._substitution_candidates(
                architecture["arch_id"], architecture["version"], slot_id,
                model["model_id"], slot_def["allowed_models"],
            )
            chosen: sqlite3.Row | None = None
            chosen_status = "missing"
            for candidate in candidates:
                status = self._evidence_status("substitution", candidate["substitution_id"], candidate["version"])
                if status == "ok":
                    chosen = candidate
                    chosen_status = "ok"
                    break
                if chosen is None:
                    chosen = candidate
                    chosen_status = status
            if chosen is None:
                checks.append(self._check("model_allowed", False, "missing",
                                          f"型号 {model['model_id']} 不在允许清单且无替代关系"))
            else:
                ref = {"kind": "substitution", "id": chosen["substitution_id"], "version": chosen["version"]}
                refs.append(ref)
                if chosen_status == "ok":
                    checks.append(self._check(
                        "model_allowed", True, "ok",
                        f"替代关系 {chosen['substitution_id']}@{chosen['version']} 允许 "
                        f"{chosen['from_model']}→{chosen['to_model']}", ref))
                elif chosen_status == "pending_confirmation":
                    checks.append(self._check(
                        "model_allowed", False, "pending_confirmation",
                        f"替代关系 {chosen['substitution_id']}@{chosen['version']} 待质量确认", ref))
                else:
                    checks.append(self._check(
                        "model_allowed", False, "invalid",
                        f"替代关系 {chosen['substitution_id']}@{chosen['version']} 已失效", ref))

        declaration = self._latest_declaration(model["model_id"], batch["vendor"])
        if declaration is None:
            checks.append(self._check("vendor_declaration", False, "missing",
                                      f"型号 {model['model_id']} 厂商 {batch['vendor']} 的厂商声明未登记"))
        else:
            ref = {"kind": "vendor_declaration", "id": declaration["declaration_id"], "version": declaration["version"]}
            refs.append(ref)
            status = self._evidence_status("vendor_declaration", ref["id"], ref["version"])
            label = f"厂商声明 {ref['id']}@{ref['version']}"
            checks.append(self._check(
                "vendor_declaration", status == "ok", status,
                {"ok": f"{label} 已确认", "pending_confirmation": f"{label} 待硬件确认", "invalid": f"{label} 已失效"}[status],
                ref))

        firmware = self.connection.execute(
            "SELECT * FROM firmware_baselines WHERE firmware_id=? AND version=?",
            (slot_row["firmware_id"], slot_row["firmware_version"]),
        ).fetchone()
        if firmware is None:
            checks.append(self._check("firmware_baseline", False, "missing",
                                      f"固件基线 {slot_row['firmware_id']}@{slot_row['firmware_version']} 未登记"))
        else:
            ref = {"kind": "firmware_baseline", "id": firmware["firmware_id"], "version": firmware["version"]}
            refs.append(ref)
            status = self._evidence_status("firmware_baseline", ref["id"], ref["version"])
            label = f"固件摘要 {ref['id']}@{ref['version']}"
            checks.append(self._check(
                "firmware_baseline", status == "ok", status,
                {"ok": f"{label} 已确认", "pending_confirmation": f"{label} 待软件确认", "invalid": f"{label} 已失效"}[status],
                ref, {"digest_sha256": firmware["digest_sha256"]}))

        capability = self._latest_capability(model["model_id"], slot_row["firmware_id"], slot_row["firmware_version"])
        if capability is None:
            checks.append(self._check("interface_capability", False, "missing",
                                      f"型号 {model['model_id']} 在固件 {slot_row['firmware_id']}@{slot_row['firmware_version']} 下的接口能力未登记"))
        else:
            ref = {"kind": "interface_capability", "id": capability["capability_id"], "version": capability["version"]}
            refs.append(ref)
            status = self._evidence_status("interface_capability", ref["id"], ref["version"])
            label = f"接口能力 {ref['id']}@{ref['version']}"
            if status != "ok":
                checks.append(self._check(
                    "interface_capability", False, status,
                    {"pending_confirmation": f"{label} 待硬件确认", "invalid": f"{label} 已失效"}[status], ref))
            else:
                provided = json.loads(capability["capabilities_json"])
                gaps = [
                    key for key, want in slot_def["required_capabilities"].items()
                    if provided.get(key) != want
                ]
                if gaps:
                    checks.append(self._check(
                        "interface_capability", False, "mismatch",
                        f"接口能力不满足: 键 {gaps} 要求 "
                        f"{ {key: slot_def['required_capabilities'][key] for key in gaps} } "
                        f"实际 { {key: provided.get(key) for key in gaps} }",
                        ref))
                else:
                    checks.append(self._check("interface_capability", True, "ok", f"{label} 覆盖架构要求", ref))

        for inspection_type in slot_def["required_inspections"]:
            inspection = self._latest_inspection(batch["batch_id"], inspection_type)
            if inspection is None:
                checks.append(self._check("inspection", False, "missing",
                                          f"批次 {batch['batch_id']} 缺少检验 {inspection_type}",
                                          None, {"inspection_type": inspection_type}))
                continue
            ref = {"kind": "inspection", "id": str(inspection["inspection_id"]), "version": 1}
            refs.append(ref)
            if inspection["result"] != "pass":
                checks.append(self._check("inspection", False, "failed",
                                          f"检验 {inspection_type} 最新结果为 fail", ref,
                                          {"inspection_type": inspection_type}))
                continue
            status = self._evidence_status("inspection", ref["id"], 1)
            label = f"检验 {inspection_type}（记录 {ref['id']}）"
            checks.append(self._check(
                "inspection", status == "ok", status,
                {"ok": f"{label} 已通过并确认", "pending_confirmation": f"{label} 待质量确认", "invalid": f"{label} 已失效"}[status],
                ref, {"inspection_type": inspection_type}))

        serial_id = slot_row["serial_id"]
        if serial_id is None:
            checks.append(self._check("serial", False, "missing", "槽位尚未装配序列号"))
        else:
            serial = self._serial(serial_id)
            if serial["batch_id"] != slot_row["batch_id"]:
                checks.append(self._check("serial", False, "mismatch",
                                          f"序列号 {serial_id} 属于批次 {serial['batch_id']}，与槽位批次不一致"))
            elif serial["state"] not in {"installed", "shipped"}:
                checks.append(self._check("serial", False, "failed",
                                          f"序列号 {serial_id} 状态为 {serial['state']}，不可用于放行"))
            else:
                checks.append(self._check("serial", True, "ok", f"序列号 {serial_id} 已装配"))

        verdict = "pass" if all(check["ok"] for check in checks) else "fail"
        return {
            "slot_id": slot_id,
            "category": slot_def["category"],
            "pin": {
                "model_id": slot_row["model_id"],
                "batch_id": slot_row["batch_id"],
                "firmware_id": slot_row["firmware_id"],
                "firmware_version": slot_row["firmware_version"],
                "serial_id": slot_row["serial_id"],
            },
            "checks": checks,
            "verdict": verdict,
            "evidence_refs": refs,
        }

    def _evaluate_config(self, config: sqlite3.Row) -> dict[str, Any]:
        architecture = self._architecture(config["arch_id"], config["arch_version"])
        slot_defs = json.loads(architecture["slots_json"])
        slot_rows = {row["slot_id"]: row for row in self._config_slots(config["config_id"])}
        slots: list[dict[str, Any]] = []
        refs: list[dict[str, Any]] = []
        for slot_def in slot_defs:
            slot_row = slot_rows.get(slot_def["slot_id"])
            if slot_row is None:
                slots.append({
                    "slot_id": slot_def["slot_id"],
                    "category": slot_def["category"],
                    "pin": None,
                    "checks": [self._check("slot_pinned", False, "missing", "槽位未配置")],
                    "verdict": "fail",
                    "evidence_refs": [],
                })
                continue
            evaluated = self._evaluate_slot(architecture, slot_def, slot_row)
            slots.append(evaluated)
            refs.extend(evaluated["evidence_refs"])
        unique_refs = sorted(
            {canonical_json(ref): ref for ref in refs}.values(),
            key=lambda ref: (ref["kind"], ref["id"], ref["version"]),
        )
        conclusion = "released" if all(slot["verdict"] == "pass" for slot in slots) else "blocked"
        return {
            "config_id": config["config_id"],
            "revision": config["revision"],
            "arch_id": config["arch_id"],
            "arch_version": config["arch_version"],
            "slots": slots,
            "evidence_refs": unique_refs,
            "conclusion": conclusion,
        }

    def release_config(self, actor_id: str, config_id: str) -> dict[str, Any]:
        self._require(actor_id, "release.issue")
        config = self._config(identifier(config_id, "config_id"))
        if config["state"] not in {"assembled", "released"}:
            raise InvalidState("配置尚未完成装配，不能生成放行结论")
        evaluation = self._evaluate_config(config)
        digest = content_digest([{
            "config_id": evaluation["config_id"],
            "revision": evaluation["revision"],
            "arch_id": evaluation["arch_id"],
            "arch_version": evaluation["arch_version"],
            "slots": evaluation["slots"],
            "evidence_refs": evaluation["evidence_refs"],
        }])
        existing = self.connection.execute(
            "SELECT * FROM assembly_releases WHERE config_id=? AND input_sha256=?",
            (config["config_id"], digest),
        ).fetchone()
        if existing is not None:
            return {
                "release_id": existing["release_id"],
                "config_id": config["config_id"],
                "conclusion": existing["conclusion"],
                "input_sha256": digest,
                "replayed": True,
            }
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO assembly_releases(config_id,config_revision,conclusion,detail_json,input_sha256,"
                "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (config["config_id"], config["revision"], evaluation["conclusion"],
                 canonical_json(evaluation), digest, actor_id, self._now()),
            )
            release_id = int(cursor.lastrowid)
            new_state = "released" if evaluation["conclusion"] == "released" else "assembled"
            self.connection.execute(
                "UPDATE machine_configs SET state=?,updated_at=? WHERE config_id=?",
                (new_state, self._now(), config["config_id"]),
            )
            self._audit("config", config["config_id"], "config.release_evaluated", actor_id,
                        {"release_id": release_id, "conclusion": evaluation["conclusion"]})
        return {
            "release_id": release_id,
            "config_id": config["config_id"],
            "conclusion": evaluation["conclusion"],
            "input_sha256": digest,
            "replayed": False,
        }

    def _release_issues(self, release: sqlite3.Row, config: sqlite3.Row) -> list[str]:
        issues: list[str] = []
        if release["config_revision"] != config["revision"]:
            issues.append("配置在放行后已变更")
        detail = json.loads(release["detail_json"])
        for ref in detail["evidence_refs"]:
            if self._is_invalidated(ref["kind"], ref["id"], ref["version"]):
                issues.append(f"证据已失效: {EVIDENCE_LABELS[ref['kind']]} {ref['id']}@{ref['version']}")
        return issues

    def ship_config(self, actor_id: str, config_id: str) -> dict[str, Any]:
        self._require(actor_id, "config.ship")
        config = self._config(identifier(config_id, "config_id"))
        if config["state"] != "released":
            raise InvalidState("只有已放行的配置可以出厂")
        release = self.connection.execute(
            "SELECT * FROM assembly_releases WHERE config_id=? ORDER BY release_id DESC LIMIT 1",
            (config["config_id"],),
        ).fetchone()
        if release is None or release["conclusion"] != "released":
            raise InvalidState("没有有效的放行结论")
        issues = self._release_issues(release, config)
        if issues:
            raise InvalidState("放行结论已失效: " + "；".join(issues))
        slots = self._config_slots(config["config_id"])
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO shipments(config_id,release_id,shipped_by,shipped_at) VALUES(?,?,?,?)",
                (config["config_id"], release["release_id"], actor_id, self._now()),
            )
            self.connection.execute(
                "UPDATE machine_configs SET state='shipped',updated_at=? WHERE config_id=?",
                (self._now(), config["config_id"]),
            )
            for slot in slots:
                if slot["serial_id"] is None:
                    continue
                self.connection.execute(
                    "UPDATE serials SET state='shipped' WHERE serial_id=?", (slot["serial_id"],)
                )
                self._serial_event(slot["serial_id"], "shipped", None, None,
                                   config["config_id"], slot["slot_id"], "", actor_id)
            self._audit("config", config["config_id"], "config.shipped", actor_id,
                        {"release_id": release["release_id"]})
        return {
            "config_id": config["config_id"],
            "release_id": release["release_id"],
            "state": "shipped",
        }

    # ------------------------------------------------------------------
    # 换件与返工
    # ------------------------------------------------------------------

    def replace_serial(
        self, actor_id: str, config_id: str, slot_id: str, new_serial_id: str, disposition_value: str, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "serial.manage")
        config = self._config(identifier(config_id, "config_id"))
        slot_id = identifier(slot_id, "slot_id")
        new_serial_id = identifier(new_serial_id, "new_serial_id")
        disposition_value = disposition(disposition_value)
        note = required_text(note, "note", 512)
        if config["state"] not in {"assembled", "released"}:
            raise InvalidState("只有装配后且未出厂的配置可以换件")
        slot = self.connection.execute(
            "SELECT * FROM config_slots WHERE config_id=? AND slot_id=?",
            (config["config_id"], slot_id),
        ).fetchone()
        if slot is None:
            raise NotFound(f"配置没有槽位: {slot_id}")
        if slot["serial_id"] is None:
            raise InvalidState("槽位尚未装配序列号，请使用装配接口")
        old_serial = self._serial(slot["serial_id"])
        new_serial = self._serial(new_serial_id)
        if new_serial["state"] != "in_stock":
            raise InvalidState(f"序列号 {new_serial_id} 状态为 {new_serial['state']}，不能用于换件")
        new_batch = self._batch(new_serial["batch_id"])
        if new_batch["model_id"] != slot["model_id"]:
            raise Conflict(f"新序列号批次属于型号 {new_batch['model_id']}，与槽位型号 {slot['model_id']} 不一致")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE serials SET state=? WHERE serial_id=?", (disposition_value, old_serial["serial_id"])
            )
            self._serial_event(old_serial["serial_id"], "replaced_out", old_serial["batch_id"], None,
                               config["config_id"], slot_id, f"{disposition_value}: {note}", actor_id)
            self.connection.execute(
                "UPDATE serials SET state='installed' WHERE serial_id=?", (new_serial_id,)
            )
            self._serial_event(new_serial_id, "replaced_in", new_serial["batch_id"], None,
                               config["config_id"], slot_id, note, actor_id)
            self.connection.execute(
                "UPDATE config_slots SET serial_id=?,batch_id=? WHERE config_id=? AND slot_id=?",
                (new_serial_id, new_serial["batch_id"], config["config_id"], slot_id),
            )
            new_state = "assembled" if config["state"] == "released" else config["state"]
            self._bump_config(config["config_id"], state=new_state)
            self._audit("config", config["config_id"], "config.serial_replaced", actor_id,
                        {"slot_id": slot_id, "old_serial": old_serial["serial_id"],
                         "new_serial": new_serial_id, "disposition": disposition_value})
        return {
            "config_id": config["config_id"],
            "slot_id": slot_id,
            "old_serial": {"serial_id": old_serial["serial_id"], "disposition": disposition_value},
            "new_serial": new_serial_id,
            "state": new_state,
        }

    def rework_serial(self, actor_id: str, serial_id: str, note: str) -> dict[str, Any]:
        self._require(actor_id, "serial.manage")
        serial = self._serial(identifier(serial_id, "serial_id"))
        note = required_text(note, "note", 512)
        if serial["state"] not in {"in_stock", "installed"}:
            raise InvalidState(f"序列号 {serial['serial_id']} 状态为 {serial['state']}，不能返工")
        with transaction(self.connection, immediate=True):
            config_id: str | None = None
            slot_id: str | None = None
            if serial["state"] == "installed":
                slot = self.connection.execute(
                    "SELECT s.config_id,s.slot_id,c.state FROM config_slots s "
                    "JOIN machine_configs c ON c.config_id=s.config_id WHERE s.serial_id=?",
                    (serial["serial_id"],),
                ).fetchone()
                if slot is not None:
                    if slot["state"] == "shipped":
                        raise InvalidState("已出厂配置的序列号不能返工")
                    config_id, slot_id = slot["config_id"], slot["slot_id"]
                    self.connection.execute(
                        "UPDATE config_slots SET serial_id=NULL WHERE config_id=? AND slot_id=?",
                        (config_id, slot_id),
                    )
                    new_state = "assembled" if slot["state"] == "released" else slot["state"]
                    self._bump_config(config_id, state=new_state)
            self.connection.execute(
                "UPDATE serials SET state='rework' WHERE serial_id=?", (serial["serial_id"],)
            )
            self._serial_event(serial["serial_id"], "rework_out", serial["batch_id"], None,
                               config_id, slot_id, note, actor_id)
            self._audit("serial", serial["serial_id"], "serial.rework_started", actor_id, {"note": note})
        return {"serial_id": serial["serial_id"], "state": "rework", "config_id": config_id, "slot_id": slot_id}

    def return_serial(self, actor_id: str, serial_id: str, note: str) -> dict[str, Any]:
        self._require(actor_id, "serial.manage")
        serial = self._serial(identifier(serial_id, "serial_id"))
        note = required_text(note, "note", 512)
        if serial["state"] != "rework":
            raise InvalidState(f"序列号 {serial['serial_id']} 状态为 {serial['state']}，不在返工中")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE serials SET state='in_stock' WHERE serial_id=?", (serial["serial_id"],)
            )
            self._serial_event(serial["serial_id"], "rework_return", None, serial["batch_id"],
                               None, None, note, actor_id)
            self._audit("serial", serial["serial_id"], "serial.rework_returned", actor_id, {"note": note})
        return {"serial_id": serial["serial_id"], "state": "in_stock", "batch_id": serial["batch_id"]}

    # ------------------------------------------------------------------
    # 查询：放行解释、待办签署与检验、替代覆盖、审计链
    # ------------------------------------------------------------------

    def explain_config(self, actor_id: str, config_id: str) -> dict[str, Any]:
        """回答一台机器人为何允许（或不允许）使用当前各批次部件。"""

        self._user(actor_id)
        config = self._config(identifier(config_id, "config_id"))
        evaluation = self._evaluate_config(config)
        release = self.connection.execute(
            "SELECT * FROM assembly_releases WHERE config_id=? ORDER BY release_id DESC LIMIT 1",
            (config["config_id"],),
        ).fetchone()
        shipment = self.connection.execute(
            "SELECT * FROM shipments WHERE config_id=?", (config["config_id"],)
        ).fetchone()
        result: dict[str, Any] = {
            "config": dict(config),
            "evaluation": evaluation,
            "latest_release": None,
            "release_valid": None,
            "release_issues": [],
            "shipment": None if shipment is None else dict(shipment),
            "post_shipment_advisories": [],
        }
        if release is not None:
            issues = self._release_issues(release, config)
            result["latest_release"] = {
                "release_id": release["release_id"],
                "config_revision": release["config_revision"],
                "conclusion": release["conclusion"],
                "input_sha256": release["input_sha256"],
                "created_by": release["created_by"],
                "created_at": release["created_at"],
                "detail": json.loads(release["detail_json"]),
            }
            if config["state"] == "shipped":
                # 已出厂配置事实是历史记录；之后的证据失效只作为通告，不回写结论。
                result["release_valid"] = True
                result["post_shipment_advisories"] = issues
            else:
                result["release_valid"] = not issues
                result["release_issues"] = issues
        return result

    def pending_items(self, actor_id: str, config_id: str) -> dict[str, Any]:
        """回答还有哪些签署或检验未完成。"""

        self._user(actor_id)
        config = self._config(identifier(config_id, "config_id"))
        evaluation = self._evaluate_config(config)
        items = [
            {
                "slot_id": slot["slot_id"],
                "check": check["check"],
                "status": check["status"],
                "message": check["message"],
            }
            for slot in evaluation["slots"]
            for check in slot["checks"]
            if not check["ok"]
        ]
        return {
            "config_id": config["config_id"],
            "state": config["state"],
            "complete": not items,
            "items": items,
        }

    def substitution_coverage(self, actor_id: str, substitution_id: str) -> dict[str, Any]:
        """回答一个替代决定覆盖哪些整机配置。"""

        self._user(actor_id)
        substitution_id = identifier(substitution_id, "substitution_id")
        rows = self.connection.execute(
            "SELECT * FROM substitutions WHERE substitution_id=? ORDER BY version DESC",
            (substitution_id,),
        ).fetchall()
        if not rows:
            raise NotFound(f"替代关系不存在: {substitution_id}")
        substitution = rows[0]
        status = self._evidence_status("substitution", substitution_id, substitution["version"])
        dependent = self.connection.execute(
            "SELECT c.config_id,c.state,c.arch_id,c.arch_version,s.slot_id,s.model_id,s.batch_id "
            "FROM machine_configs c JOIN config_slots s ON s.config_id=c.config_id "
            "WHERE c.arch_id=? AND c.arch_version=? AND s.slot_id=? AND s.model_id=? ORDER BY c.config_id",
            (substitution["arch_id"], substitution["arch_version"], substitution["slot_id"], substitution["to_model"]),
        ).fetchall()
        architecture = self._architecture(substitution["arch_id"], substitution["arch_version"])
        slot_def = next(
            item for item in json.loads(architecture["slots_json"]) if item["slot_id"] == substitution["slot_id"]
        )
        configs = []
        for row in dependent:
            relies = row["model_id"] not in slot_def["allowed_models"]
            configs.append({
                "config_id": row["config_id"],
                "state": row["state"],
                "batch_id": row["batch_id"],
                "relies_on_substitution": relies,
            })
        return {
            "substitution": dict(substitution) | {"conditions": json.loads(substitution["conditions_json"])},
            "status": status,
            "scope": {
                "arch_id": substitution["arch_id"],
                "arch_version": substitution["arch_version"],
                "slot_id": substitution["slot_id"],
                "from_model": substitution["from_model"],
                "to_model": substitution["to_model"],
            },
            "dependent_configs": configs,
            "open_configs_blocked_if_invalidated": [
                item["config_id"] for item in configs
                if item["relies_on_substitution"] and item["state"] != "shipped"
            ],
        }

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute("SELECT * FROM audit_events ORDER BY event_id").fetchall()
        previous_hash = "0" * 64
        valid = True
        for row in rows:
            body = {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
                valid = False
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash}
