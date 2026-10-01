"""部件来源与兼容放行链的领域用例。

设计要点：
- 证据、签署、替代料、配置和序列号事件全部只追加；失效通过撤销标记或
  新版本表达，不覆盖、不删除。
- 放行结论锚定确定的整机配置摘要；出厂（sealed）后数据库触发器拒绝回写，
  证据再失效也只影响尚未出厂或待放行的配置。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Mapping

from .clock import SystemClock, isoformat
from .contracts import (
    EVIDENCE_KINDS,
    EVIDENCE_OWNER,
    validate_architecture,
    validate_evidence,
    validate_position,
)
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "hardware": {
        "read", "part.write", "architecture.publish", "evidence.submit",
        "config.write", "movement.write",
    },
    "software": {"read", "evidence.submit"},
    "quality": {
        "read", "evidence.submit", "evidence.revoke", "substitution.write",
        "release.evaluate", "release.decide", "release.ship",
    },
    "auditor": {"read", "report.read"},
    "admin": {
        "read", "report.read", "part.write", "architecture.publish", "evidence.submit",
        "evidence.revoke", "substitution.write", "config.write", "movement.write",
        "release.evaluate", "release.decide", "release.ship", "user.write",
    },
}


class ReleaseChainService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def bootstrap_admin(self, user_id: str = "admin", display_name: str = "系统管理员") -> dict[str, Any] | None:
        """初始化首个管理员账号；已存在时不做改动。"""

        if self.connection.execute("SELECT 1 FROM users WHERE user_id=?", (user_id,)).fetchone():
            return None
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",
                (user_id, display_name, "admin", self._now()),
            )
        return {"user_id": user_id, "role": "admin"}

    # ------------------------------------------------------------------ 基础

    def _now(self) -> str:
        return isoformat(self.clock.now())

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
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(
        self, actor_id: str, user_id: str, display_name: str, role: str
    ) -> dict[str, Any]:
        self._require(actor_id, "user.write")
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
                self._audit("user", user_id, "user.created", actor_id, {"role": role})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    # ------------------------------------------------------------- 主数据/架构

    def register_part(self, actor_id: str, part_no: str, kind: str, description: str) -> dict[str, Any]:
        self._require(actor_id, "part.write")
        if kind not in ("controller", "bus_chip", "ai_compute"):
            raise ValidationFailed("kind 必须是 controller、bus_chip 或 ai_compute")
        if not description.strip():
            raise ValidationFailed("description 不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO parts(part_no,kind,description,created_at) VALUES(?,?,?,?)",
                    (part_no, kind, description.strip(), self._now()),
                )
                self._audit("part", part_no, "part.registered", actor_id, {"kind": kind})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"部件料号已存在: {part_no}") from exc
        return {"part_no": part_no, "kind": kind}

    def publish_architecture(self, actor_id: str, architecture_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "architecture.publish")
        normalized = validate_architecture(raw)
        digest = content_digest([normalized])
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT COALESCE(MAX(version),0) AS v FROM architectures WHERE architecture_id=?",
                (architecture_id,),
            ).fetchone()
            version = row["v"] + 1
            try:
                self.connection.execute(
                    "INSERT INTO architectures(architecture_id,version,canonical_json,content_sha256,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?)",
                    (architecture_id, version, canonical_json(normalized), digest, actor_id, self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("架构内容与已发布版本完全相同，或编号不合法") from exc
            self._audit("architecture", f"{architecture_id}@{version}",
                        "architecture.published", actor_id, {"sha256": digest})
        return {"architecture_id": architecture_id, "version": version, "sha256": digest}

    def get_architecture(self, actor_id: str, architecture_id: str, version: int) -> dict[str, Any]:
        self._require(actor_id, "read")
        row = self.connection.execute(
            "SELECT * FROM architectures WHERE architecture_id=? AND version=?",
            (architecture_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("架构版本不存在")
        result = dict(row)
        result["content"] = json.loads(result.pop("canonical_json"))
        return result

    # ------------------------------------------------------------------ 证据

    def submit_evidence(
        self, actor_id: str, part_no: str, kind: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        actor = self._require(actor_id, "evidence.submit")
        if kind not in EVIDENCE_KINDS:
            raise ValidationFailed(f"未知证据类型: {kind}")
        if actor["role"] != "admin" and actor["role"] != EVIDENCE_OWNER[kind]:
            raise Forbidden(f"{kind} 证据只能由 {EVIDENCE_OWNER[kind]} 角色提交")
        normalized = validate_evidence(kind, payload)
        if not self.connection.execute("SELECT 1 FROM parts WHERE part_no=?", (part_no,)).fetchone():
            raise NotFound(f"部件料号不存在: {part_no}")
        digest = content_digest([{"kind": kind, "payload": normalized}])
        with transaction(self.connection, immediate=True):
            previous = self.connection.execute(
                "SELECT evidence_id, version, revoked FROM part_evidence "
                "WHERE part_no=? AND kind=? ORDER BY version DESC LIMIT 1",
                (part_no, kind),
            ).fetchone()
            version = 1 if previous is None else previous["version"] + 1
            try:
                cursor = self.connection.execute(
                    "INSERT INTO part_evidence(part_no,kind,version,superseded_version,payload_json,"
                    "content_sha256,submitted_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (part_no, kind, version,
                     None if previous is None else previous["evidence_id"],
                     canonical_json(normalized), digest, actor["user_id"], self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("证据版本冲突") from exc
            evidence_id = cursor.lastrowid
            self._audit("evidence", str(evidence_id), "evidence.submitted", actor["user_id"], {
                "part_no": part_no, "kind": kind, "version": version,
                "supersedes": None if previous is None else previous["evidence_id"],
            })
        return {
            "evidence_id": evidence_id, "part_no": part_no, "kind": kind,
            "version": version, "sha256": digest,
            "awaiting_role": EVIDENCE_OWNER[kind],
        }

    def sign_evidence(
        self, actor_id: str, evidence_id: int, decision: str, comment: str = ""
    ) -> dict[str, Any]:
        actor = self._require(actor_id, "evidence.submit")  # 三个工程角色都有此权限
        row = self.connection.execute(
            "SELECT * FROM part_evidence WHERE evidence_id=?", (evidence_id,)
        ).fetchone()
        if row is None:
            raise NotFound("证据版本不存在")
        owner = EVIDENCE_OWNER[row["kind"]]
        if actor["role"] != owner:
            raise Forbidden(f"{row['kind']} 证据只能由 {owner} 角色确认")
        if actor["user_id"] == row["submitted_by"]:
            raise Forbidden("提交人不能确认自己提交的证据")
        if decision not in ("confirmed", "rejected"):
            raise ValidationFailed("decision 必须是 confirmed 或 rejected")
        if row["revoked"]:
            raise InvalidState("证据版本已失效，不能再签署")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_signoffs(evidence_id,role,decision,comment,signed_by,signed_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (evidence_id, owner, decision, comment, actor["user_id"], self._now()),
                )
                self._audit("evidence", str(evidence_id), "evidence.signed", actor["user_id"],
                            {"role": owner, "decision": decision})
        except sqlite3.IntegrityError as exc:
            raise Conflict("该角色已经签署过此证据版本") from exc
        return {"evidence_id": evidence_id, "role": owner, "decision": decision}

    def revoke_evidence(self, actor_id: str, evidence_id: int, reason: str) -> dict[str, Any]:
        actor = self._require(actor_id, "evidence.revoke")
        if not reason.strip():
            raise ValidationFailed("撤销原因不能为空")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM part_evidence WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            if row is None:
                raise NotFound("证据版本不存在")
            if row["revoked"]:
                raise InvalidState("证据版本已经失效")
            self.connection.execute(
                "UPDATE part_evidence SET revoked=1,revoked_by=?,revoked_at=?,revoke_reason=? "
                "WHERE evidence_id=?",
                (actor["user_id"], self._now(), reason.strip(), evidence_id),
            )
            self._audit("evidence", str(evidence_id), "evidence.revoked", actor["user_id"],
                        {"part_no": row["part_no"], "kind": row["kind"], "reason": reason})
        return {"evidence_id": evidence_id, "revoked": True}

    def get_evidence(self, actor_id: str, evidence_id: int) -> dict[str, Any]:
        self._require(actor_id, "read")
        row = self.connection.execute(
            "SELECT * FROM part_evidence WHERE evidence_id=?", (evidence_id,)
        ).fetchone()
        if row is None:
            raise NotFound("证据版本不存在")
        result = dict(row)
        result["payload"] = json.loads(result.pop("payload_json"))
        result["signoffs"] = [
            dict(sign) for sign in self.connection.execute(
                "SELECT role,decision,comment,signed_by,signed_at FROM evidence_signoffs "
                "WHERE evidence_id=? ORDER BY role", (evidence_id,)
            ).fetchall()
        ]
        return result

    # ------------------------------------------------------------------ 替代料

    def approve_substitution(
        self,
        actor_id: str,
        substitution_id: str,
        original_part_no: str,
        substitute_part_no: str,
        justification: str,
        architecture_id: str | None = None,
        applies_from_version: int | None = None,
        applies_to_version: int | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "substitution.write")
        if not justification.strip():
            raise ValidationFailed("justification 不能为空")
        for part_no in (original_part_no, substitute_part_no):
            if not self.connection.execute("SELECT 1 FROM parts WHERE part_no=?", (part_no,)).fetchone():
                raise NotFound(f"部件料号不存在: {part_no}")
        if original_part_no == substitute_part_no:
            raise ValidationFailed("替代料号不能与原料号相同")
        original = self.connection.execute(
            "SELECT kind FROM parts WHERE part_no=?", (original_part_no,)
        ).fetchone()
        substitute = self.connection.execute(
            "SELECT kind FROM parts WHERE part_no=?", (substitute_part_no,)
        ).fetchone()
        if original["kind"] != substitute["kind"]:
            raise ValidationFailed("替代料与原料号的部件类型必须一致")
        range_tuple = (architecture_id, applies_from_version, applies_to_version)
        if (architecture_id is None) != (applies_from_version is None):
            raise ValidationFailed("架构适用范围必须同时给出 architecture_id 与版本区间，或都为空")
        if architecture_id is not None:
            if not self.connection.execute(
                "SELECT 1 FROM architectures WHERE architecture_id=? AND version=?",
                (architecture_id, applies_to_version),
            ).fetchone():
                raise NotFound("架构适用范围引用了不存在的架构版本")
        payload = {
            "substitution_id": substitution_id,
            "original_part_no": original_part_no,
            "substitute_part_no": substitute_part_no,
            "architecture_id": architecture_id,
            "applies_from_version": applies_from_version,
            "applies_to_version": applies_to_version,
            "justification": justification.strip(),
        }
        digest = content_digest([payload])
        with transaction(self.connection, immediate=True):
            previous = self.connection.execute(
                "SELECT COALESCE(MAX(version),0) AS v FROM substitutions WHERE substitution_id=?",
                (substitution_id,),
            ).fetchone()
            if previous["v"]:
                last = self.connection.execute(
                    "SELECT original_part_no,substitute_part_no FROM substitutions "
                    "WHERE substitution_id=? AND version=?", (substitution_id, previous["v"])
                ).fetchone()
                if (last["original_part_no"], last["substitute_part_no"]) != (
                    original_part_no, substitute_part_no
                ):
                    raise ValidationFailed("同一替代决定编号不能更换原料号或替代料号")
            try:
                self.connection.execute(
                    "INSERT INTO substitutions(substitution_id,version,original_part_no,"
                    "substitute_part_no,architecture_id,applies_from_version,applies_to_version,"
                    "justification,content_sha256,approved_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (substitution_id, previous["v"] + 1, original_part_no, substitute_part_no,
                     architecture_id, applies_from_version, applies_to_version,
                     justification.strip(), digest, actor_id, self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("替代决定版本冲突") from exc
            version = previous["v"] + 1
            self._audit("substitution", f"{substitution_id}@{version}",
                        "substitution.approved", actor_id,
                        {**{k: v for k, v in payload.items() if k != "substitution_id"},
                         "version": version})
        return {"substitution_id": substitution_id, "version": version, "coverage": range_tuple}

    def revoke_substitution(self, actor_id: str, substitution_id: str, reason: str) -> dict[str, Any]:
        actor = self._require(actor_id, "substitution.write")
        if not reason.strip():
            raise ValidationFailed("撤销原因不能为空")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM substitutions WHERE substitution_id=? "
                "ORDER BY version DESC LIMIT 1", (substitution_id,)
            ).fetchone()
            if row is None:
                raise NotFound("替代决定不存在")
            if row["revoked"]:
                raise InvalidState("替代决定最新版本已经失效")
            self.connection.execute(
                "UPDATE substitutions SET revoked=1,revoked_by=?,revoked_at=?,revoke_reason=? "
                "WHERE substitution_id=? AND version=?",
                (actor["user_id"], self._now(), reason.strip(), substitution_id, row["version"]),
            )
            self._audit("substitution", f"{substitution_id}@{row['version']}",
                        "substitution.revoked", actor["user_id"], {"reason": reason})
        return {"substitution_id": substitution_id, "version": row["version"], "revoked": True}

    def _active_substitution(
        self, nominal: str, actual: str, architecture_id: str, architecture_version: int
    ) -> dict[str, Any] | None:
        """找到覆盖指定架构版本的生效替代决定（最新生效版本）。"""

        rows = self.connection.execute(
            "SELECT * FROM substitutions WHERE original_part_no=? AND substitute_part_no=? "
            "AND revoked=0 ORDER BY version DESC",
            (nominal, actual),
        ).fetchall()
        for row in rows:
            if row["architecture_id"] is None:
                return dict(row)
            if (
                row["architecture_id"] == architecture_id
                and row["applies_from_version"] <= architecture_version <= row["applies_to_version"]
            ):
                return dict(row)
        return None

    def substitution_coverage(self, actor_id: str, substitution_id: str) -> dict[str, Any]:
        self._require(actor_id, "read")
        versions = self.connection.execute(
            "SELECT * FROM substitutions WHERE substitution_id=? ORDER BY version",
            (substitution_id,),
        ).fetchall()
        if not versions:
            raise NotFound("替代决定不存在")
        latest = self.connection.execute(
            "SELECT * FROM substitutions WHERE substitution_id=? ORDER BY version DESC LIMIT 1",
            (substitution_id,),
        ).fetchone()
        affected_pending: list[dict[str, Any]] = []
        frozen: list[dict[str, Any]] = []
        if not latest["revoked"]:
            configs = self.connection.execute(
                "SELECT c.config_sha256,c.robot_serial,c.architecture_id,c.architecture_version,"
                "c.positions_json,r.sealed,r.decision FROM robot_configurations c "
                "LEFT JOIN assembly_releases r ON r.config_sha256=c.config_sha256"
            ).fetchall()
            for config in configs:
                positions = json.loads(config["positions_json"])
                if not self._config_uses_substitution(dict(config), positions, latest):
                    continue
                item = {
                    "config_sha256": config["config_sha256"],
                    "robot_serial": config["robot_serial"],
                    "architecture": f"{config['architecture_id']}@{config['architecture_version']}",
                    "decision": config["decision"],
                }
                (frozen if config["sealed"] else affected_pending).append(item)
        return {
            "substitution_id": substitution_id,
            "latest_version": latest["version"],
            "active": not bool(latest["revoked"]),
            "original_part_no": latest["original_part_no"],
            "substitute_part_no": latest["substitute_part_no"],
            "coverage": {
                "architecture_id": latest["architecture_id"],
                "applies_from_version": latest["applies_from_version"],
                "applies_to_version": latest["applies_to_version"],
            },
            "affects_pending_configurations": affected_pending,
            "frozen_factory_configurations": frozen,
        }

    def _config_uses_substitution(
        self, config: dict[str, Any], positions: dict[str, Any], substitution: sqlite3.Row
    ) -> bool:
        architecture = self._architecture_content(
            config["architecture_id"], config["architecture_version"]
        )
        for slot, requirement in architecture["requirements"].items():
            nominal = requirement.get("part_no")
            actual = positions.get(slot, {}).get("part_no")
            if nominal and actual == substitution["substitute_part_no"] and nominal == substitution["original_part_no"]:
                if substitution["architecture_id"] is None:
                    return True
                if (
                    substitution["architecture_id"] == config["architecture_id"]
                    and substitution["applies_from_version"] <= config["architecture_version"]
                    <= substitution["applies_to_version"]
                ):
                    return True
        return False

    # ------------------------------------------------------------- 配置与去向

    def _architecture_content(self, architecture_id: str, version: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT canonical_json FROM architectures WHERE architecture_id=? AND version=?",
            (architecture_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("架构版本不存在")
        return json.loads(row["canonical_json"])

    def register_configuration(
        self,
        actor_id: str,
        robot_serial: str,
        architecture_id: str,
        architecture_version: int,
        positions: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._require(actor_id, "config.write")
        architecture = self._architecture_content(architecture_id, architecture_version)
        normalized = validate_position(positions)
        if set(normalized) != set(architecture["requirements"]):
            raise ValidationFailed("配置槽位必须与架构要求一一对应")
        canonical = {
            "robot_serial": robot_serial,
            "architecture_id": architecture_id,
            "architecture_version": architecture_version,
            "positions": normalized,
        }
        digest = content_digest([canonical])
        with transaction(self.connection, immediate=True):
            try:
                self.connection.execute(
                    "INSERT INTO robot_configurations(config_sha256,robot_serial,architecture_id,"
                    "architecture_version,positions_json,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (digest, robot_serial, architecture_id, architecture_version,
                     canonical_json(normalized), actor_id, self._now()),
                )
                self._audit("configuration", digest, "configuration.registered", actor_id, {
                    "robot_serial": robot_serial,
                    "architecture": f"{architecture_id}@{architecture_version}",
                })
            except sqlite3.IntegrityError:
                existing = self.connection.execute(
                    "SELECT robot_serial FROM robot_configurations WHERE config_sha256=?", (digest,)
                ).fetchone()
                if existing["robot_serial"] != robot_serial:
                    raise Conflict("配置摘要与其他机器人冲突") from None
        return {"config_sha256": digest, "robot_serial": robot_serial}

    def record_movement(
        self,
        actor_id: str,
        serial_no: str,
        part_no: str,
        event: str,
        robot_serial: str | None = None,
        config_sha256: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        self._require(actor_id, "movement.write")
        if event not in ("installed", "removed", "reworked", "scrapped"):
            raise ValidationFailed("event 必须是 installed、removed、reworked 或 scrapped")
        if not self.connection.execute("SELECT 1 FROM parts WHERE part_no=?", (part_no,)).fetchone():
            raise NotFound(f"部件料号不存在: {part_no}")
        last = self.connection.execute(
            "SELECT * FROM serial_movements WHERE serial_no=? ORDER BY movement_id DESC LIMIT 1",
            (serial_no,),
        ).fetchone()
        allowed: dict[str | None, set[str]] = {
            None: {"installed"},
            "installed": {"removed", "reworked", "scrapped"},
            "removed": {"installed", "reworked", "scrapped"},
            "reworked": {"installed", "reworked", "scrapped"},
            "scrapped": set(),
        }
        if event not in allowed[None if last is None else last["event"]]:
            raise InvalidState(
                f"序列号当前状态为 {last['event'] if last else '未登记'}，不能记录 {event}"
            )
        target_config = None
        if event == "installed":
            if not robot_serial or not config_sha256:
                raise ValidationFailed("装配必须给出机器人序列号和配置摘要")
            target_config = self.connection.execute(
                "SELECT * FROM robot_configurations WHERE config_sha256=?", (config_sha256,)
            ).fetchone()
            if target_config is None:
                raise NotFound("配置不存在，先登记确定配置")
            if target_config["robot_serial"] != robot_serial:
                raise ValidationFailed("机器人序列号与配置不一致")
            positions = json.loads(target_config["positions_json"])
            slot_hit = next(
                (slot for slot, ref in positions.items()
                 if ref["part_no"] == part_no and ref["serial_no"] == serial_no),
                None,
            )
            if slot_hit is None:
                raise ValidationFailed("该序列号/料号不在目标配置的槽位中")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO serial_movements(serial_no,part_no,event,robot_serial,config_sha256,"
                "note,actor_id,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (serial_no, part_no, event, robot_serial, config_sha256, note,
                 actor_id, self._now()),
            )
            self._audit("serial", serial_no, f"serial.{event}", actor_id, {
                "part_no": part_no, "robot_serial": robot_serial,
                "config_sha256": config_sha256, "note": note,
            })
        return {"serial_no": serial_no, "event": event, "part_no": part_no}

    def serial_trace(self, actor_id: str, serial_no: str) -> dict[str, Any]:
        self._require(actor_id, "read")
        rows = self.connection.execute(
            "SELECT movement_id,part_no,event,robot_serial,config_sha256,note,actor_id,created_at "
            "FROM serial_movements WHERE serial_no=? ORDER BY movement_id",
            (serial_no,),
        ).fetchall()
        if not rows:
            raise NotFound("序列号没有任何去向记录")
        last = rows[-1]
        location = None
        if last["event"] in ("installed", "reworked") and last["config_sha256"]:
            location = {"robot_serial": last["robot_serial"], "config_sha256": last["config_sha256"]}
        return {
            "serial_no": serial_no,
            "part_no": last["part_no"],
            "state": last["event"],
            "location": location,
            "scrapped": last["event"] == "scrapped",
            "movements": [dict(row) for row in rows],
        }

    # ------------------------------------------------------------------ 放行

    @staticmethod
    def _firmware_at_least(actual: str, required: str) -> bool:
        def core(text: str) -> tuple[int, ...]:
            return tuple(int(part) for part in text.split("-", 1)[0].split("+", 1)[0].split("."))
        return core(actual) >= core(required)

    def _latest_evidence(self, part_no: str, kind: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM part_evidence WHERE part_no=? AND kind=? "
            "ORDER BY version DESC LIMIT 1", (part_no, kind)
        ).fetchone()

    def _evaluate_slot(self, slot: str, requirement: Mapping[str, Any], ref: Mapping[str, str]) -> dict[str, Any]:
        part_no = ref["part_no"]
        serial_no = ref["serial_no"]
        part = self.connection.execute("SELECT * FROM parts WHERE part_no=?", (part_no,)).fetchone()
        blockers: list[str] = []
        pending: list[str] = []
        if part is None:
            blockers.append(f"槽位 {slot} 的料号 {part_no} 未登记")
            part_kind = requirement["kind"]
        else:
            part_kind = part["kind"]
            if part["kind"] != requirement["kind"]:
                blockers.append(
                    f"槽位 {slot} 要求 {requirement['kind']}，实际料号类型为 {part['kind']}"
                )

        nominal = requirement.get("part_no")
        substitution_used = None
        if nominal and part_no != nominal:
            match = None
            arch_id = self._current_arch[0]
            arch_ver = self._current_arch[1]
            match = self._active_substitution(nominal, part_no, arch_id, arch_ver)
            if match is None:
                blockers.append(
                    f"槽位 {slot} 使用 {part_no}，但没有覆盖该架构版本的有效替代料批准替代 {nominal}"
                )
            else:
                substitution_used = {
                    "substitution_id": match["substitution_id"],
                    "version": match["version"],
                    "coverage": {
                        "architecture_id": match["architecture_id"],
                        "applies_from_version": match["applies_from_version"],
                        "applies_to_version": match["applies_to_version"],
                    },
                    "justification": match["justification"],
                }

        evidence_used: dict[str, Any] = {}
        if part is not None:
            for kind in EVIDENCE_KINDS:
                row = self._latest_evidence(part_no, kind)
                owner = EVIDENCE_OWNER[kind]
                if row is None:
                    blockers.append(f"槽位 {slot} 缺少 {kind} 证据")
                    pending.append(f"{part_no}:{kind} 等待提交({owner})")
                    continue
                entry: dict[str, Any] = {
                    "evidence_id": row["evidence_id"], "version": row["version"],
                    "submitted_by": row["submitted_by"], "sha256": row["content_sha256"],
                }
                if row["revoked"]:
                    blockers.append(
                        f"槽位 {slot} 的 {part_no} {kind} 证据 v{row['version']} 已失效"
                    )
                    pending.append(f"{part_no}:{kind} 等待重新提交并签署")
                    evidence_used[kind] = entry
                    continue
                signoff = self.connection.execute(
                    "SELECT decision,signed_by FROM evidence_signoffs WHERE evidence_id=? AND role=?",
                    (row["evidence_id"], owner),
                ).fetchone()
                if signoff is None:
                    blockers.append(f"槽位 {slot} 的 {kind} 证据缺少 {owner} 角色签署")
                    pending.append(f"{part_no}:{kind} v{row['version']} 等待 {owner} 签署")
                elif signoff["decision"] == "rejected":
                    blockers.append(f"槽位 {slot} 的 {kind} 证据被 {owner} 角色驳回")
                    pending.append(f"{part_no}:{kind} 需要重新提交")
                else:
                    entry["confirmed_by"] = signoff["signed_by"]
                # 技术兼容性检查与签署状态无关，证据内容本身即被校验
                payload = json.loads(row["payload_json"])
                if kind == "firmware_digest" and requirement.get("min_firmware"):
                    if not self._firmware_at_least(payload["firmware_baseline"], requirement["min_firmware"]):
                        blockers.append(
                            f"槽位 {slot} 固件基线 {payload['firmware_baseline']} "
                            f"低于架构要求 {requirement['min_firmware']}"
                        )
                if kind == "interface_capability":
                    missing_protocols = sorted(
                        set(requirement.get("required_bus_protocols", [])) - set(payload["bus_protocols"])
                    )
                    entry["bus_protocols"] = payload["bus_protocols"]
                    if missing_protocols:
                        blockers.append(f"槽位 {slot} 缺少总线协议能力 {missing_protocols}")
                if kind == "inspection":
                    entry["result"] = payload["result"]
                    if payload["result"] != "pass":
                        blockers.append(
                            f"槽位 {slot} 检验结论为 {payload['result']}，不能放行"
                        )
                        pending.append(f"{part_no}:inspection 等待合格检验")
                if kind == "lineage":
                    entry["manufacturing_batch"] = payload["manufacturing_batch"]
                    entry["date_code"] = payload["date_code"]
                evidence_used[kind] = entry

        # 序列号去向核对
        serial_state = self.connection.execute(
            "SELECT event,robot_serial,config_sha256 FROM serial_movements "
            "WHERE serial_no=? ORDER BY movement_id DESC LIMIT 1", (serial_no,)
        ).fetchone()
        if serial_state is None:
            blockers.append(f"槽位 {slot} 序列号 {serial_no} 没有装配去向记录")
        elif serial_state["event"] == "scrapped":
            blockers.append(f"槽位 {slot} 序列号 {serial_no} 已报废")
        elif serial_state["event"] != "installed" or serial_state["config_sha256"] != self._current_config:
            blockers.append(f"槽位 {slot} 序列号 {serial_no} 未装入当前配置")

        return {
            "slot": slot,
            "required_kind": requirement["kind"],
            "nominal_part_no": nominal,
            "part_no": part_no,
            "serial_no": serial_no,
            "substitution": substitution_used,
            "evidence": evidence_used,
            "blockers": blockers,
            "pending": pending,
        }

    def evaluate_configuration(self, actor_id: str, config_sha256: str) -> dict[str, Any]:
        actor = self._require(actor_id, "release.evaluate")
        config = self.connection.execute(
            "SELECT * FROM robot_configurations WHERE config_sha256=?", (config_sha256,)
        ).fetchone()
        if config is None:
            raise NotFound("配置不存在")
        existing = self.connection.execute(
            "SELECT sealed FROM assembly_releases WHERE config_sha256=?", (config_sha256,)
        ).fetchone()
        if existing is not None and existing["sealed"]:
            raise InvalidState("配置已出厂，放行结论已冻结，不能重新评估")
        architecture = self._architecture_content(config["architecture_id"], config["architecture_version"])
        positions = json.loads(config["positions_json"])
        self._current_arch = (config["architecture_id"], config["architecture_version"])
        self._current_config = config_sha256
        slots = [
            self._evaluate_slot(slot, architecture["requirements"][slot], positions[slot])
            for slot in sorted(architecture["requirements"])
        ]
        blockers = [item for slot in slots for item in slot["blockers"]]
        pending = [item for slot in slots for item in slot["pending"]]
        gate = "released" if not blockers else "blocked"
        evaluation = {
            "config_sha256": config_sha256,
            "robot_serial": config["robot_serial"],
            "architecture": f"{config['architecture_id']}@{config['architecture_version']}",
            "gate": gate,
            "slots": slots,
            "blockers": blockers,
            "pending": pending,
            "evaluated_by": actor["user_id"],
            "evaluated_at": self._now(),
        }
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO assembly_releases(config_sha256,decision,evaluation_json) "
                "VALUES(?,?,?) ON CONFLICT(config_sha256) DO UPDATE SET "
                "decision=excluded.decision, evaluation_json=excluded.evaluation_json, "
                "decided_by=NULL, decided_at=NULL",
                (config_sha256, gate, canonical_json(evaluation)),
            )
            self._audit("release", config_sha256, "release.evaluated", actor["user_id"],
                        {"gate": gate, "blocker_count": len(blockers)})
        return evaluation

    def decide_release(
        self, actor_id: str, config_sha256: str, decision: str, reason: str
    ) -> dict[str, Any]:
        actor = self._require(actor_id, "release.decide")
        if decision not in ("released", "rejected"):
            raise ValidationFailed("decision 必须是 released 或 rejected")
        if not reason.strip():
            raise ValidationFailed("reason 不能为空")
        row = self.connection.execute(
            "SELECT * FROM assembly_releases WHERE config_sha256=?", (config_sha256,)
        ).fetchone()
        if row is None:
            raise InvalidState("请先对配置执行兼容性评估")
        if row["sealed"]:
            raise InvalidState("配置已出厂，放行结论不可更改")
        if decision == "released" and row["decision"] != "released":
            raise InvalidState("仍存在未关闭的阻断项，不能放行")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE assembly_releases SET decision=?,decided_by=?,decided_at=? "
                "WHERE config_sha256=? AND sealed=0",
                (decision, actor["user_id"], self._now(), config_sha256),
            )
            self._audit("release", config_sha256, "release.decided", actor["user_id"],
                        {"decision": decision, "reason": reason})
        return {"config_sha256": config_sha256, "decision": decision}

    def ship_release(self, actor_id: str, config_sha256: str) -> dict[str, Any]:
        actor = self._require(actor_id, "release.ship")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM assembly_releases WHERE config_sha256=?", (config_sha256,)
            ).fetchone()
            if row is None:
                raise InvalidState("配置尚未评估，不能出厂")
            if row["sealed"]:
                raise InvalidState("配置已经出厂")
            if row["decision"] != "released":
                raise InvalidState("只有放行结论为 released 的配置可以出厂")
            self.connection.execute(
                "UPDATE assembly_releases SET sealed=1,sealed_at=? WHERE config_sha256=? AND sealed=0",
                (self._now(), config_sha256),
            )
            self._audit("release", config_sha256, "release.shipped", actor["user_id"], {})
        return {"config_sha256": config_sha256, "sealed": True}

    def explain_robot(self, actor_id: str, config_sha256: str) -> dict[str, Any]:
        """回答：这台机器人为什么允许/不允许使用某批部件、替代覆盖范围、未完成事项。"""

        self._require(actor_id, "read")
        config = self.connection.execute(
            "SELECT * FROM robot_configurations WHERE config_sha256=?", (config_sha256,)
        ).fetchone()
        if config is None:
            raise NotFound("配置不存在")
        release = self.connection.execute(
            "SELECT * FROM assembly_releases WHERE config_sha256=?", (config_sha256,)
        ).fetchone()
        explanation: dict[str, Any] = {
            "config_sha256": config_sha256,
            "robot_serial": config["robot_serial"],
            "architecture": f"{config['architecture_id']}@{config['architecture_version']}",
            "factory_sealed": bool(release and release["sealed"]),
            "release_decision": None if release is None else release["decision"],
        }
        if release is not None:
            evaluation = json.loads(release["evaluation_json"])
            explanation["slots"] = evaluation["slots"]
            explanation["blockers"] = evaluation["blockers"]
            explanation["pending"] = evaluation["pending"]
            explanation["evaluated_at"] = evaluation["evaluated_at"]
            if release["sealed"]:
                explanation["notice"] = "配置已出厂，以下为出厂时冻结的事实；后续证据失效不回写本结论。"
        else:
            explanation["notice"] = "配置尚未评估。"
            positions = json.loads(config["positions_json"])
            explanation["positions"] = positions
            explanation["blockers"] = ["尚未执行兼容性评估"]
        return explanation

    def pending_releases(self, actor_id: str) -> list[dict[str, Any]]:
        self._require(actor_id, "read")
        rows = self.connection.execute(
            "SELECT r.config_sha256,c.robot_serial,c.architecture_id,c.architecture_version,"
            "r.decision,r.sealed FROM assembly_releases r "
            "JOIN robot_configurations c ON c.config_sha256=r.config_sha256 "
            "WHERE r.sealed=0 ORDER BY r.config_sha256"
        ).fetchall()
        return [dict(row) for row in rows]

    def audit(self, actor_id: str, entity_type: str, entity_id: str) -> list[dict[str, Any]]:
        self._require(actor_id, "read")
        rows = self.connection.execute(
            "SELECT event_id,entity_type,entity_id,event_type,actor_id,payload_json,created_at "
            "FROM audit_events WHERE entity_type=? AND entity_id=? ORDER BY event_id",
            (entity_type, entity_id),
        ).fetchall()
        return [
            dict(row) | {"payload": json.loads(row["payload_json"])}
            for row in rows
        ]
