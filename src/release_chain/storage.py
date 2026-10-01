"""部件来源与兼容放行链的 SQLite 结构。

所有业务表只追加（INSERT），不提供覆盖更新；对已不可变的事实表通过触发器
拒绝 UPDATE 与 DELETE，保证证据失效只能追加新版本、不能回写历史。
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 账号与硬件/软件/质量角色分离
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('hardware', 'software', 'quality', 'auditor', 'admin')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL
);

-- 架构版本（整机电子架构基线），内容按摘要去重
CREATE TABLE IF NOT EXISTS architectures (
    architecture_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    canonical_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (architecture_id, version),
    UNIQUE (content_sha256)
);

-- 部件料号主数据（仅登记，兼容性由架构要求与部件证据决定）
CREATE TABLE IF NOT EXISTS parts (
    part_no TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('controller', 'bus_chip', 'ai_compute')),
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 部件证据：厂商声明、批次谱系、固件摘要、接口能力、检验结果
-- 同一 (part_no, kind) 可有多版本；superseded_version 串起版本链；
-- revoked=1 表示该版本证据失效（追加标记，不删除原行）。
CREATE TABLE IF NOT EXISTS part_evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    part_no TEXT NOT NULL REFERENCES parts(part_no),
    kind TEXT NOT NULL CHECK (kind IN (
        'vendor_declaration', 'lineage', 'firmware_digest',
        'interface_capability', 'inspection')),
    version INTEGER NOT NULL CHECK (version > 0),
    superseded_version INTEGER REFERENCES part_evidence(evidence_id),
    payload_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    submitted_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    revoked_by TEXT REFERENCES users(user_id),
    revoked_at TEXT,
    revoke_reason TEXT,
    UNIQUE (part_no, kind, version)
);

-- 角色签署：硬件、软件、质量分别确认自己负责的证据版本；
-- 每个角色对每版证据至多一条签署（追加即终态，不可改）。
CREATE TABLE IF NOT EXISTS evidence_signoffs (
    evidence_id INTEGER NOT NULL REFERENCES part_evidence(evidence_id),
    role TEXT NOT NULL CHECK (role IN ('hardware', 'software', 'quality')),
    decision TEXT NOT NULL CHECK (decision IN ('confirmed', 'rejected')),
    comment TEXT NOT NULL DEFAULT '',
    signed_by TEXT NOT NULL REFERENCES users(user_id),
    signed_at TEXT NOT NULL,
    PRIMARY KEY (evidence_id, role)
);

-- 替代料批准：替代料号在适用架构版本范围内可替代原料号，同样版本化、可撤销。
CREATE TABLE IF NOT EXISTS substitutions (
    substitution_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    original_part_no TEXT NOT NULL REFERENCES parts(part_no),
    substitute_part_no TEXT NOT NULL REFERENCES parts(part_no),
    architecture_id TEXT,
    applies_from_version INTEGER,
    applies_to_version INTEGER,
    justification TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    approved_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    revoked_by TEXT REFERENCES users(user_id),
    revoked_at TEXT,
    revoke_reason TEXT,
    PRIMARY KEY (substitution_id, version),
    CHECK (original_part_no <> substitute_part_no),
    CHECK ((applies_from_version IS NULL) = (applies_to_version IS NULL)),
    CHECK (applies_from_version IS NULL OR applies_from_version <= applies_to_version)
);

-- 确定的整机配置：对配置内容求摘要，作为放行结论锚定的不可变事实。
CREATE TABLE IF NOT EXISTS robot_configurations (
    config_sha256 TEXT PRIMARY KEY CHECK (length(config_sha256) = 64),
    robot_serial TEXT NOT NULL,
    architecture_id TEXT NOT NULL,
    architecture_version INTEGER NOT NULL,
    positions_json TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    FOREIGN KEY (architecture_id, architecture_version)
        REFERENCES architectures(architecture_id, version)
);

-- 序列号去向事件：装配、拆出、返工、报废，全部追加；
-- 同序列号当前状态由事件链推导，历史永不回写。
CREATE TABLE IF NOT EXISTS serial_movements (
    movement_id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_no TEXT NOT NULL,
    part_no TEXT NOT NULL REFERENCES parts(part_no),
    event TEXT NOT NULL CHECK (event IN ('installed', 'removed', 'reworked', 'scrapped')),
    robot_serial TEXT,
    config_sha256 TEXT REFERENCES robot_configurations(config_sha256),
    note TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_serial_movements_serial ON serial_movements(serial_no, movement_id);

-- 针对确定配置的装配放行评估与结论（每配置仅一行；出厂即冻结）。
CREATE TABLE IF NOT EXISTS assembly_releases (
    config_sha256 TEXT PRIMARY KEY REFERENCES robot_configurations(config_sha256),
    decision TEXT NOT NULL CHECK (decision IN ('released', 'rejected', 'blocked')),
    evaluation_json TEXT NOT NULL,
    decided_by TEXT REFERENCES users(user_id),
    decided_at TEXT,
    sealed INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),
    sealed_at TEXT
);

-- 审计事件流
CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 事实表不可变：拒绝任何更新或删除（撤销通过追加新版本/失效标记完成）。
CREATE TRIGGER IF NOT EXISTS trg_evidence_no_update
BEFORE UPDATE ON part_evidence
WHEN NOT (
    OLD.revoked = 0 AND NEW.revoked = 1
    AND NEW.part_no = OLD.part_no AND NEW.kind = OLD.kind
    AND NEW.version = OLD.version AND NEW.payload_json = OLD.payload_json
    AND NEW.content_sha256 = OLD.content_sha256
    AND NEW.submitted_by = OLD.submitted_by AND NEW.created_at = OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'part_evidence 为追加型事实，只允许追加撤销标记(0->1)');
END;
CREATE TRIGGER IF NOT EXISTS trg_evidence_no_delete
BEFORE DELETE ON part_evidence
BEGIN
    SELECT RAISE(ABORT, 'part_evidence 不可删除');
END;
CREATE TRIGGER IF NOT EXISTS trg_signoffs_no_update
BEFORE UPDATE ON evidence_signoffs
BEGIN
    SELECT RAISE(ABORT, 'evidence_signoffs 不可更新');
END;
CREATE TRIGGER IF NOT EXISTS trg_signoffs_no_delete
BEFORE DELETE ON evidence_signoffs
BEGIN
    SELECT RAISE(ABORT, 'evidence_signoffs 不可删除');
END;
CREATE TRIGGER IF NOT EXISTS trg_configs_no_update
BEFORE UPDATE ON robot_configurations
BEGIN
    SELECT RAISE(ABORT, 'robot_configurations 不可更新');
END;
CREATE TRIGGER IF NOT EXISTS trg_configs_no_delete
BEFORE DELETE ON robot_configurations
BEGIN
    SELECT RAISE(ABORT, 'robot_configurations 不可删除');
END;
CREATE TRIGGER IF NOT EXISTS trg_movements_no_update
BEFORE UPDATE ON serial_movements
BEGIN
    SELECT RAISE(ABORT, 'serial_movements 不可更新');
END;
CREATE TRIGGER IF NOT EXISTS trg_movements_no_delete
BEFORE DELETE ON serial_movements
BEGIN
    SELECT RAISE(ABORT, 'serial_movements 不可删除');
END;
CREATE TRIGGER IF NOT EXISTS trg_release_sealed_no_update
BEFORE UPDATE ON assembly_releases
WHEN OLD.sealed = 1
BEGIN
    SELECT RAISE(ABORT, '已出厂配置的放行结论已冻结，不可回写');
END;
CREATE TRIGGER IF NOT EXISTS trg_release_no_delete
BEFORE DELETE ON assembly_releases
BEGIN
    SELECT RAISE(ABORT, 'assembly_releases 不可删除');
END;
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "users", "architectures", "parts", "part_evidence",
    "evidence_signoffs", "substitutions", "robot_configurations",
    "serial_movements", "assembly_releases", "audit_events",
})


def connect(path: str | Path = ":memory:") -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    triggers = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_%'"
        ).fetchall()
    }
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    return {
        "tables": tables,
        "missing_tables": sorted(REQUIRED_TABLES - set(tables)),
        "schema_version": None if version_row is None else version_row["value"],
        "immutability_triggers": sorted(triggers),
    }
