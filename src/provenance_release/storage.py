"""部件来源与兼容放行链的 SQLite 模式与事务辅助。

证据类表（厂商声明、固件基线、接口能力、检验结果、替代关系、确认与失效）
均为只插不改的不可覆盖版本；更正通过登记新版本完成。
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

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('hardware','software','quality','operator','auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS component_models (
    model_id TEXT PRIMARY KEY,
    category TEXT NOT NULL CHECK (category IN ('controller','bus_chip','ai_compute')),
    vendor TEXT NOT NULL,
    description TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS architectures (
    arch_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    name TEXT NOT NULL,
    slots_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (arch_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS vendor_declarations (
    declaration_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    model_id TEXT NOT NULL REFERENCES component_models(model_id),
    vendor TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (declaration_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS firmware_baselines (
    firmware_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    model_id TEXT NOT NULL REFERENCES component_models(model_id),
    digest_sha256 TEXT NOT NULL CHECK (length(digest_sha256) = 64),
    notes TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (firmware_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS interface_capabilities (
    capability_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    model_id TEXT NOT NULL REFERENCES component_models(model_id),
    firmware_id TEXT NOT NULL,
    firmware_version INTEGER NOT NULL,
    capabilities_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (capability_id, version),
    UNIQUE (content_sha256),
    FOREIGN KEY (firmware_id, firmware_version) REFERENCES firmware_baselines(firmware_id, version)
);

CREATE TABLE IF NOT EXISTS part_batches (
    batch_id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL REFERENCES component_models(model_id),
    vendor TEXT NOT NULL,
    lot_code TEXT NOT NULL,
    parent_batch_id TEXT REFERENCES part_batches(batch_id),
    split_note TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inspections (
    inspection_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES part_batches(batch_id),
    inspection_type TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('pass','fail')),
    evidence_ref TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS substitutions (
    substitution_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    arch_id TEXT NOT NULL,
    arch_version INTEGER NOT NULL,
    slot_id TEXT NOT NULL,
    from_model TEXT NOT NULL REFERENCES component_models(model_id),
    to_model TEXT NOT NULL REFERENCES component_models(model_id),
    conditions_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (substitution_id, version),
    UNIQUE (content_sha256),
    FOREIGN KEY (arch_id, arch_version) REFERENCES architectures(arch_id, version)
);

CREATE TABLE IF NOT EXISTS evidence_confirmations (
    confirmation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN
        ('vendor_declaration','firmware_baseline','interface_capability','inspection','substitution')),
    evidence_id TEXT NOT NULL,
    evidence_version INTEGER NOT NULL CHECK (evidence_version > 0),
    domain TEXT NOT NULL CHECK (domain IN ('hardware','software','quality')),
    statement TEXT NOT NULL,
    confirmed_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (evidence_kind, evidence_id, evidence_version, domain)
);

CREATE TABLE IF NOT EXISTS evidence_invalidations (
    invalidation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN
        ('vendor_declaration','firmware_baseline','interface_capability','inspection','substitution','batch')),
    evidence_id TEXT NOT NULL,
    evidence_version INTEGER NOT NULL CHECK (evidence_version >= 0),
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (evidence_kind, evidence_id, evidence_version)
);

CREATE TABLE IF NOT EXISTS machine_configs (
    config_id TEXT PRIMARY KEY,
    robot_model TEXT NOT NULL,
    arch_id TEXT NOT NULL,
    arch_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('draft','assembled','released','shipped')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (arch_id, arch_version) REFERENCES architectures(arch_id, version)
);

CREATE TABLE IF NOT EXISTS serials (
    serial_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES part_batches(batch_id),
    state TEXT NOT NULL CHECK (state IN ('in_stock','installed','rework','scrapped','returned','shipped')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_slots (
    config_id TEXT NOT NULL REFERENCES machine_configs(config_id),
    slot_id TEXT NOT NULL,
    model_id TEXT NOT NULL REFERENCES component_models(model_id),
    batch_id TEXT NOT NULL REFERENCES part_batches(batch_id),
    firmware_id TEXT NOT NULL,
    firmware_version INTEGER NOT NULL,
    serial_id TEXT REFERENCES serials(serial_id),
    PRIMARY KEY (config_id, slot_id)
);

CREATE TABLE IF NOT EXISTS assembly_releases (
    release_id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_id TEXT NOT NULL REFERENCES machine_configs(config_id),
    config_revision INTEGER NOT NULL,
    conclusion TEXT NOT NULL CHECK (conclusion IN ('released','blocked')),
    detail_json TEXT NOT NULL,
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (config_id, input_sha256)
);

CREATE TABLE IF NOT EXISTS shipments (
    config_id TEXT PRIMARY KEY REFERENCES machine_configs(config_id),
    release_id INTEGER NOT NULL REFERENCES assembly_releases(release_id),
    shipped_by TEXT NOT NULL REFERENCES users(user_id),
    shipped_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS serial_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_id TEXT NOT NULL REFERENCES serials(serial_id),
    event_type TEXT NOT NULL,
    from_batch_id TEXT,
    to_batch_id TEXT,
    config_id TEXT,
    slot_id TEXT,
    note TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_serial_events_serial
ON serial_events(serial_id, event_id);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_entity
ON audit_events(entity_type, entity_id, event_id);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "users", "component_models", "architectures", "vendor_declarations",
    "firmware_baselines", "interface_capabilities", "part_batches", "inspections",
    "substitutions", "evidence_confirmations", "evidence_invalidations",
    "machine_configs", "config_slots", "assembly_releases", "shipments",
    "serials", "serial_events", "audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。

    check_same_thread=False 允许 HTTP 工作线程共享连接；并发安全由
    JsonApplication 中的请求锁保证（单连接 SQLite 的串行语义）。
    """

    connection = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    """初始化基础资料表，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
