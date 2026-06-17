"""Unified database bootstrap and compatibility facade."""

from __future__ import annotations

import logging

import mysql.connector
from mysql.connector import Error, pooling
from werkzeug.security import generate_password_hash

from backend.app.repositories import (
    ai_repository,
    analysis_repository,
    asset_repository,
    auth_repository,
    discovery_repository,
    ml_repository,
    risk_repository,
)

logger = logging.getLogger(__name__)

_pool: pooling.MySQLConnectionPool | None = None


DDL_ASSET = """
CREATE TABLE IF NOT EXISTS asset (
    asset_id       INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain         VARCHAR(255) NOT NULL,
    ip             VARCHAR(45) DEFAULT NULL,
    port           SMALLINT UNSIGNED DEFAULT 80,
    status_code    SMALLINT UNSIGNED DEFAULT NULL,
    title          VARCHAR(512) DEFAULT NULL,
    server         VARCHAR(255) DEFAULT NULL,
    first_seen     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                   ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id),
    UNIQUE KEY uq_domain_ip_port (domain, ip, port),
    INDEX idx_domain (domain),
    INDEX idx_status (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_ASSET_ANALYSIS = """
CREATE TABLE IF NOT EXISTS asset_analysis (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id         INT UNSIGNED NOT NULL,
    asset_type       VARCHAR(64) NOT NULL DEFAULT 'unknown',
    model_confidence DECIMAL(5,4) NOT NULL DEFAULT 0.0000,
    analysis_time    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_asset_analysis_asset_id (asset_id),
    INDEX idx_asset_type (asset_type),
    CONSTRAINT fk_analysis_asset
        FOREIGN KEY (asset_id) REFERENCES asset(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_ASSET_TAG = """
CREATE TABLE IF NOT EXISTS asset_tag (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id     INT UNSIGNED NOT NULL,
    tag_name     VARCHAR(64) NOT NULL,
    tag_source   VARCHAR(32) NOT NULL DEFAULT 'rule_engine',
    confidence   DECIMAL(5,4) NOT NULL DEFAULT 1.0000,
    matched_rule VARCHAR(512) DEFAULT NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_asset_tag (asset_id, tag_name, tag_source),
    INDEX idx_tag_name (tag_name),
    CONSTRAINT fk_tag_asset
        FOREIGN KEY (asset_id) REFERENCES asset(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_RISK_RESULT = """
CREATE TABLE IF NOT EXISTS risk_result (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id     INT UNSIGNED NOT NULL,
    risk_score   TINYINT UNSIGNED NOT NULL DEFAULT 0,
    risk_level   VARCHAR(16) NOT NULL DEFAULT 'low',
    score_detail TEXT DEFAULT NULL,
    suggestions  TEXT DEFAULT NULL,
    assessed_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_risk_asset_id (asset_id),
    INDEX idx_risk_level (risk_level),
    INDEX idx_risk_score (risk_score),
    CONSTRAINT fk_risk_asset
        FOREIGN KEY (asset_id) REFERENCES asset(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_ASSET_AI_ANALYSIS = """
CREATE TABLE IF NOT EXISTS asset_ai_analysis (
    id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id       INT UNSIGNED NOT NULL,
    asset_type     VARCHAR(100) DEFAULT NULL,
    risk_reason    TEXT DEFAULT NULL,
    weak_points    JSON DEFAULT NULL,
    suggestions    JSON DEFAULT NULL,
    report_summary TEXT DEFAULT NULL,
    model_name     VARCHAR(100) DEFAULT NULL,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                   ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_asset_ai_analysis (asset_id),
    CONSTRAINT fk_ai_analysis_asset
        FOREIGN KEY (asset_id) REFERENCES asset(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_ASSET_ML_ANALYSIS = """
CREATE TABLE IF NOT EXISTS asset_ml_analysis (
    id                     INT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id               INT UNSIGNED NOT NULL,
    component              VARCHAR(120) DEFAULT NULL,
    component_confidence   SMALLINT NOT NULL DEFAULT 0,
    match_evidence         JSON DEFAULT NULL,
    matched_cves           JSON DEFAULT NULL,
    severity_counts        JSON DEFAULT NULL,
    ml_risk_score          TINYINT UNSIGNED NOT NULL DEFAULT 0,
    ml_risk_level          VARCHAR(16) NOT NULL DEFAULT 'low',
    weak_points            JSON DEFAULT NULL,
    explanation            TEXT DEFAULT NULL,
    disclaimer             TEXT DEFAULT NULL,
    model_name             VARCHAR(120) DEFAULT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                           ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_asset_ml_analysis (asset_id),
    INDEX idx_ml_risk_level (ml_risk_level),
    CONSTRAINT fk_ml_analysis_asset
        FOREIGN KEY (asset_id) REFERENCES asset(asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_USER_ACCOUNT = """
CREATE TABLE IF NOT EXISTS user_account (
    id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username       VARCHAR(64) NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,
    display_name   VARCHAR(100) DEFAULT NULL,
    avatar_url     LONGTEXT DEFAULT NULL,
    role           VARCHAR(32) NOT NULL DEFAULT 'user',
    is_active      TINYINT(1) NOT NULL DEFAULT 1,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                   ON UPDATE CURRENT_TIMESTAMP,
    last_login_at  DATETIME DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_account_username (username),
    INDEX idx_user_account_role (role),
    INDEX idx_user_account_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_DISCOVERY_RUN = """
CREATE TABLE IF NOT EXISTS discovery_run (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain        VARCHAR(255) NOT NULL,
    mode          VARCHAR(16) NOT NULL DEFAULT 'hybrid',
    status        VARCHAR(16) NOT NULL DEFAULT 'completed',
    options_json  LONGTEXT DEFAULT NULL,
    summary_json  LONGTEXT DEFAULT NULL,
    started_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_discovery_run_domain (domain),
    INDEX idx_discovery_run_mode (mode),
    INDEX idx_discovery_run_finished (finished_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_ASSET_DISCOVERY_RECORD = """
CREATE TABLE IF NOT EXISTS asset_discovery_record (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    run_id            BIGINT UNSIGNED NOT NULL,
    stage             VARCHAR(16) NOT NULL,
    subdomain         VARCHAR(255) NOT NULL,
    ip                VARCHAR(45) DEFAULT NULL,
    source            VARCHAR(64) NOT NULL,
    evidence_text     TEXT DEFAULT NULL,
    urls_json         LONGTEXT DEFAULT NULL,
    js_endpoints_json LONGTEXT DEFAULT NULL,
    first_seen        DATETIME DEFAULT NULL,
    last_seen         DATETIME DEFAULT NULL,
    confidence_score  SMALLINT NOT NULL DEFAULT 0,
    validation_status VARCHAR(16) NOT NULL DEFAULT 'discovered',
    raw_payload       LONGTEXT DEFAULT NULL,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_discovery_record_run (run_id),
    INDEX idx_discovery_record_stage (stage),
    INDEX idx_discovery_record_subdomain (subdomain),
    INDEX idx_discovery_record_source (source),
    CONSTRAINT fk_discovery_record_run
        FOREIGN KEY (run_id) REFERENCES discovery_run(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_ASSET_VALIDATION_RECORD = """
CREATE TABLE IF NOT EXISTS asset_validation_record (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    run_id            BIGINT UNSIGNED NOT NULL,
    subdomain         VARCHAR(255) NOT NULL,
    ip                VARCHAR(45) DEFAULT NULL,
    port              SMALLINT UNSIGNED DEFAULT NULL,
    scheme            VARCHAR(16) DEFAULT NULL,
    status_code       SMALLINT UNSIGNED DEFAULT NULL,
    title             VARCHAR(512) DEFAULT NULL,
    server            VARCHAR(255) DEFAULT NULL,
    success           TINYINT(1) NOT NULL DEFAULT 0,
    error_message     TEXT DEFAULT NULL,
    sources_json      LONGTEXT DEFAULT NULL,
    urls_json         LONGTEXT DEFAULT NULL,
    js_endpoints_json LONGTEXT DEFAULT NULL,
    cert_subject      TEXT DEFAULT NULL,
    cert_issuer       TEXT DEFAULT NULL,
    first_seen        DATETIME DEFAULT NULL,
    last_seen         DATETIME DEFAULT NULL,
    confidence_score  SMALLINT NOT NULL DEFAULT 0,
    validation_status VARCHAR(16) NOT NULL DEFAULT 'discovered',
    raw_payload       LONGTEXT DEFAULT NULL,
    validated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_validation_record_run (run_id),
    INDEX idx_validation_record_subdomain (subdomain),
    INDEX idx_validation_record_success (success),
    CONSTRAINT fk_validation_record_run
        FOREIGN KEY (run_id) REFERENCES discovery_run(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def init_db(config: dict) -> None:
    """Initialize database, connection pool, and all tables."""
    global _pool

    try:
        conn = mysql.connector.connect(
            host=config["MYSQL_HOST"],
            port=config["MYSQL_PORT"],
            user=config["MYSQL_USER"],
            password=config["MYSQL_PASSWORD"],
        )
        cursor = conn.cursor()
        db_name = config["MYSQL_DATABASE"]
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Error as exc:
        logger.error("create database failed: %s", exc)
        raise

    try:
        _pool = pooling.MySQLConnectionPool(
            pool_name="asset_pool",
            # 资产详情页会并发读取资产、标签、分析、风险、AI/ML 等数据，连接池过小容易被瞬时请求打满。
            pool_size=int(config.get("MYSQL_POOL_SIZE", 15)),
            host=config["MYSQL_HOST"],
            port=config["MYSQL_PORT"],
            user=config["MYSQL_USER"],
            password=config["MYSQL_PASSWORD"],
            database=config["MYSQL_DATABASE"],
            charset="utf8mb4",
            autocommit=False,
        )
    except Error as exc:
        logger.error("init mysql pool failed: %s", exc)
        raise

    init_asset_tables()
    init_analysis_tables()
    init_risk_table()
    init_ai_analysis_table()
    init_ml_analysis_table()
    init_user_table()
    init_discovery_tables()
    ensure_default_admin(config)


def get_connection() -> pooling.PooledMySQLConnection:
    """Get a connection from the pool."""
    if _pool is None:
        raise RuntimeError("database pool is not initialized, call init_db() first")
    return _pool.get_connection()


def init_asset_tables() -> None:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(DDL_ASSET)
        conn.commit()
        cursor.close()
    except Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_analysis_tables() -> None:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(DDL_ASSET_ANALYSIS)
        cursor.execute(DDL_ASSET_TAG)
        conn.commit()
        cursor.close()
    except Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_risk_table() -> None:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(DDL_RISK_RESULT)
        conn.commit()
        cursor.close()
    except Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_ai_analysis_table() -> None:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(DDL_ASSET_AI_ANALYSIS)
        conn.commit()
        cursor.close()
    except Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_ml_analysis_table() -> None:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(DDL_ASSET_ML_ANALYSIS)
        conn.commit()
        cursor.close()
    except Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_user_table() -> None:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(DDL_USER_ACCOUNT)
        cursor.execute("SHOW COLUMNS FROM user_account LIKE 'avatar_url';")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE user_account ADD COLUMN avatar_url LONGTEXT DEFAULT NULL AFTER display_name;")
        conn.commit()
        cursor.close()
    except Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_discovery_tables() -> None:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(DDL_DISCOVERY_RUN)
        cursor.execute(DDL_ASSET_DISCOVERY_RECORD)
        cursor.execute(DDL_ASSET_VALIDATION_RECORD)
        conn.commit()
        cursor.close()
    except Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_default_admin(config: dict) -> None:
    """Create a default admin account when no user exists."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS cnt FROM user_account;")
        total = cursor.fetchone()["cnt"]
        cursor.close()
    except Error:
        raise
    finally:
        conn.close()

    if total:
        return

    username = config.get("AUTH_USERNAME", "admin")
    password_hash = config.get("AUTH_PASSWORD_HASH") or generate_password_hash(
        config.get("AUTH_PASSWORD", "Admin@123456")
    )
    create_user(
        username=username,
        password_hash=password_hash,
        display_name="system-admin",
        role="admin",
    )


# Compatibility facade: keep all legacy function names stable.
def create_user(
    username: str,
    password_hash: str,
    display_name: str | None = None,
    role: str = "user",
    avatar_url: str | None = None,
) -> int:
    return auth_repository.create_user(
        get_connection,
        username=username,
        password_hash=password_hash,
        display_name=display_name,
        role=role,
        avatar_url=avatar_url,
    )


def fetch_user_by_username(username: str) -> dict | None:
    return auth_repository.fetch_user_by_username(get_connection, username)


def fetch_all_users() -> list[dict]:
    return auth_repository.fetch_all_users(get_connection)


def fetch_user_by_id(user_id: int) -> dict | None:
    return auth_repository.fetch_user_by_id(get_connection, user_id)


def update_user_profile(
    user_id: int,
    *,
    display_name: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    avatar_url: str | None = None,
) -> int:
    return auth_repository.update_user_profile(
        get_connection,
        user_id,
        display_name=display_name,
        role=role,
        is_active=is_active,
        avatar_url=avatar_url,
    )


def delete_user_by_id(user_id: int) -> int:
    return auth_repository.delete_user_by_id(get_connection, user_id)


def update_user_last_login(user_id: int) -> None:
    auth_repository.update_user_last_login(get_connection, user_id)


def create_discovery_run(
    domain: str,
    mode: str,
    *,
    status: str = "completed",
    options: dict | None = None,
    summary: dict | None = None,
) -> int:
    return discovery_repository.create_discovery_run(
        get_connection,
        domain=domain,
        mode=mode,
        status=status,
        options=options,
        summary=summary,
    )


def save_discovery_records(run_id: int, stage: str, targets: list[dict]) -> int:
    return discovery_repository.save_discovery_records(get_connection, run_id, stage, targets)


def save_validation_records(run_id: int, results: list[dict]) -> int:
    return discovery_repository.save_validation_records(get_connection, run_id, results)


def persist_scan_result(scan_request: dict, scan_result: dict) -> dict:
    return discovery_repository.persist_scan_result(get_connection, scan_request, scan_result)


def upsert_asset(
    domain: str,
    ip: str,
    port: int,
    status_code: int | None,
    title: str | None,
    server: str | None,
) -> int:
    return asset_repository.upsert_asset(
        get_connection,
        domain=domain,
        ip=ip,
        port=port,
        status_code=status_code,
        title=title,
        server=server,
    )


def fetch_all_assets() -> list[dict]:
    return asset_repository.fetch_all_assets(get_connection)


def fetch_asset_by_id(asset_id: int) -> dict | None:
    return asset_repository.fetch_asset_by_id(get_connection, asset_id)


def delete_asset_by_id(asset_id: int) -> int:
    return asset_repository.delete_asset_by_id(get_connection, asset_id)


def upsert_analysis(asset_id: int, asset_type: str, confidence: float) -> None:
    analysis_repository.upsert_analysis(get_connection, asset_id, asset_type, confidence)


def fetch_analysis(asset_id: int) -> dict | None:
    return analysis_repository.fetch_analysis(get_connection, asset_id)


def fetch_all_analysis() -> list[dict]:
    return analysis_repository.fetch_all_analysis(get_connection)


def upsert_tag(
    asset_id: int,
    tag_name: str,
    tag_source: str,
    confidence: float,
    matched_rule: str = "",
) -> None:
    analysis_repository.upsert_tag(
        get_connection,
        asset_id=asset_id,
        tag_name=tag_name,
        tag_source=tag_source,
        confidence=confidence,
        matched_rule=matched_rule,
    )


def upsert_tags_batch(tags: list[dict]) -> int:
    return analysis_repository.upsert_tags_batch(get_connection, tags)


def fetch_tags_by_asset(asset_id: int) -> list[dict]:
    return analysis_repository.fetch_tags_by_asset(get_connection, asset_id)


def delete_tags_by_asset(asset_id: int) -> int:
    return analysis_repository.delete_tags_by_asset(get_connection, asset_id)


def upsert_risk(
    asset_id: int,
    risk_score: int,
    risk_level: str,
    score_detail: str,
    suggestions: str,
) -> None:
    risk_repository.upsert_risk(
        get_connection,
        asset_id=asset_id,
        risk_score=risk_score,
        risk_level=risk_level,
        score_detail=score_detail,
        suggestions=suggestions,
    )


def fetch_risk_by_asset(asset_id: int) -> dict | None:
    return risk_repository.fetch_risk_by_asset(get_connection, asset_id)


def upsert_ai_analysis(
    asset_id: int,
    asset_type: str,
    risk_reason: str,
    weak_points: list[str],
    suggestions: list[str],
    report_summary: str,
    model_name: str,
) -> None:
    ai_repository.upsert_ai_analysis(
        get_connection,
        asset_id=asset_id,
        asset_type=asset_type,
        risk_reason=risk_reason,
        weak_points=weak_points,
        suggestions=suggestions,
        report_summary=report_summary,
        model_name=model_name,
    )


def fetch_ai_analysis(asset_id: int) -> dict | None:
    return ai_repository.fetch_ai_analysis(get_connection, asset_id)


def upsert_ml_analysis(
    asset_id: int,
    component: str,
    component_confidence: int,
    match_evidence: list[str],
    matched_cves: list[dict],
    severity_counts: dict,
    ml_risk_score: int,
    ml_risk_level: str,
    weak_points: list[str],
    explanation: str,
    disclaimer: str,
    model_name: str,
) -> None:
    ml_repository.upsert_ml_analysis(
        get_connection,
        asset_id=asset_id,
        component=component,
        component_confidence=component_confidence,
        match_evidence=match_evidence,
        matched_cves=matched_cves,
        severity_counts=severity_counts,
        ml_risk_score=ml_risk_score,
        ml_risk_level=ml_risk_level,
        weak_points=weak_points,
        explanation=explanation,
        disclaimer=disclaimer,
        model_name=model_name,
    )


def fetch_ml_analysis(asset_id: int) -> dict | None:
    return ml_repository.fetch_ml_analysis(get_connection, asset_id)


def fetch_all_risks(
    risk_level: str | None = None,
    min_score: int | None = None,
    page: int = 1,
    per_page: int = 20,
) -> dict:
    return risk_repository.fetch_all_risks(get_connection, risk_level, min_score, page, per_page)


def fetch_risk_stats() -> dict:
    return risk_repository.fetch_risk_stats(get_connection)
