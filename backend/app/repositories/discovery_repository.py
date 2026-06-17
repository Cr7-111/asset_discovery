# 文件作用：扫描记录数据访问层，负责保存扫描任务、发现记录和验证记录。
"""Discovery repository: persistence operations for scan runs and records."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Callable

from mysql.connector import Error

logger = logging.getLogger(__name__)


def _parse_iso_datetime(value: str | None) -> datetime | None:
    """Convert ISO timestamp strings from discovery layer into naive UTC datetimes."""
    # 发现模型使用 ISO 字符串，写入 MySQL 前统一转为 datetime。
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


def create_discovery_run(
    get_connection: Callable,
    *,
    domain: str,
    mode: str,
    status: str = "completed",
    options: dict | None = None,
    summary: dict | None = None,
) -> int:
    """Create one scan run record and return the run id."""
    # discovery_run 记录一次完整扫描任务，是发现记录和验证记录的父记录。
    sql = """
    INSERT INTO discovery_run (domain, mode, status, options_json, summary_json, started_at, finished_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    payload_options = json.dumps(options or {}, ensure_ascii=False)
    # 扫描参数和汇总结果以 JSON 字符串保存，便于后续追溯扫描配置。
    payload_summary = json.dumps(summary or {}, ensure_ascii=False)
    now = datetime.utcnow()

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (domain, mode, status, payload_options, payload_summary, now, now))
        conn.commit()
        run_id = cursor.lastrowid
        cursor.close()
        return run_id
    except Error as exc:
        conn.rollback()
        logger.error("create_discovery_run failed [domain=%s mode=%s]: %s", domain, mode, exc)
        raise
    finally:
        conn.close()


def save_discovery_records(get_connection: Callable, run_id: int, stage: str, targets: list[dict]) -> int:
    """Persist passive or active discovery targets as source-level records."""
    # 发现记录按 passive/active 分阶段保存，用于说明资产线索来源。
    sql = """
    INSERT INTO asset_discovery_record (
        run_id, stage, subdomain, ip, source, evidence_text, urls_json, js_endpoints_json,
        first_seen, last_seen, confidence_score, validation_status, raw_payload
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """

    rows = []
    for target in targets:
        # 一个目标可能有多个来源和多个 IP，因此需要展开为多行过程记录。
        subdomain = target.get("subdomain")
        if not subdomain:
            continue
        ips = target.get("ips") or [None]
        sources = target.get("sources") or ["unknown"]
        evidence_text = "\n".join(target.get("evidence") or [])[:4000]
        # URL 和 JS 端点数量不固定，使用 JSON 保存最灵活。
        urls_json = json.dumps(target.get("urls") or [], ensure_ascii=False)
        js_endpoints_json = json.dumps(target.get("js_endpoints") or [], ensure_ascii=False)
        first_seen = _parse_iso_datetime(target.get("first_seen"))
        last_seen = _parse_iso_datetime(target.get("last_seen"))
        confidence_score = int(target.get("confidence_score") or 0)
        validation_status = str(target.get("validation_status") or "discovered")
        raw_payload = json.dumps(target, ensure_ascii=False)

        for source in sources:
            for ip in ips:
                rows.append(
                    (
                        run_id,
                        stage,
                        subdomain,
                        ip,
                        source,
                        evidence_text,
                        urls_json,
                        js_endpoints_json,
                        first_seen,
                        last_seen,
                        confidence_score,
                        validation_status,
                        raw_payload,
                    )
                )

    if not rows:
        # 没有可保存记录时直接返回 0，避免执行空批量插入。
        return 0

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.executemany(sql, rows)
        conn.commit()
        count = cursor.rowcount
        cursor.close()
        return count
    except Error as exc:
        conn.rollback()
        logger.error("save_discovery_records failed [run_id=%d stage=%s]: %s", run_id, stage, exc)
        raise
    finally:
        conn.close()


def save_validation_records(get_connection: Callable, run_id: int, results: list[dict]) -> int:
    """Persist validation probe outputs for one scan run."""
    # 验证记录保存每一次 HTTP/HTTPS 探测的状态码、标题、Server 和来源上下文。
    sql = """
    INSERT INTO asset_validation_record (
        run_id, subdomain, ip, port, scheme, status_code, title, server, success, error_message,
        sources_json, urls_json, js_endpoints_json, cert_subject, cert_issuer, first_seen, last_seen,
        confidence_score, validation_status, raw_payload, validated_at
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """

    rows = []
    now = datetime.utcnow()
    for result in results:
        # raw_payload 保留完整探测结果，后续字段扩展时仍可追溯原始内容。
        rows.append(
            (
                run_id,
                result.get("subdomain"),
                result.get("ip"),
                result.get("port"),
                result.get("scheme"),
                result.get("status_code"),
                result.get("title"),
                result.get("server"),
                1 if result.get("success") else 0,
                result.get("error"),
                json.dumps(result.get("sources") or [], ensure_ascii=False),
                json.dumps(result.get("urls") or [], ensure_ascii=False),
                json.dumps(result.get("js_endpoints") or [], ensure_ascii=False),
                result.get("cert_subject"),
                result.get("cert_issuer"),
                _parse_iso_datetime(result.get("first_seen")),
                _parse_iso_datetime(result.get("last_seen")),
                int(result.get("confidence_score") or 0),
                str(result.get("validation_status") or "discovered"),
                json.dumps(result, ensure_ascii=False),
                now,
            )
        )

    if not rows:
        return 0

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.executemany(sql, rows)
        conn.commit()
        count = cursor.rowcount
        cursor.close()
        return count
    except Error as exc:
        conn.rollback()
        logger.error("save_validation_records failed [run_id=%d]: %s", run_id, exc)
        raise
    finally:
        conn.close()


def persist_scan_result(get_connection: Callable, scan_request: dict, scan_result: dict) -> dict:
    """Persist one scan run plus separated discovery and validation records."""
    # summary 只保存统计信息，详细目标分别进入发现记录和验证记录表。
    summary = {
        "discovery_summary": scan_result.get("discovery_summary", {}),
        "passive_summary": scan_result.get("passive_summary", {}),
        "active_summary": scan_result.get("active_summary", {}),
        "validation_summary": scan_result.get("validation_summary", {}),
        "subdomains_found": scan_result.get("subdomains_found", 0),
        "probes_total": scan_result.get("probes_total", 0),
    }
    run_id = create_discovery_run(
        # 先创建父级扫描任务，后续记录通过 run_id 关联。
        get_connection,
        domain=str(scan_result.get("domain") or scan_request.get("domain") or ""),
        mode=str(scan_result.get("mode") or scan_request.get("mode") or "hybrid"),
        options=scan_request,
        summary=summary,
    )
    passive_rows = save_discovery_records(get_connection, run_id, "passive", scan_result.get("passive_target_details", []))
    # 主动发现、被动发现和验证结果分开保存，便于论文中说明分层存储设计。
    active_rows = save_discovery_records(get_connection, run_id, "active", scan_result.get("active_target_details", []))
    validation_rows = save_validation_records(
        get_connection,
        run_id,
        scan_result.get("validated_results") or scan_result.get("results") or [],
    )
    return {
        "run_id": run_id,
        "discovery_records_saved": passive_rows + active_rows,
        "validation_records_saved": validation_rows,
    }
