"""机器学习漏洞情报分析结果仓储层。"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Callable

from mysql.connector import Error

logger = logging.getLogger(__name__)


def upsert_ml_analysis(
    get_connection: Callable,
    *,
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
    """新增或更新单个资产的机器学习漏洞情报分析结果。"""
    sql = """
    INSERT INTO asset_ml_analysis
        (asset_id, component, component_confidence, match_evidence, matched_cves,
         severity_counts, ml_risk_score, ml_risk_level, weak_points, explanation,
         disclaimer, model_name, created_at, updated_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        component = VALUES(component),
        component_confidence = VALUES(component_confidence),
        match_evidence = VALUES(match_evidence),
        matched_cves = VALUES(matched_cves),
        severity_counts = VALUES(severity_counts),
        ml_risk_score = VALUES(ml_risk_score),
        ml_risk_level = VALUES(ml_risk_level),
        weak_points = VALUES(weak_points),
        explanation = VALUES(explanation),
        disclaimer = VALUES(disclaimer),
        model_name = VALUES(model_name),
        updated_at = VALUES(updated_at);
    """
    now = datetime.utcnow()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            sql,
            (
                asset_id,
                component,
                int(component_confidence),
                json.dumps(match_evidence, ensure_ascii=False),
                json.dumps(matched_cves, ensure_ascii=False),
                json.dumps(severity_counts, ensure_ascii=False),
                int(ml_risk_score),
                ml_risk_level,
                json.dumps(weak_points, ensure_ascii=False),
                explanation,
                disclaimer,
                model_name,
                now,
                now,
            ),
        )
        conn.commit()
        cursor.close()
    except Error as exc:
        conn.rollback()
        logger.error("upsert_ml_analysis failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()


def fetch_ml_analysis(get_connection: Callable, asset_id: int) -> dict | None:
    """读取单个资产已保存的机器学习漏洞情报分析结果。"""
    sql = """
    SELECT id, asset_id, component, component_confidence, match_evidence, matched_cves,
           severity_counts, ml_risk_score, ml_risk_level, weak_points, explanation,
           disclaimer, model_name, created_at, updated_at
    FROM asset_ml_analysis
    WHERE asset_id = %s;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (asset_id,))
        row = cursor.fetchone()
        cursor.close()
        if row:
            for key in ("match_evidence", "matched_cves", "severity_counts", "weak_points"):
                value = row.get(key)
                if isinstance(value, str):
                    try:
                        row[key] = json.loads(value)
                    except json.JSONDecodeError:
                        row[key] = [] if key != "severity_counts" else {}
            row["created_at"] = str(row["created_at"])
            row["updated_at"] = str(row["updated_at"])
        return row
    except Error as exc:
        logger.error("fetch_ml_analysis failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()
