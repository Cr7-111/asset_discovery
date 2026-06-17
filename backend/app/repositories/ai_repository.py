# 文件作用：负责 AI 综合风险研判结果的数据库写入和查询。
"""AI analysis repository: persistence for LLM-generated analysis."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Callable

from mysql.connector import Error

logger = logging.getLogger(__name__)


def upsert_ai_analysis(
    get_connection: Callable,
    *,
    asset_id: int,
    asset_type: str,
    risk_reason: str,
    weak_points: list[str],
    suggestions: list[str],
    report_summary: str,
    model_name: str,
) -> None:
    """Insert or update AI analysis for one asset."""
    # 每个资产只保留一条最新 AI 分析结果；重复分析时通过唯一键更新旧记录。
    sql = """
    INSERT INTO asset_ai_analysis
        (asset_id, asset_type, risk_reason, weak_points, suggestions, report_summary, model_name, created_at, updated_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        asset_type = VALUES(asset_type),
        risk_reason = VALUES(risk_reason),
        weak_points = VALUES(weak_points),
        suggestions = VALUES(suggestions),
        report_summary = VALUES(report_summary),
        model_name = VALUES(model_name),
        updated_at = VALUES(updated_at);
    """
    now = datetime.utcnow()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        # weak_points 和 suggestions 是列表结构，入库前转成 JSON 字符串保存。
        cursor.execute(
            sql,
            (
                asset_id,
                asset_type,
                risk_reason,
                json.dumps(weak_points, ensure_ascii=False),
                json.dumps(suggestions, ensure_ascii=False),
                report_summary,
                model_name,
                now,
                now,
            ),
        )
        conn.commit()
        cursor.close()
    except Error as exc:
        # 写入失败时回滚事务，避免部分字段写入导致分析结果不完整。
        conn.rollback()
        logger.error("upsert_ai_analysis failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()


def fetch_ai_analysis(get_connection: Callable, asset_id: int) -> dict | None:
    """Fetch AI analysis by asset id."""
    # 按资产编号读取 AI 分析结果，供资产详情页“综合风险研判”模块展示。
    sql = """
    SELECT id, asset_id, asset_type, risk_reason, weak_points, suggestions,
           report_summary, model_name, created_at, updated_at
    FROM asset_ai_analysis
    WHERE asset_id = %s;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (asset_id,))
        row = cursor.fetchone()
        cursor.close()
        if row:
            for key in ("weak_points", "suggestions"):
                value = row.get(key)
                if isinstance(value, str):
                    try:
                        # JSON 字段返回给前端前恢复成列表结构，方便页面逐条展示。
                        row[key] = json.loads(value)
                    except json.JSONDecodeError:
                        # 历史脏数据或异常 JSON 不阻断详情展示，降级为空列表。
                        row[key] = []
            # datetime 统一转字符串，避免 Flask JSON 序列化兼容问题。
            row["created_at"] = str(row["created_at"])
            row["updated_at"] = str(row["updated_at"])
        return row
    except Error as exc:
        logger.error("fetch_ai_analysis failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()
