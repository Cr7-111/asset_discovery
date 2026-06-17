"""Analysis repository: persistence operations for analysis and tags."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Callable

from mysql.connector import Error

logger = logging.getLogger(__name__)


def upsert_analysis(get_connection: Callable, asset_id: int, asset_type: str, confidence: float) -> None:
    """Insert or update one asset analysis result."""
    sql = """
    INSERT INTO asset_analysis (asset_id, asset_type, model_confidence, analysis_time)
    VALUES (%s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        asset_type = VALUES(asset_type),
        model_confidence = VALUES(model_confidence),
        analysis_time = VALUES(analysis_time);
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (asset_id, asset_type, round(confidence, 4), datetime.utcnow()))
        conn.commit()
        cursor.close()
    except Error as exc:
        conn.rollback()
        logger.error("upsert_analysis failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()


def fetch_analysis(get_connection: Callable, asset_id: int) -> dict | None:
    """Fetch analysis result by asset id."""
    sql = """
    SELECT id, asset_id, asset_type, model_confidence, analysis_time
    FROM asset_analysis
    WHERE asset_id = %s;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (asset_id,))
        row = cursor.fetchone()
        cursor.close()
        if row:
            row["model_confidence"] = float(row["model_confidence"])
            row["analysis_time"] = str(row["analysis_time"])
        return row
    except Error as exc:
        logger.error("fetch_analysis failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()


def fetch_all_analysis(get_connection: Callable) -> list[dict]:
    """Fetch all analysis results."""
    sql = """
    SELECT aa.id, aa.asset_id, aa.asset_type, aa.model_confidence, aa.analysis_time,
           a.domain, a.ip, a.port
    FROM asset_analysis aa
    JOIN asset a ON aa.asset_id = a.asset_id
    ORDER BY aa.analysis_time DESC;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql)
        rows = cursor.fetchall()
        cursor.close()
        for row in rows:
            row["model_confidence"] = float(row["model_confidence"])
            row["analysis_time"] = str(row["analysis_time"])
        return rows
    except Error as exc:
        logger.error("fetch_all_analysis failed: %s", exc)
        raise
    finally:
        conn.close()


def upsert_tag(
    get_connection: Callable,
    *,
    asset_id: int,
    tag_name: str,
    tag_source: str,
    confidence: float,
    matched_rule: str = "",
) -> None:
    """Insert or update one asset tag."""
    sql = """
    INSERT INTO asset_tag (asset_id, tag_name, tag_source, confidence, matched_rule, created_at)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        confidence = VALUES(confidence),
        matched_rule = VALUES(matched_rule),
        created_at = VALUES(created_at);
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            sql,
            (
                asset_id,
                tag_name,
                tag_source,
                round(confidence, 4),
                (matched_rule or "")[:512],
                datetime.utcnow(),
            ),
        )
        conn.commit()
        cursor.close()
    except Error as exc:
        conn.rollback()
        logger.error("upsert_tag failed [asset_id=%d tag=%s]: %s", asset_id, tag_name, exc)
        raise
    finally:
        conn.close()


def upsert_tags_batch(get_connection: Callable, tags: list[dict]) -> int:
    """Insert or update multiple asset tags in one transaction."""
    if not tags:
        return 0

    sql = """
    INSERT INTO asset_tag (asset_id, tag_name, tag_source, confidence, matched_rule, created_at)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        confidence = VALUES(confidence),
        matched_rule = VALUES(matched_rule),
        created_at = VALUES(created_at);
    """
    now = datetime.utcnow()
    rows = [
        (
            item["asset_id"],
            item["tag_name"],
            item["tag_source"],
            round(float(item.get("confidence", 1.0)), 4),
            (item.get("matched_rule") or "")[:512],
            now,
        )
        for item in tags
    ]

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.executemany(sql, rows)
        conn.commit()
        saved = cursor.rowcount
        cursor.close()
        return saved
    except Error as exc:
        conn.rollback()
        logger.error("upsert_tags_batch failed: %s", exc)
        raise
    finally:
        conn.close()


def fetch_tags_by_asset(get_connection: Callable, asset_id: int) -> list[dict]:
    """Fetch all tags for one asset."""
    sql = """
    SELECT id, asset_id, tag_name, tag_source, confidence, matched_rule, created_at
    FROM asset_tag
    WHERE asset_id = %s
    ORDER BY confidence DESC, created_at DESC;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (asset_id,))
        rows = cursor.fetchall()
        cursor.close()
        for row in rows:
            row["confidence"] = float(row["confidence"])
            row["created_at"] = str(row["created_at"])
        return rows
    except Error as exc:
        logger.error("fetch_tags_by_asset failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()


def delete_tags_by_asset(get_connection: Callable, asset_id: int) -> int:
    """Delete all tags for one asset."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM asset_tag WHERE asset_id = %s;", (asset_id,))
        conn.commit()
        rows = cursor.rowcount
        cursor.close()
        return rows
    except Error as exc:
        conn.rollback()
        logger.error("delete_tags_by_asset failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()
