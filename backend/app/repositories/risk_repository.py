"""Risk repository: persistence operations for risk scoring results."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Callable

from mysql.connector import Error

logger = logging.getLogger(__name__)


def upsert_risk(
    get_connection: Callable,
    *,
    asset_id: int,
    risk_score: int,
    risk_level: str,
    score_detail: str,
    suggestions: str,
) -> None:
    """Insert or update risk result for one asset."""
    sql = """
    INSERT INTO risk_result (asset_id, risk_score, risk_level, score_detail, suggestions, assessed_at)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        risk_score = VALUES(risk_score),
        risk_level = VALUES(risk_level),
        score_detail = VALUES(score_detail),
        suggestions = VALUES(suggestions),
        assessed_at = VALUES(assessed_at);
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            sql,
            (
                asset_id,
                risk_score,
                risk_level,
                score_detail,
                suggestions,
                datetime.utcnow(),
            ),
        )
        conn.commit()
        cursor.close()
    except Error as exc:
        conn.rollback()
        logger.error("upsert_risk failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()


def fetch_risk_by_asset(get_connection: Callable, asset_id: int) -> dict | None:
    """Fetch one risk result with asset details."""
    sql = """
    SELECT r.id, r.asset_id, r.risk_score, r.risk_level, r.score_detail, r.suggestions,
           r.assessed_at, a.domain, a.ip, a.port, a.title, a.server
    FROM risk_result r
    JOIN asset a ON r.asset_id = a.asset_id
    WHERE r.asset_id = %s;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (asset_id,))
        row = cursor.fetchone()
        cursor.close()
        if row:
            row["assessed_at"] = str(row["assessed_at"])
        return row
    except Error as exc:
        logger.error("fetch_risk_by_asset failed [asset_id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()


def fetch_all_risks(
    get_connection: Callable,
    risk_level: str | None = None,
    min_score: int | None = None,
    page: int = 1,
    per_page: int = 20,
) -> dict:
    """Fetch paginated risk results."""
    where_clauses = []
    params: list = []

    if risk_level:
        where_clauses.append("r.risk_level = %s")
        params.append(risk_level)
    if min_score is not None:
        where_clauses.append("r.risk_score >= %s")
        params.append(min_score)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    count_sql = (
        "SELECT COUNT(*) AS cnt FROM risk_result r "
        f"JOIN asset a ON r.asset_id = a.asset_id {where_sql};"
    )
    data_sql = f"""
    SELECT r.id, r.asset_id, r.risk_score, r.risk_level, r.score_detail, r.suggestions,
           r.assessed_at, a.domain, a.ip, a.port
    FROM risk_result r
    JOIN asset a ON r.asset_id = a.asset_id
    {where_sql}
    ORDER BY r.risk_score DESC
    LIMIT %s OFFSET %s;
    """
    offset = (page - 1) * per_page

    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(count_sql, params)
        total = cursor.fetchone()["cnt"]
        cursor.execute(data_sql, params + [per_page, offset])
        rows = cursor.fetchall()
        cursor.close()
        for row in rows:
            row["assessed_at"] = str(row["assessed_at"])
        return {"total": total, "page": page, "per_page": per_page, "items": rows}
    except Error as exc:
        logger.error("fetch_all_risks failed: %s", exc)
        raise
    finally:
        conn.close()


def fetch_risk_stats(get_connection: Callable) -> dict:
    """Fetch dashboard statistics for risk and analysis data."""
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) AS cnt FROM asset;")
        total_assets = cursor.fetchone()["cnt"]

        cursor.execute(
            """
            SELECT COUNT(*) AS cnt, ROUND(AVG(risk_score), 1) AS avg_score
            FROM risk_result;
            """
        )
        summary = cursor.fetchone()
        assessed_assets = summary["cnt"]
        avg_score = float(summary["avg_score"] or 0)

        cursor.execute(
            """
            SELECT risk_level, COUNT(*) AS cnt
            FROM risk_result
            GROUP BY risk_level;
            """
        )
        level_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for row in cursor.fetchall():
            level_counts[row["risk_level"]] = row["cnt"]

        cursor.execute(
            """
            SELECT asset_type, COUNT(*) AS cnt
            FROM asset_analysis
            GROUP BY asset_type
            ORDER BY cnt DESC;
            """
        )
        type_counts = {row["asset_type"]: row["cnt"] for row in cursor.fetchall()}

        cursor.close()
        return {
            "total_assets": total_assets,
            "assessed_assets": assessed_assets,
            "avg_score": avg_score,
            "level_counts": level_counts,
            "type_counts": type_counts,
        }
    except Error as exc:
        logger.error("fetch_risk_stats failed: %s", exc)
        raise
    finally:
        conn.close()
