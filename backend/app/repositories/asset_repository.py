# 文件作用：资产表数据访问层，负责有效资产的新增、更新、查询和删除。
"""Asset repository: persistence operations for asset table."""

from __future__ import annotations

import logging
from typing import Callable

from mysql.connector import Error

logger = logging.getLogger(__name__)


def upsert_asset(
    get_connection: Callable,
    *,
    domain: str,
    ip: str,
    port: int,
    status_code: int | None,
    title: str | None,
    server: str | None,
) -> int:
    """新增或更新一条有效资产记录。"""
    # 没有 HTTP 状态码说明未完成有效验证，不应进入资产基础表。
    if status_code is None:
        logger.info("skip asset without status_code [%s/%s:%d]", domain, ip, port)
        return 0
    # 将验证成功的目标写入资产基础表；若资产已存在，则更新最新探测结果。
    sql = """
    INSERT INTO asset (domain, ip, port, status_code, title, server)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        status_code = VALUES(status_code),
        title = VALUES(title),
        server = VALUES(server),
        last_seen = CURRENT_TIMESTAMP;
    """
    conn = get_connection()
    try:
        # 使用独立连接执行写入，完成后及时关闭，避免连接池被长期占用。
        cursor = conn.cursor()
        # domain、ip、port 用于唯一标识一个资产入口。
        cursor.execute(sql, (domain, ip, port, status_code, title, server))
        conn.commit()
        rows = cursor.rowcount
        cursor.close()
        return rows
    except Error as exc:
        conn.rollback()
        logger.error("upsert_asset failed [%s/%s:%d]: %s", domain, ip, port, exc)
        raise
    finally:
        conn.close()


def fetch_all_assets(get_connection: Callable) -> list[dict]:
    """Fetch all assets ordered by last_seen desc."""
    # 资产列表只展示有状态码的有效资产，过滤掉未验证或验证失败的线索。
    sql = """
    SELECT asset_id, domain, ip, port, status_code, title, server, first_seen, last_seen
    FROM asset
    WHERE status_code IS NOT NULL
    ORDER BY last_seen DESC;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql)
        rows = cursor.fetchall()
        cursor.close()
        for row in rows:
            # datetime 转为字符串，方便 Flask JSON 序列化和前端直接展示。
            row["first_seen"] = str(row["first_seen"])
            row["last_seen"] = str(row["last_seen"])
        return rows
    except Error as exc:
        logger.error("fetch_all_assets failed: %s", exc)
        raise
    finally:
        conn.close()


def fetch_asset_by_id(get_connection: Callable, asset_id: int) -> dict | None:
    """Fetch a single asset by id."""
    # 资产详情按主键查询，供分析、风险评估和详情页共用。
    sql = """
    SELECT asset_id, domain, ip, port, status_code, title, server, first_seen, last_seen
    FROM asset
    WHERE asset_id = %s;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (asset_id,))
        row = cursor.fetchone()
        cursor.close()
        if row:
            row["first_seen"] = str(row["first_seen"])
            row["last_seen"] = str(row["last_seen"])
        return row
    except Error as exc:
        logger.error("fetch_asset_by_id failed [id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()


def delete_asset_by_id(get_connection: Callable, asset_id: int) -> int:
    """Delete one asset by id."""
    # 删除资产时，相关分析/标签/风险表通过数据库外键级联清理。
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM asset WHERE asset_id = %s;", (asset_id,))
        conn.commit()
        rows = cursor.rowcount
        cursor.close()
        return rows
    except Error as exc:
        conn.rollback()
        logger.error("delete_asset_by_id failed [id=%d]: %s", asset_id, exc)
        raise
    finally:
        conn.close()
