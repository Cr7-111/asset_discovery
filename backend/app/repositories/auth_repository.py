"""Auth repository: persistence operations for user accounts."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Callable

from mysql.connector import Error

logger = logging.getLogger(__name__)


def _public_user(row: dict | None) -> dict | None:
    if not row:
        return None
    public = {
        "id": row.get("id"),
        "username": row.get("username"),
        "display_name": row.get("display_name"),
        "avatar_url": row.get("avatar_url") or "",
        "role": row.get("role"),
        "is_active": row.get("is_active"),
        "created_at": str(row.get("created_at")) if row.get("created_at") else None,
        "updated_at": str(row.get("updated_at")) if row.get("updated_at") else None,
        "last_login_at": str(row.get("last_login_at")) if row.get("last_login_at") else None,
    }
    return public


def create_user(
    get_connection: Callable,
    *,
    username: str,
    password_hash: str,
    display_name: str | None = None,
    role: str = "user",
    avatar_url: str | None = None,
) -> int:
    """Create a user account and return the new id."""
    sql = """
    INSERT INTO user_account (username, password_hash, display_name, avatar_url, role)
    VALUES (%s, %s, %s, %s, %s);
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (username, password_hash, display_name, avatar_url, role))
        conn.commit()
        user_id = cursor.lastrowid
        cursor.close()
        return user_id
    except Error as exc:
        conn.rollback()
        logger.error("create_user failed [username=%s]: %s", username, exc)
        raise
    finally:
        conn.close()


def fetch_all_users(get_connection: Callable) -> list[dict]:
    """Fetch all users without password hashes."""
    sql = """
    SELECT id, username, display_name, avatar_url, role, is_active, created_at, updated_at, last_login_at
    FROM user_account
    ORDER BY id ASC;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql)
        rows = cursor.fetchall()
        cursor.close()
        return [_public_user(row) for row in rows]
    except Error as exc:
        logger.error("fetch_all_users failed: %s", exc)
        raise
    finally:
        conn.close()


def fetch_user_by_id(get_connection: Callable, user_id: int) -> dict | None:
    """Fetch one user by id without password hash."""
    sql = """
    SELECT id, username, display_name, avatar_url, role, is_active, created_at, updated_at, last_login_at
    FROM user_account
    WHERE id = %s;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (user_id,))
        row = cursor.fetchone()
        cursor.close()
        return _public_user(row)
    except Error as exc:
        logger.error("fetch_user_by_id failed [id=%d]: %s", user_id, exc)
        raise
    finally:
        conn.close()


def fetch_user_by_username(get_connection: Callable, username: str) -> dict | None:
    """Fetch one user account by username."""
    sql = """
    SELECT id, username, password_hash, display_name, avatar_url, role, is_active, created_at, updated_at, last_login_at
    FROM user_account
    WHERE username = %s;
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (username,))
        row = cursor.fetchone()
        cursor.close()
        if row:
            row["created_at"] = str(row["created_at"])
            row["updated_at"] = str(row["updated_at"])
            row["last_login_at"] = str(row["last_login_at"]) if row["last_login_at"] else None
        return row
    except Error as exc:
        logger.error("fetch_user_by_username failed [username=%s]: %s", username, exc)
        raise
    finally:
        conn.close()


def update_user_profile(
    get_connection: Callable,
    user_id: int,
    *,
    display_name: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    avatar_url: str | None = None,
) -> int:
    """Update editable user fields and return affected row count."""
    fields = []
    values = []
    if display_name is not None:
        fields.append("display_name = %s")
        values.append(display_name)
    if role is not None:
        fields.append("role = %s")
        values.append(role)
    if is_active is not None:
        fields.append("is_active = %s")
        values.append(1 if is_active else 0)
    if avatar_url is not None:
        fields.append("avatar_url = %s")
        values.append(avatar_url)
    if not fields:
        return 0

    values.append(user_id)
    sql = f"UPDATE user_account SET {', '.join(fields)} WHERE id = %s;"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, tuple(values))
        conn.commit()
        rowcount = cursor.rowcount
        cursor.close()
        return rowcount
    except Error as exc:
        conn.rollback()
        logger.error("update_user_profile failed [id=%d]: %s", user_id, exc)
        raise
    finally:
        conn.close()


def delete_user_by_id(get_connection: Callable, user_id: int) -> int:
    """Delete one user by id and return affected row count."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_account WHERE id = %s;", (user_id,))
        conn.commit()
        rowcount = cursor.rowcount
        cursor.close()
        return rowcount
    except Error as exc:
        conn.rollback()
        logger.error("delete_user_by_id failed [id=%d]: %s", user_id, exc)
        raise
    finally:
        conn.close()


def update_user_last_login(get_connection: Callable, user_id: int) -> None:
    """Update user last login timestamp."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_account SET last_login_at = %s WHERE id = %s;",
            (datetime.utcnow(), user_id),
        )
        conn.commit()
        cursor.close()
    except Error as exc:
        conn.rollback()
        logger.error("update_user_last_login failed [id=%d]: %s", user_id, exc)
        raise
    finally:
        conn.close()
