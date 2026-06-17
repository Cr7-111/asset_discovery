# 认证服务门面，统一导出用户账号相关的数据访问函数。
"""Auth service facade for user account persistence operations."""

from __future__ import annotations

from backend.app.core.db import (
    create_user,
    delete_user_by_id,
    fetch_all_users,
    fetch_user_by_id,
    fetch_user_by_username,
    update_user_last_login,
    update_user_profile,
)

__all__ = [
    # 通过 __all__ 明确服务层对外暴露的用户相关能力，API 层只从这里导入。
    "create_user",
    "delete_user_by_id",
    "fetch_all_users",
    "fetch_user_by_id",
    "fetch_user_by_username",
    "update_user_last_login",
    "update_user_profile",
]
