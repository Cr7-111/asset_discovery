# 文件作用：资产服务门面，统一导出资产查询和删除相关的数据访问能力。
"""Asset service facade for asset query and deletion operations."""

from __future__ import annotations

from backend.app.core.db import delete_asset_by_id, fetch_all_assets, fetch_asset_by_id

__all__ = [
    # API 层只从服务门面导入资产操作函数，保持路由层依赖简单。
    "delete_asset_by_id",
    "fetch_all_assets",
    "fetch_asset_by_id",
]
