# 文件作用：资产扫描服务门面，统一导出扫描执行、扫描结果持久化和资产入库能力。
"""Scan service facade for scan execution and scan-result persistence."""

from __future__ import annotations

from backend.app.core.db import persist_scan_result, upsert_asset
from backend.app.services.discovery.orchestrator import run_multi_source_scan

__all__ = [
    # API 层通过该服务门面调用扫描相关能力，避免直接依赖底层仓储和编排模块。
    "persist_scan_result",
    "run_multi_source_scan",
    "upsert_asset",
]
