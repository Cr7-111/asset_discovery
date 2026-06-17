# 文件作用：提供资产列表查询、资产详情查询和资产删除接口。
"""Asset query and deletion routes."""

from __future__ import annotations

from flask import Blueprint, jsonify

from backend.app.api.common import logger
from backend.app.services.asset_service import delete_asset_by_id, fetch_all_assets, fetch_asset_by_id

asset_bp = Blueprint("asset_api", __name__)


@asset_bp.route("/assets", methods=["GET"])
def list_assets():
    try:
        # 查询已经入库并验证成功的资产列表，供前端资产管理页面展示。
        assets = fetch_all_assets()
        return jsonify({"total": len(assets), "assets": assets})
    except Exception as exc:  # noqa: BLE001
        logger.error("Fetch assets failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@asset_bp.route("/assets/<int:asset_id>", methods=["GET"])
def get_asset(asset_id: int):
    try:
        # 根据资产主键读取单个资产详情，后续分析、风险和机器学习模块都依赖该资产信息。
        asset = fetch_asset_by_id(asset_id)
        if asset is None:
            # 资产不存在时返回 404，便于前端给出明确提示。
            return jsonify({"error": f"asset_id={asset_id} not found"}), 404
        return jsonify(asset)
    except Exception as exc:  # noqa: BLE001
        logger.error("Fetch asset failed [id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc)}), 500


@asset_bp.route("/assets/<int:asset_id>", methods=["DELETE"])
def remove_asset(asset_id: int):
    try:
        # 删除资产基础记录；相关分析结果由数据库外键或业务逻辑同步清理。
        rows = delete_asset_by_id(asset_id)
        if rows == 0:
            return jsonify({"error": f"asset_id={asset_id} not found"}), 404
        return jsonify({"message": f"deleted asset_id={asset_id}"})
    except Exception as exc:  # noqa: BLE001
        logger.error("Delete asset failed [id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc)}), 500
