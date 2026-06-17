"""机器学习漏洞情报辅助分析接口。"""

from __future__ import annotations

from flask import Blueprint, jsonify

from backend.app.api.common import logger
from backend.app.services.ml_vulnerability_service import analyze_asset_with_ml, get_saved_ml_analysis

ml_bp = Blueprint("ml_api", __name__)


@ml_bp.route("/ml/analyze/<int:asset_id>", methods=["POST"])
def ml_analyze_one(asset_id: int):
    """生成并保存单个资产的机器学习漏洞情报分析结果。"""
    try:
        # 根据前端传入的资产编号，调用机器学习漏洞情报分析服务。
        result = analyze_asset_with_ml(asset_id)
        # 分析成功返回 200；资产不存在或分析失败时返回对应状态。
        status_code = 200 if result.get("status") == "ok" else 404
        return jsonify(result), status_code
    except Exception as exc:  # noqa: BLE001
        # 捕获异常并返回错误信息，避免接口异常中断前端流程。
        logger.error("ML vulnerability analysis failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc), "asset_id": asset_id}), 500


@ml_bp.route("/ml/analyze/<int:asset_id>", methods=["GET"])
def get_ml_analyze_one(asset_id: int):
    """读取已保存的机器学习漏洞情报分析结果。"""
    try:
        result = get_saved_ml_analysis(asset_id)
        if result is None:
            return jsonify({"message": "ML analysis not found", "asset_id": asset_id}), 404
        return jsonify(result), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Get ML vulnerability analysis failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc), "asset_id": asset_id}), 500
