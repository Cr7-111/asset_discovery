# 文件作用：提供 AI 综合风险研判结果生成和查询接口。
"""AI analysis routes."""

from __future__ import annotations

from flask import Blueprint, jsonify

from backend.app.api.common import logger
from backend.app.services.ai_service import analyze_asset_with_ai, get_ai_analysis

ai_bp = Blueprint("ai_api", __name__)


@ai_bp.route("/ai/analyze/<int:asset_id>", methods=["POST"])
def ai_analyze_one(asset_id: int):
    logger.info("Received AI analysis request: asset_id=%d", asset_id)
    try:
        # 根据资产、规则分析、风险评估等上下文生成综合研判内容。
        result = analyze_asset_with_ai(asset_id)
        status_code = 200 if result.get("status") == "ok" else 422
        return jsonify(result), status_code
    except Exception as exc:  # noqa: BLE001
        logger.error("AI analysis failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc), "asset_id": asset_id}), 500


@ai_bp.route("/ai/analyze/<int:asset_id>", methods=["GET"])
def get_ai_analyze_one(asset_id: int):
    try:
        # 查询已保存的 AI 分析结果，避免每次打开详情页都重复生成。
        result = get_ai_analysis(asset_id)
        if result is None:
            return jsonify({"message": "AI analysis not found", "asset_id": asset_id}), 404
        return jsonify(result), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Get AI analysis failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc), "asset_id": asset_id}), 500
