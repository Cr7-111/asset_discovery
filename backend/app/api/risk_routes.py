# 文件作用：提供资产风险评估、风险列表和仪表盘统计接口。
"""Risk assessment and dashboard routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from backend.app.api.common import logger
from backend.app.services.risk_service import assess_all_assets, assess_asset, get_dashboard_stats, get_risk_detail, get_risk_list

risk_bp = Blueprint("risk_api", __name__)


@risk_bp.route("/risk/assess/<int:asset_id>", methods=["POST"])
def assess_one(asset_id: int):
    logger.info("Received risk assessment request: asset_id=%d", asset_id)
    try:
        # 对单个资产执行确定性规则评分，并保存到 risk_result 表。
        result = assess_asset(asset_id)
        status_code = 200 if result.get("status") == "ok" else 422
        return jsonify(result), status_code
    except Exception as exc:  # noqa: BLE001
        logger.error("Risk assessment failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc)}), 500


@risk_bp.route("/risk/assess/all", methods=["POST"])
def assess_all():
    logger.info("Received assess-all request")
    try:
        # 对所有资产执行批量风险评估，用于初始化或批量刷新风险结果。
        return jsonify(assess_all_assets()), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Assess all failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@risk_bp.route("/risk/<int:asset_id>", methods=["GET"])
def get_risk(asset_id: int):
    try:
        # 查询单个资产的风险详情，包含分值、等级、命中规则和整改建议。
        detail = get_risk_detail(asset_id)
        if detail is None:
            return jsonify(
                {
                    "message": "risk detail not found, call POST /api/risk/assess/<asset_id> first",
                    "asset_id": asset_id,
                }
            ), 404
        return jsonify(detail), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Get risk failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc)}), 500


@risk_bp.route("/risks", methods=["GET"])
def list_risks():
    # 支持按风险等级、最低分值和分页参数筛选风险列表。
    risk_level = request.args.get("risk_level", "").strip() or None
    min_score = request.args.get("min_score", type=int)
    page = request.args.get("page", default=1, type=int)
    per_page = min(request.args.get("per_page", default=20, type=int), 100)

    try:
        return jsonify(get_risk_list(risk_level, min_score, page, per_page)), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("List risks failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@risk_bp.route("/dashboard/stats", methods=["GET"])
def dashboard_stats():
    try:
        # 返回首页统计卡片和图表所需的聚合数据。
        return jsonify(get_dashboard_stats()), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Dashboard stats failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
