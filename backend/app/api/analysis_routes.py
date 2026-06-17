# 文件作用：提供资产规则分析、资产标签查询和批量分析接口。
"""Rule analysis and tag query routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from backend.app.api.common import logger
from backend.app.services.analysis_service import analyze_all_assets, analyze_asset, get_asset_analysis, get_asset_tags

analysis_bp = Blueprint("analysis_api", __name__)


@analysis_bp.route("/analyze/<int:asset_id>", methods=["POST"])
def analyze_one(asset_id: int):
    logger.info("Received analysis request: asset_id=%d", asset_id)
    try:
        # 对单个资产执行规则分析，生成资产类型、薄弱点和标签等结果。
        result = analyze_asset(asset_id)
        status_code = 200 if result.get("status") == "ok" else 422
        return jsonify(result), status_code
    except Exception as exc:  # noqa: BLE001
        logger.error("Analyze asset failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc), "asset_id": asset_id}), 500


@analysis_bp.route("/analyze/all", methods=["POST"])
def analyze_all():
    logger.info("Received analyze-all request")
    try:
        # 批量分析所有资产，单个资产失败不会中断整体任务。
        return jsonify(analyze_all_assets()), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Analyze all failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@analysis_bp.route("/assets/<int:asset_id>/analysis", methods=["GET"])
def get_analysis(asset_id: int):
    try:
        # 查询指定资产最近一次规则分析结果。
        analysis = get_asset_analysis(asset_id)
        if analysis is None:
            return jsonify(
                {
                    "message": "analysis not found, call POST /api/analyze/<asset_id> first",
                    "asset_id": asset_id,
                }
            ), 404
        return jsonify(analysis), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Get analysis failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc)}), 500


@analysis_bp.route("/assets/<int:asset_id>/tags", methods=["GET"])
def get_tags(asset_id: int):
    # source 参数用于按标签来源过滤，例如 rule_engine。
    source_filter = request.args.get("source", "").strip()
    try:
        tags = get_asset_tags(asset_id)
        if source_filter:
            tags = [tag for tag in tags if tag.get("tag_source") == source_filter]
        return jsonify({"asset_id": asset_id, "total": len(tags), "tags": tags}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Get tags failed [asset_id=%d]: %s", asset_id, exc)
        return jsonify({"error": str(exc)}), 500
