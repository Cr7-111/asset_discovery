# 封装风险评估业务流程，负责读取资产和标签、调用评分规则并保存风险结果。
"""Risk assessment service based on deterministic rule scoring."""

import json
import logging

from backend.app.core.db import (
    fetch_all_assets,
    fetch_all_risks,
    fetch_asset_by_id,
    fetch_risk_by_asset,
    fetch_risk_stats,
    fetch_tags_by_asset,
    upsert_risk,
)
from backend.app.rules.risk_engine import calc_risk_score

logger = logging.getLogger(__name__)


def _build_asset_data(asset: dict, tags: list[dict]) -> dict:
    """Merge asset fields and tags into the input format used by risk_engine."""
    # risk_engine 只关心结构化资产画像，这里统一整理输入字段。
    return {
        "asset_id": asset.get("asset_id"),
        "domain": asset.get("domain"),
        "ip": asset.get("ip"),
        "port": asset.get("port"),
        "status_code": asset.get("status_code"),
        "title": asset.get("title"),
        "server": asset.get("server"),
        "tags": tags,
    }


def assess_asset(asset_id: int) -> dict:
    """Assess one asset using rule scoring only."""
    try:
        # 先读取资产基础信息，风险评估必须基于已入库资产执行。
        asset = fetch_asset_by_id(asset_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("risk assessment failed to read asset [asset_id=%d]: %s", asset_id, exc)
        return _err(asset_id, f"read asset failed: {exc}")

    if asset is None:
        return _err(asset_id, "asset not found")

    try:
        # 标签来自资产分析模块，可作为风险规则的重要补充依据。
        tags = fetch_tags_by_asset(asset_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("read tags failed, fallback to empty tags [asset_id=%d]: %s", asset_id, exc)
        tags = []

    asset_data = _build_asset_data(asset, tags)

    try:
        # 调用确定性规则引擎计算风险分值、等级、命中明细和整改建议。
        score_result = calc_risk_score(asset_data)
    except Exception as exc:  # noqa: BLE001
        logger.error("rule score failed [asset_id=%d]: %s", asset_id, exc)
        return _err(asset_id, f"rule score failed: {exc}")

    score_detail_json = json.dumps(score_result["score_detail"], ensure_ascii=False)
    suggestions_text = "\n".join(score_result["suggestions"])

    try:
        # 将风险结果写入数据库，资产详情页和风险列表可直接读取。
        upsert_risk(
            asset_id=asset_id,
            risk_score=score_result["risk_score"],
            risk_level=score_result["risk_level"],
            score_detail=score_detail_json,
            suggestions=suggestions_text,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("write risk_result failed [asset_id=%d]: %s", asset_id, exc)

    return {
        "asset_id": asset_id,
        "domain": asset.get("domain"),
        "risk_score": score_result["risk_score"],
        "risk_level": score_result["risk_level"],
        "score_detail": score_result["score_detail"],
        "suggestions": score_result["suggestions"],
        "status": "ok",
    }


def assess_all_assets() -> dict:
    """Assess all assets without stopping on single failures."""
    try:
        # 批量评估以资产基础表为入口。
        assets = fetch_all_assets()
    except Exception as exc:  # noqa: BLE001
        logger.error("batch risk assessment failed to read assets: %s", exc)
        return {"total": 0, "success": 0, "failed": 0, "results": [], "error": str(exc)}

    total = len(assets)
    success = 0
    failed = 0
    results = []

    logger.info("start batch rule risk assessment, total=%d", total)

    for index, asset in enumerate(assets, 1):
        asset_id = asset.get("asset_id")
        if not asset_id:
            failed += 1
            continue
        try:
            # 复用单资产评估逻辑，保证批量和单次结果一致。
            result = assess_asset(int(asset_id))
            results.append(
                {
                    "asset_id": result["asset_id"],
                    "domain": result.get("domain"),
                    "risk_score": result["risk_score"],
                    "risk_level": result["risk_level"],
                    "status": result["status"],
                }
            )
            if result["status"] == "ok":
                success += 1
            else:
                failed += 1
        except Exception as exc:  # noqa: BLE001
            logger.error("batch risk assessment error [asset_id=%s]: %s", asset_id, exc)
            failed += 1
            results.append({"asset_id": asset_id, "status": "error", "error": str(exc)})

        if index % 20 == 0:
            logger.info("batch rule risk assessment progress: %d/%d", index, total)

    logger.info("batch rule risk assessment completed: total=%d success=%d failed=%d", total, success, failed)
    return {"total": total, "success": success, "failed": failed, "results": results}


def get_risk_detail(asset_id: int) -> dict | None:
    """Fetch one risk result and parse score_detail JSON when possible."""
    try:
        row = fetch_risk_by_asset(asset_id)
        if row and row.get("score_detail"):
            try:
                # score_detail 入库时是 JSON 字符串，返回前转换为数组便于前端展示。
                row["score_detail"] = json.loads(row["score_detail"])
            except Exception:  # noqa: BLE001
                pass
        return row
    except Exception as exc:  # noqa: BLE001
        logger.error("get_risk_detail failed [asset_id=%d]: %s", asset_id, exc)
        return None


def get_risk_list(risk_level=None, min_score=None, page=1, per_page=20) -> dict:
    """Fetch paginated risk results."""
    try:
        # 风险列表支持等级、分值和分页筛选。
        result = fetch_all_risks(risk_level, min_score, page, per_page)
        for item in result.get("items", []):
            if item.get("score_detail"):
                try:
                    item["score_detail"] = json.loads(item["score_detail"])
                except Exception:  # noqa: BLE001
                    pass
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("get_risk_list failed: %s", exc)
        return {"total": 0, "page": page, "per_page": per_page, "items": []}


def get_dashboard_stats() -> dict:
    """Fetch dashboard statistics."""
    try:
        # 仪表盘统计由数据库聚合获得。
        return fetch_risk_stats()
    except Exception as exc:  # noqa: BLE001
        logger.error("get_dashboard_stats failed: %s", exc)
        return {
            "total_assets": 0,
            "assessed_assets": 0,
            "avg_score": 0,
            "level_counts": {},
            "type_counts": {},
        }


def _err(asset_id: int, message: str) -> dict:
    # 统一错误返回结构，避免前端需要处理多种失败格式。
    logger.warning("risk assessment failed [asset_id=%d]: %s", asset_id, message)
    return {
        "asset_id": asset_id,
        "risk_score": 0,
        "risk_level": "unknown",
        "score_detail": [],
        "suggestions": [],
        "status": "error",
        "error": message,
    }
