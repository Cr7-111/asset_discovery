# 实现资产分析业务，完成资产类型识别、标签生成和分析结果保存。
"""Rule-based asset analysis service.

The previous local classifier is disabled. Asset analysis now uses the rule
engine only: first generate rule tags, then infer asset type from those tags,
and finally persist rule-derived analysis results.
"""

import logging
from typing import Optional

from backend.app.core.db import (
    delete_tags_by_asset,
    fetch_all_assets,
    fetch_analysis,
    fetch_asset_by_id,
    fetch_tags_by_asset,
    upsert_analysis,
    upsert_tags_batch,
)
from backend.app.rules.tag_rules import RuleMatchResult, match_rules

logger = logging.getLogger(__name__)


TAG_TYPE_PRIORITY = [
    # 标签到资产类型的优先级映射。前面的标签风险和指向性更强，会优先决定资产类型。
    ("database_exposed", "database_service"),
    ("middleware_exposed", "middleware_service"),
    ("api_service", "api_service"),
    ("api_docs_exposed", "api_service"),
    ("admin_panel", "admin_panel"),
    ("dev_env", "dev_test_system"),
    ("test_env", "dev_test_system"),
    ("login_page", "web_site"),
]


def analyze_asset(asset_id: int) -> dict:
    """Analyze one asset with rule tags and rule-derived asset type."""
    try:
        # 根据资产编号读取基础信息，后续规则匹配依赖域名、标题、Server 和端口。
        asset = fetch_asset_by_id(asset_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("read asset failed [asset_id=%d]: %s", asset_id, exc)
        return _error_result(asset_id, f"read asset failed: {exc}")

    if asset is None:
        return _error_result(asset_id, "asset not found")

    # 对数据库字段做安全转换，避免空值或异常类型影响规则判断。
    domain = _safe_str(asset.get("domain"))
    title = _safe_str(asset.get("title"))
    server = _safe_str(asset.get("server"))
    port = _safe_int(asset.get("port"))

    logger.info("start rule analysis [asset_id=%d domain=%s]", asset_id, domain or "-")

    # 先执行标签规则匹配，再根据标签推断资产类型。
    rule_result = _run_rule_match(asset_id, domain, title, server, port)
    inferred_type, type_confidence = _infer_asset_type(rule_result.tags)

    try:
        # 保存资产分析主结果，包括资产类型和置信度。
        upsert_analysis(
            asset_id=asset_id,
            asset_type=inferred_type,
            confidence=type_confidence,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("write asset_analysis failed [asset_id=%d]: %s", asset_id, exc)

    # 将规则命中的标签转换为数据库可保存的字典结构。
    tags_to_save = [
        {
            "asset_id": asset_id,
            "tag_name": tag.tag_name,
            "tag_source": "rule_engine",
            "confidence": tag.confidence,
            "matched_rule": tag.matched_rule,
        }
        for tag in rule_result.tags
    ]

    try:
        # 每次重新分析前先删除旧标签，避免同一资产重复累积过期标签。
        delete_tags_by_asset(asset_id)
        if tags_to_save:
            upsert_tags_batch(tags_to_save)
        logger.info("asset tags saved [asset_id=%d count=%d]", asset_id, len(tags_to_save))
    except Exception as exc:  # noqa: BLE001
        logger.error("write asset_tag failed [asset_id=%d]: %s", asset_id, exc)

    return {
        # 返回结构化结果，供接口层直接返回给前端。
        "asset_id": asset_id,
        "domain": domain,
        "asset_type": inferred_type,
        "confidence": type_confidence,
        "all_probs": {},
        "tags": tags_to_save,
        "tag_count": len(tags_to_save),
        "status": "ok",
    }


def analyze_all_assets() -> dict:
    """Run rule analysis for every asset without stopping on single failures."""
    try:
        # 批量分析以当前资产表为准，只处理已经验证入库的有效资产。
        assets = fetch_all_assets()
    except Exception as exc:  # noqa: BLE001
        logger.error("batch analysis failed to read assets: %s", exc)
        return {"total": 0, "success": 0, "failed": 0, "results": [], "error": str(exc)}

    total = len(assets)
    success = 0
    failed = 0
    results = []

    logger.info("start batch rule analysis, total=%d", total)

    for index, asset in enumerate(assets, 1):
        asset_id = asset.get("asset_id")
        if not asset_id:
            failed += 1
            continue
        try:
            # 复用单资产分析逻辑，保证批量分析和手动分析结果一致。
            result = analyze_asset(int(asset_id))
            results.append(
                {
                    "asset_id": result["asset_id"],
                    "domain": result.get("domain"),
                    "asset_type": result["asset_type"],
                    "confidence": result["confidence"],
                    "tag_count": result["tag_count"],
                    "status": result["status"],
                }
            )
            if result["status"] == "ok":
                success += 1
            else:
                failed += 1
            if index % 10 == 0:
                logger.info("batch rule analysis progress: %d/%d", index, total)
        except Exception as exc:  # noqa: BLE001
            logger.error("batch rule analysis error [asset_id=%s]: %s", asset_id, exc)
            failed += 1
            results.append({"asset_id": asset_id, "status": "error", "error": str(exc)})

    logger.info("batch rule analysis completed: total=%d success=%d failed=%d", total, success, failed)
    return {"total": total, "success": success, "failed": failed, "results": results}


def get_asset_analysis(asset_id: int) -> dict | None:
    """Fetch analysis result for one asset."""
    try:
        return fetch_analysis(asset_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("get_asset_analysis failed [asset_id=%d]: %s", asset_id, exc)
        return None


def get_asset_tags(asset_id: int) -> list[dict]:
    """Fetch all tags for one asset."""
    try:
        return fetch_tags_by_asset(asset_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("get_asset_tags failed [asset_id=%d]: %s", asset_id, exc)
        return []


def _run_rule_match(asset_id, domain, title, server, port) -> RuleMatchResult:
    """Run the rule engine safely."""
    try:
        # 规则引擎只依赖资产指纹，不访问外部服务，保证分析结果稳定可复现。
        return match_rules(
            asset_id=asset_id,
            domain=domain,
            title=title,
            server=server,
            port=port,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("rule match failed [asset_id=%d]: %s", asset_id, exc)
        return RuleMatchResult(asset_id=asset_id)


def _infer_asset_type(tags) -> tuple[str, float]:
    """Infer asset type from rule tags."""
    # 将命中的标签集合化，便于按优先级快速判断资产类型。
    tag_names = {tag.tag_name for tag in tags}
    for tag_name, asset_type in TAG_TYPE_PRIORITY:
        if tag_name in tag_names:
            return asset_type, 1.0
    return "unknown", 0.0


def _safe_str(value) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _safe_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _error_result(asset_id: int, message: str) -> dict:
    logger.warning("asset analysis failed [asset_id=%d]: %s", asset_id, message)
    return {
        "asset_id": asset_id,
        "asset_type": "unknown",
        "confidence": 0.0,
        "tags": [],
        "tag_count": 0,
        "status": "error",
        "error": message,
    }
