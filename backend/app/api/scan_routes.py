# 文件作用：提供资产发现扫描接口，负责接收扫描请求、调用多源扫描流程并保存有效资产。
"""Scan-related API routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from backend.app.api.common import apply_lab_scan_defaults, logger
from backend.app.services.scan_service import persist_scan_result, run_multi_source_scan, upsert_asset

scan_bp = Blueprint("scan_api", __name__)


@scan_bp.route("/scan", methods=["POST"])
def scan():
    """Start a multi-source asset discovery scan."""
    # 从前端请求体中读取扫描参数，silent=True 可以避免非法 JSON 直接抛异常。
    body = request.get_json(silent=True) or {}
    # 对靶场环境补充默认扫描参数，例如 DNS、端口、被动情报地址等。
    body = apply_lab_scan_defaults(body)
    # domain 是扫描入口，mode 用于决定执行主动、被动还是混合扫描。
    domain = (body.get("domain") or "").strip().lower()
    mode = str(body.get("mode") or "hybrid").strip().lower()
    if not domain:
        return jsonify({"error": "missing required parameter 'domain'"}), 400

    logger.info("Received discovery scan request: domain=%s mode=%s", domain, mode)

    try:
        # 调用服务层执行完整多源扫描，接口层不直接处理扫描细节。
        scan_result = run_multi_source_scan(body)
    except ValueError as exc:
        # 参数错误返回 400，便于前端给出可读提示。
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        # 未预期异常记录日志并返回 500，避免后端堆栈直接暴露给前端。
        logger.error("Discovery scan failed: %s", exc)
        return jsonify({"error": f"discovery scan failed: {exc}"}), 500

    # target_details 是融合后的目标视图，probe_results 是验证后可展示/可入库结果。
    target_details = scan_result.get("target_details", [])
    probe_results = scan_result.get("results", [])
    saved = 0
    persistence_result = {"run_id": None, "discovery_records_saved": 0, "validation_records_saved": 0}

    try:
        # 保存扫描过程数据，包括扫描任务、发现阶段记录和验证阶段记录。
        persistence_result = persist_scan_result(body, scan_result)
    except Exception as exc:  # noqa: BLE001
        # 过程记录保存失败不阻断资产入库，但需要写日志便于排查。
        logger.error("Scan persistence failed [domain=%s mode=%s]: %s", domain, mode, exc)

    for result in probe_results:
        # 双重兜底：没有返回状态码的目标不作为有效资产写入 asset 表。
        if result.get("status_code") is None:
            continue
        try:
            upsert_asset(
                domain=result["subdomain"],
                ip=result["ip"],
                port=result["port"],
                status_code=result["status_code"],
                title=result["title"],
                server=result["server"],
            )
            saved += 1
        except Exception as exc:  # noqa: BLE001
            # 单个资产入库失败不影响其他资产，保证扫描结果尽量完整保存。
            logger.error(
                "Asset persistence failed [%s/%s:%d]: %s",
                result["subdomain"],
                result["ip"],
                result["port"],
                exc,
            )

    logger.info(
        "Scan finished: domain=%s mode=%s targets=%d probes=%d saved=%d",
        domain,
        scan_result.get("mode", mode),
        len(target_details),
        len(probe_results),
        saved,
    )

    return jsonify(
        {
            # 以下字段供前端展示本次扫描概况、来源统计和详细结果。
            "domain": domain,
            "mode": scan_result.get("mode", mode),
            "run_id": persistence_result["run_id"],
            "subdomains_found": len(target_details),
            "probes_total": len(probe_results),
            "saved": saved,
            "discovery_records_saved": persistence_result["discovery_records_saved"],
            "validation_records_saved": persistence_result["validation_records_saved"],
            "results": probe_results,
            "validated_results": scan_result.get("validated_results", probe_results),
            "discovery_summary": scan_result.get("discovery_summary", {}),
            "passive_summary": scan_result.get("passive_summary", {}),
            "active_summary": scan_result.get("active_summary", {}),
            "validation_summary": scan_result.get("validation_summary", {}),
            "passive_target_details": scan_result.get("passive_target_details", []),
            "active_target_details": scan_result.get("active_target_details", []),
            "target_details": target_details,
        }
    )
