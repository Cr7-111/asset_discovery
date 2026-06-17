# 编排资产发现流程，统一调度被动发现、主动发现、验证融合和结果汇总。
"""Multi-source asset discovery orchestration entrypoints."""

from __future__ import annotations

import requests

from backend.app.models.discovery_models import TargetRecord
from backend.app.services.discovery.probe import probe_targets
from backend.app.services.discovery.subdomain import discover_subdomains_list

from .active import run_active_discovery_stage
from .passive import run_passive_discovery_stage
from .shared import VALID_SCAN_MODES, build_source_stats, normalize_domain, snapshot_targets
from .validation import run_validation_and_fusion_stage


def run_passive_discovery(body: dict) -> dict[str, TargetRecord]:
    # 被动发现入口：统一做域名规范化，避免子流程重复处理空域名。
    domain = normalize_domain(body.get("domain") or "")
    if not domain:
        raise ValueError("missing required parameter 'domain'")

    # request_get_fn 以依赖注入方式传入，便于测试时替换网络请求。
    return run_passive_discovery_stage(
        body,
        domain=domain,
        request_get_fn=requests.get,
    )


def run_active_discovery(body: dict) -> dict[str, TargetRecord]:
    # 主动发现入口：根据目标域名执行 DNS 枚举、爬取和证书扩展等逻辑。
    domain = normalize_domain(body.get("domain") or "")
    if not domain:
        raise ValueError("missing required parameter 'domain'")

    return run_active_discovery_stage(
        body,
        domain=domain,
        # 子域名枚举函数也通过参数注入，便于单元测试和扩展字典来源。
        enumerate_subdomains_fn=discover_subdomains_list,
    )


def run_validation_and_fusion(
    body: dict,
    passive_targets: dict[str, TargetRecord] | None = None,
    active_targets: dict[str, TargetRecord] | None = None,
) -> dict:
    # 验证融合阶段要求已知扫描主域名，用于爬取和证书解析中的范围控制。
    domain = normalize_domain(body.get("domain") or "")
    if not domain:
        raise ValueError("missing required parameter 'domain'")

    return run_validation_and_fusion_stage(
        body,
        domain=domain,
        passive_targets=passive_targets,
        active_targets=active_targets,
        probe_fn=probe_targets,
        request_get_fn=requests.get,
    )


def run_multi_source_scan(body: dict) -> dict:
    # 1. 规范化目标域名，并校验扫描模式是否合法。
    domain = normalize_domain(body.get("domain") or "")
    if not domain:
        raise ValueError("missing required parameter 'domain'")

    mode = str(body.get("mode") or "hybrid").strip().lower()
    if mode not in VALID_SCAN_MODES:
        raise ValueError(f"unsupported scan mode: {mode}")

    # 2. 根据扫描模式分别执行被动发现、主动发现或混合发现。
    # passive 模式只依赖情报线索，active 模式只做主动枚举，hybrid 会同时启用两类来源。
    passive_targets = run_passive_discovery(body) if mode in {"passive", "hybrid"} else {}
    active_targets = run_active_discovery(body) if mode in {"active", "hybrid"} else {}
    # 3. 融合多源发现结果，并对目标进行可访问性验证。
    # validation 内部会合并同名目标的来源、URL、证书和日志线索。
    validation = run_validation_and_fusion(body, passive_targets=passive_targets, active_targets=active_targets)
    targets = validation["targets"]

    # 4. 汇总扫描结果，返回给接口层用于入库和前端展示。
    return {
        "domain": domain,
        "mode": mode,
        "targets": targets,
        "subdomains_found": len(targets),
        "probes_total": len(validation["results"]),
        "results": validation["results"],
        "validated_results": validation["results"],
        "discovery_summary": {
            "source_stats": build_source_stats(targets),
            "enriched_targets": validation["validation_summary"]["enriched_targets"],
            "targets_with_ip": sum(1 for item in targets.values() if item.ips),
            "mode": mode,
            "passive_targets": len(passive_targets),
            "active_targets": len(active_targets),
        },
        "passive_summary": {
            "targets_found": len(passive_targets),
            "source_stats": build_source_stats(passive_targets),
        },
        "active_summary": {
            "targets_found": len(active_targets),
            "source_stats": build_source_stats(active_targets),
        },
        "validation_summary": validation["validation_summary"],
        "passive_target_details": snapshot_targets(passive_targets),
        "active_target_details": snapshot_targets(active_targets),
        "target_details": snapshot_targets(targets),
    }
