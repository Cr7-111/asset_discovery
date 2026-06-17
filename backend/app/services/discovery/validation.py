# 执行资产验证与多源结果融合，过滤无效探测结果并生成前端展示数据。
"""Validation and fusion stage for multi-source discovery."""

from __future__ import annotations

from typing import Callable

import requests

from backend.app.models.discovery_models import TargetRecord

from .active import enrich_from_crawl_and_cert
from .shared import connect_overrides, merge_targets, resolve_hostname_if_needed


def build_validation_output(targets: dict[str, TargetRecord], probe_results: list) -> list[dict]:
    # 将 ProbeResult 对象转换为普通字典，方便 JSON 返回和数据库保存。
    output_records = []
    for pr in probe_results:
        # 未拿到 HTTP 状态码的探测结果不进入前端展示和后续入库流程。
        if pr.status_code is None:
            continue
        target = targets.get(pr.subdomain)
        # 这里补充来源、URL、JS 端点和证书信息，使前端能解释“资产从哪里来”。
        output_records.append(
            {
                "subdomain": pr.subdomain,
                "ip": pr.ip,
                "port": pr.port,
                "scheme": pr.scheme,
                "status_code": pr.status_code,
                "title": pr.title,
                "server": pr.server,
                "success": pr.success,
                "error": pr.error,
                "sources": sorted(target.sources) if target else [],
                "urls": sorted(target.urls)[:20] if target else [],
                "js_endpoints": sorted(target.js_endpoints)[:20] if target else [],
                "cert_subject": target.cert_subject if target else None,
                "cert_issuer": target.cert_issuer if target else None,
                "confidence_score": target.confidence_score if target else 0,
                "validation_status": target.validation_status if target else "unknown",
                "first_seen": target.first_seen if target else None,
                "last_seen": target.last_seen if target else None,
            }
        )
    return output_records


def run_validation_and_fusion_stage(
    body: dict,
    *,
    domain: str,
    passive_targets: dict[str, TargetRecord] | None,
    active_targets: dict[str, TargetRecord] | None,
    probe_fn: Callable[..., list],
    request_get_fn: Callable[..., requests.Response],
) -> dict:
    # 从扫描参数中读取 DNS、HTTP、证书校验和端口配置。
    nameservers = body.get("nameservers")
    dns_timeout = float(body.get("dns_timeout", 3.0))
    http_timeout = tuple(body.get("http_timeout", [5, 10]))
    verify_ssl = bool(body.get("verify_ssl", False))
    raw_ports = body.get("ports")
    ports = [tuple(port) for port in raw_ports] if raw_ports else None

    targets: dict[str, TargetRecord] = {}
    # 将被动发现和主动发现得到的目标合并到同一个字典中。
    # 同一子域名如果来自多个来源，会合并来源、证据和置信度。
    merge_targets(targets, passive_targets or {})
    merge_targets(targets, active_targets or {})

    for hostname, target in targets.items():
        # 验证前先尝试解析 IP；没有 IP 的目标只作为线索，不进入 HTTP 探测。
        resolve_hostname_if_needed(hostname, target, nameservers=nameservers, timeout=dns_timeout)

    # 只对已解析到 IP 的目标发起 HTTP/HTTPS 探测。
    probe_input = [{"subdomain": item.subdomain, "ips": sorted(item.ips)} for item in targets.values() if item.ips]
    probe_results = (
        probe_fn(
            targets=probe_input,
            ports=ports,
            timeout=http_timeout,
            verify_ssl=verify_ssl,
            connect_overrides=connect_overrides(body),
        )
        if probe_input
        else []
    )

    for result in probe_results:
        target = targets.get(result.subdomain)
        if target:
            # 根据探测是否成功更新目标验证状态，例如 alive 或 probed。
            target.mark_probed(bool(result.success))

    # 首轮探测成功后，继续从页面链接、JS 文件和证书 SAN 中补充新目标。
    added_after_enrich = enrich_from_crawl_and_cert(
        domain,
        targets,
        probe_results,
        body=body,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        http_timeout=http_timeout,
        request_get_fn=request_get_fn,
    )

    if added_after_enrich:
        new_probe_input = []
        # 记录已探测过的子域名/IP 组合，避免重复探测。
        known_pairs = {(pr.subdomain, pr.ip) for pr in probe_results}
        for hostname, item in targets.items():
            resolve_hostname_if_needed(hostname, item, nameservers=nameservers, timeout=dns_timeout)
            if not item.ips:
                continue
            missing_ips = [ip for ip in item.ips if (item.subdomain, ip) not in known_pairs]
            if missing_ips:
                new_probe_input.append({"subdomain": item.subdomain, "ips": missing_ips})

        if new_probe_input:
            # 对扩展阶段新增的目标再执行一次探测，使其也能进入验证结果。
            more_results = probe_fn(
                targets=new_probe_input,
                ports=ports,
                timeout=http_timeout,
                verify_ssl=verify_ssl,
                connect_overrides=connect_overrides(body),
            )
            for result in more_results:
                target = targets.get(result.subdomain)
                if target:
                    target.mark_probed(bool(result.success))
            probe_results.extend(more_results)

    output_records = build_validation_output(targets, probe_results)
    return {
        "targets": targets,
        "results": output_records,
        "validation_summary": {
            # summary 用于前端扫描统计卡片和论文截图中的数量说明。
            "resolved_targets": sum(1 for item in targets.values() if item.ips),
            "alive_results": sum(1 for item in probe_results if getattr(item, "success", False)),
            "probes_total": len(probe_results),
            "enriched_targets": added_after_enrich,
        },
    }
