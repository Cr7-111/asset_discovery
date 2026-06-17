# 被动发现采集器，整合 CT 日志、被动 DNS、搜索结果、流量日志、备案和云资产线索。
"""Passive discovery collectors (CT logs, passive DNS, traffic, search, ICP, cloud)."""

from __future__ import annotations

import logging
from typing import Callable
from urllib.parse import quote, urlparse

import requests
from bs4 import BeautifulSoup

from backend.app.models.discovery_models import TargetRecord
from backend.app.services.discovery.traffic import discover_from_traffic_data

from .shared import (
    DEFAULT_HEADERS,
    DEFAULT_PASSIVE_DNS_API_TEMPLATE,
    DEFAULT_SEARCH_QUERIES,
    connect_overrides,
    merge_target,
    normalize_domain,
    request_get,
    resolve_hostname_if_needed,
    safe_get_json,
    same_scope,
)

logger = logging.getLogger(__name__)


def ingest_record_list(
    records: list,
    targets: dict[str, TargetRecord],
    *,
    source: str,
    domain: str,
) -> int:
    # 通用记录导入函数，兼容字符串列表和字典列表两种输入格式。
    count_before = len(targets)
    for row in records:
        if isinstance(row, str):
            # 简单字符串记录直接按域名处理。
            hostname = normalize_domain(row)
            if same_scope(hostname, domain):
                merge_target(targets, hostname, source=source, evidence=f"{source}: {hostname}")
            continue

        if not isinstance(row, dict):
            continue

        hostname = normalize_domain(
            # 不同数据源字段命名不同，这里按常见字段顺序提取主机名。
            row.get("hostname") or row.get("domain") or row.get("subdomain") or row.get("host") or ""
        )
        if not same_scope(hostname, domain):
            continue
        ips = row.get("ips") or ([row["ip"]] if row.get("ip") else [])
        url = str(row.get("url") or "").strip()
        merge_target(
            targets,
            hostname,
            ips=ips,
            source=source,
            evidence=f"{source}: {hostname}",
            url=url,
        )
    return len(targets) - count_before


def discover_from_ct_log(
    domain: str,
    targets: dict[str, TargetRecord],
    *,
    nameservers: list[str] | None,
    dns_timeout: float,
    http_timeout: tuple[int, int],
    request_get_fn: Callable[..., requests.Response],
) -> int:
    # CT 日志来源于证书透明度数据，适合发现 HTTPS 证书中出现过的子域名。
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    count_before = len(targets)
    try:
        resp = request_get_fn(url, headers=DEFAULT_HEADERS, timeout=http_timeout, verify=False)
        resp.raise_for_status()
        rows = safe_get_json(resp)
        if not isinstance(rows, list):
            return 0

        for row in rows:
            if not isinstance(row, dict):
                continue
            name_value = str(row.get("name_value") or "").strip()
            if not name_value:
                continue
            for name in name_value.splitlines():
                # CT 记录可能包含通配符域名，统一去掉 *. 后再进入同域判断。
                hostname = name.strip().lstrip("*.").lower()
                if not same_scope(hostname, domain):
                    continue
                record = merge_target(
                    targets,
                    hostname,
                    source="ct_log",
                    evidence=f"crt.sh certificate entry: {hostname}",
                )
                if record:
                    resolve_hostname_if_needed(hostname, record, nameservers=nameservers, timeout=dns_timeout)
    except Exception as exc:  # noqa: BLE001
        logger.warning("collect ct logs failed (degraded): %s", exc)
    return len(targets) - count_before


def discover_from_passive_dns(
    body: dict,
    domain: str,
    targets: dict[str, TargetRecord],
    *,
    http_timeout: tuple[int, int],
    request_get_fn: Callable[..., requests.Response],
) -> int:
    # 优先使用请求体中注入的被动 DNS 记录，便于靶场和单元测试复现。
    injected = body.get("passive_dns_records") or []
    added = ingest_record_list(injected, targets, source="passive_dns", domain=domain)
    if added:
        return added

    api_url = body.get("passive_dns_api_url") or DEFAULT_PASSIVE_DNS_API_TEMPLATE
    if not api_url:
        return 0

    try:
        resp = request_get(
            api_url.format(domain=quote(domain)),
            timeout=http_timeout,
            connect_override_map=connect_overrides(body),
            request_get_fn=request_get_fn,
        )
        resp.raise_for_status()
        content_type = (resp.headers.get("Content-Type") or "").lower()

        if "json" in content_type:
            # JSON 返回可能是列表，也可能包在 records/data 字段中。
            rows = safe_get_json(resp)
            if isinstance(rows, dict):
                rows = rows.get("records") or rows.get("data") or []
            if not isinstance(rows, list):
                return 0
            return ingest_record_list(rows, targets, source="passive_dns", domain=domain)

        text = resp.text.strip()
        if not text:
            return 0
        if "api count exceeded" in text.lower() or "error" in text.lower():
            logger.warning("public passive dns api returned rate limit or error: %s", text[:120])
            return 0

        rows = []
        # 文本返回按 hostname,ip 解析，兼容 hackertarget hostsearch 格式。
        for line in text.splitlines():
            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 2:
                continue
            rows.append({"hostname": parts[0], "ip": parts[1]})
        return ingest_record_list(rows, targets, source="passive_dns", domain=domain)
    except Exception as exc:  # noqa: BLE001
        logger.warning("collect passive dns failed (degraded): %s", exc)
        return 0


def discover_from_traffic(body: dict, domain: str, targets: dict[str, TargetRecord]) -> int:
    # 从离线流量日志或结构化流量记录中提取同域名资产。
    count_before = len(targets)
    findings = discover_from_traffic_data(body, domain)
    for finding in findings:
        record = merge_target(
            targets,
            finding["hostname"],
            source="traffic_sniff",
            evidence=(finding.get("evidence") or ["traffic sniff discovery"])[0],
        )
        if record is None:
            continue
        for evidence in finding.get("evidence") or []:
            if evidence not in record.evidences:
                record.evidences.append(evidence)
        for url in finding.get("urls") or []:
            record.urls.add(url)
    return len(targets) - count_before


def discover_from_search(
    body: dict,
    domain: str,
    targets: dict[str, TargetRecord],
    *,
    http_timeout: tuple[int, int],
    request_get_fn: Callable[..., requests.Response],
) -> int:
    # 搜索来源既支持注入模拟结果，也支持访问搜索页面解析 a[href]。
    injected = body.get("search_results") or []
    added = ingest_record_list(injected, targets, source="search_engine", domain=domain)
    if added:
        return added

    queries = body.get("search_queries") or [q.format(domain=domain) for q in DEFAULT_SEARCH_QUERIES]
    search_template = body.get("search_engine_url_template") or ""
    if not search_template:
        return 0

    count_before = len(targets)
    for query in queries:
        try:
            # 靶场中 search_engine_url_template 指向本地伪搜索服务，避免依赖公网。
            resp = request_get(
                search_template.format(query=quote(query)),
                timeout=http_timeout,
                connect_override_map=connect_overrides(body),
                request_get_fn=request_get_fn,
            )
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            for node in soup.select("a[href]"):
                href = (node.get("href") or "").strip()
                if not href:
                    continue
                parsed = urlparse(href)
                hostname = normalize_domain(parsed.hostname or "")
                if not same_scope(hostname, domain):
                    continue
                merge_target(
                    targets,
                    hostname,
                    source="search_engine",
                    evidence=f"search query: {query}",
                    url=href,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("collect search results failed (query=%s, degraded): %s", query, exc)
    return len(targets) - count_before


def discover_from_icp(body: dict, domain: str, targets: dict[str, TargetRecord]) -> int:
    # ICP 备案数据作为可选被动来源，由请求体传入。
    return ingest_record_list(body.get("icp_records") or [], targets, source="icp_record", domain=domain)


def discover_from_cloud_assets(body: dict, domain: str, targets: dict[str, TargetRecord]) -> int:
    # 云资产数据作为可选扩展来源，支持域名资产和纯公网 IP 两类记录。
    rows = body.get("cloud_assets") or []
    count_before = len(targets)
    for row in rows:
        if not isinstance(row, dict):
            continue
        hostname = normalize_domain(row.get("domain") or row.get("hostname") or "")
        if hostname and same_scope(hostname, domain):
            merge_target(
                targets,
                hostname,
                ips=row.get("ips") or ([row["ip"]] if row.get("ip") else []),
                source="cloud_api",
                evidence=f"cloud asset: {row.get('provider', 'unknown')}",
                url=str(row.get("url") or "").strip(),
            )
            continue

        public_ip = str(row.get("ip") or "").strip()
        if public_ip:
            pseudo_host = normalize_domain(row.get("name") or f"cloud-{public_ip.replace('.', '-')}.{domain}")
            merge_target(
                targets,
                pseudo_host,
                ips=[public_ip],
                source="cloud_api",
                evidence=f"cloud asset ip: {public_ip}",
            )
    return len(targets) - count_before


def run_passive_discovery_stage(
    body: dict,
    *,
    domain: str,
    request_get_fn: Callable[..., requests.Response],
) -> dict[str, TargetRecord]:
    # 被动发现总入口，根据开关依次执行多个数据源采集。
    nameservers = body.get("nameservers")
    dns_timeout = float(body.get("dns_timeout", 3.0))
    http_timeout = tuple(body.get("http_timeout", [5, 10]))

    targets: dict[str, TargetRecord] = {}

    if body.get("enable_ct", True):
        # 证书透明度日志查询可能访问公网，因此靶场默认可以关闭。
        discover_from_ct_log(
            domain,
            targets,
            nameservers=nameservers,
            dns_timeout=dns_timeout,
            http_timeout=http_timeout,
            request_get_fn=request_get_fn,
        )
    if body.get("enable_passive_dns", True):
        # 被动 DNS 可来自公网 API，也可来自靶场内置情报服务。
        discover_from_passive_dns(
            body,
            domain,
            targets,
            http_timeout=http_timeout,
            request_get_fn=request_get_fn,
        )
    if body.get("enable_traffic_sniff", True):
        discover_from_traffic(body, domain, targets)
    if body.get("enable_search", True):
        discover_from_search(
            body,
            domain,
            targets,
            http_timeout=http_timeout,
            request_get_fn=request_get_fn,
        )
    if body.get("enable_icp", True):
        discover_from_icp(body, domain, targets)
    if body.get("enable_cloud", True):
        discover_from_cloud_assets(body, domain, targets)

    return targets
