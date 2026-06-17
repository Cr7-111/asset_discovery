# 资产发现公共工具模块，提供域名规范化、目标合并、请求覆盖和来源统计等通用能力。
"""Shared helpers used by passive, active, and validation discovery stages."""

from __future__ import annotations

import logging
import re
from copy import deepcopy
from typing import Callable, Iterable
from urllib.parse import urlparse, urlunparse

import requests

from backend.app.models.discovery_models import TargetRecord
from backend.app.services.discovery.subdomain import resolve_a_records

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    # 多个被动/主动采集函数共用请求头，模拟浏览器访问并提升兼容性。
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

DEFAULT_SEARCH_QUERIES = [
    # 默认搜索语句用于模拟搜索引擎资产发现。
    "site:{domain}",
    "site:*.{domain}",
    'site:{domain} "swagger"',
    'site:{domain} "api"',
    'site:{domain} "login"',
]
DEFAULT_PASSIVE_DNS_API_TEMPLATE = "https://api.hackertarget.com/hostsearch/?q={domain}"
VALID_SCAN_MODES = {"passive", "active", "hybrid"}

JS_ENDPOINT_RE = re.compile(
    # 匹配完整 URL、常见 API 路径以及包含 api/graphql/swagger/openapi 的路径。
    r"""
    (?:
        https?://[A-Za-z0-9._:-]+(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?
        |
        /(?:api|rest|graphql|swagger|openapi|v[0-9]+)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*
        |
        /[A-Za-z0-9._/-]+(?:api|graphql|swagger|openapi)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def normalize_domain(target: str) -> str:
    # 支持传入裸域名或 URL，统一提取 hostname 并转为小写。
    raw = (target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    hostname = (parsed.hostname or raw).strip().lower().rstrip(".")
    return hostname


def same_scope(hostname: str, root_domain: str) -> bool:
    # 限制发现范围，只有根域名本身或其子域名才被认为属于同一资产范围。
    hostname = (hostname or "").lower().rstrip(".")
    root_domain = (root_domain or "").lower().rstrip(".")
    return bool(hostname) and (hostname == root_domain or hostname.endswith(f".{root_domain}"))


def safe_get_json(response: requests.Response) -> object | None:
    # 外部接口返回不一定是合法 JSON，解析失败时返回 None 而不是抛异常。
    try:
        return response.json()
    except ValueError:
        return None


def connect_overrides(body: dict) -> dict[str, str]:
    # connect_overrides 用于靶场 host 模式：访问域名时实际连接到指定 IP。
    overrides = body.get("connect_overrides") or {}
    normalized: dict[str, str] = {}
    if isinstance(overrides, dict):
        for hostname, ip in overrides.items():
            key = normalize_domain(str(hostname))
            value = str(ip or "").strip()
            if key and value:
                normalized[key] = value
    return normalized


def build_request_target(url: str, connect_override_map: dict[str, str]) -> tuple[str, dict]:
    # 如果当前 URL 命中连接覆盖，则将连接目标改为 IP，同时保留 Host 头。
    parsed = urlparse(url)
    hostname = normalize_domain(parsed.hostname or "")
    override_ip = connect_override_map.get(hostname)
    if not override_ip or not hostname:
        return url, DEFAULT_HEADERS

    netloc = override_ip if not parsed.port else f"{override_ip}:{parsed.port}"
    target_url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    headers = {**DEFAULT_HEADERS, "Host": hostname}
    return target_url, headers


def request_get(
    url: str,
    *,
    timeout: tuple[int, int],
    connect_override_map: dict[str, str],
    request_get_fn: Callable[..., requests.Response],
) -> requests.Response:
    # 统一封装 GET 请求，所有调用点都自动支持连接覆盖和默认请求头。
    target_url, headers = build_request_target(url, connect_override_map)
    return request_get_fn(
        target_url,
        headers=headers,
        timeout=timeout,
        verify=False,
        allow_redirects=True,
    )


def snapshot_targets(targets: dict[str, TargetRecord]) -> list[dict]:
    # 将 TargetRecord 转成可 JSON 序列化的字典列表，并按子域名排序方便展示。
    return [item.to_public_dict() for item in sorted(targets.values(), key=lambda value: value.subdomain)]


def merge_target(
    targets: dict[str, TargetRecord],
    hostname: str,
    *,
    ips: Iterable[str] | None = None,
    source: str,
    evidence: str = "",
    url: str = "",
    js_endpoints: Iterable[str] | None = None,
) -> TargetRecord | None:
    # 合并单个目标：如果目标已存在，则追加来源、IP、URL、JS 端点等信息。
    hostname = normalize_domain(hostname)
    if not hostname:
        return None

    item = targets.setdefault(hostname, TargetRecord(subdomain=hostname))
    # add_discovery 会更新来源集合、证据列表和置信度。
    item.add_discovery(source=source, evidence=evidence)

    for ip in ips or []:
        if ip:
            item.ips.add(str(ip))
    if url:
        item.urls.add(url)
    for endpoint in js_endpoints or []:
        if endpoint:
            item.js_endpoints.add(endpoint)
    return item


def merge_targets(targets: dict[str, TargetRecord], incoming: dict[str, TargetRecord]) -> None:
    # 合并两个来源集合，用于把主动发现和被动发现结果汇总到统一目标表。
    for hostname, record in incoming.items():
        target = targets.setdefault(hostname, deepcopy(record))
        if target is not record:
            for source in sorted(record.sources):
                target.add_discovery(source)
            for ip in record.ips:
                target.ips.add(ip)
            for url in record.urls:
                target.urls.add(url)
            for evidence in record.evidences:
                if evidence not in target.evidences:
                    target.evidences.append(evidence)
            for endpoint in record.js_endpoints:
                target.js_endpoints.add(endpoint)
            if record.cert_subject:
                # 证书字段属于富化信息，只有 incoming 中存在时才覆盖。
                target.cert_subject = record.cert_subject
            if record.cert_issuer:
                target.cert_issuer = record.cert_issuer
            target.cert_sans.update(record.cert_sans)
            target.first_seen = min(target.first_seen, record.first_seen)
            target.last_seen = max(target.last_seen, record.last_seen)
            target.confidence_score = max(target.confidence_score, record.confidence_score)
            if target.validation_status == "discovered":
                target.validation_status = record.validation_status


def resolve_hostname_if_needed(
    hostname: str,
    target: TargetRecord,
    *,
    nameservers: list[str] | None,
    timeout: float,
) -> None:
    # 已有 IP 的目标直接标记为 resolved，避免重复 DNS 请求。
    if target.ips:
        target.mark_resolved()
        return
    try:
        resolved = resolve_a_records(hostname, nameservers=nameservers, timeout=timeout)
        if resolved:
            target.ips.update(resolved)
            target.mark_resolved()
    except Exception as exc:  # noqa: BLE001
        logger.debug("resolve fused target failed [%s]: %s", hostname, exc)


def fetch_url_text(
    url: str,
    timeout: tuple[int, int],
    *,
    connect_override_map: dict[str, str],
    request_get_fn: Callable[..., requests.Response],
) -> str:
    # 获取网页或 JS 文本内容，供爬取和 JS 提取阶段复用。
    resp = request_get(
        url,
        timeout=timeout,
        connect_override_map=connect_override_map,
        request_get_fn=request_get_fn,
    )
    resp.raise_for_status()
    return resp.text


def build_source_stats(targets: dict[str, TargetRecord]) -> dict[str, int]:
    # 统计每种发现来源命中的目标数量，用于前端来源标签和扫描统计。
    stats: dict[str, int] = {}
    for item in targets.values():
        for source in item.sources:
            stats[source] = stats.get(source, 0) + 1
    return dict(sorted(stats.items(), key=lambda kv: kv[0]))
