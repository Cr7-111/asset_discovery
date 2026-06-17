# 主动发现与富化模块，负责 DNS 枚举、网页爬取、JS 端点提取和证书解析。
"""Active discovery and enrichment logic (DNS enum, crawl, JS, certificate)."""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Callable
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from backend.app.models.discovery_models import TargetRecord

from .shared import (
    JS_ENDPOINT_RE,
    connect_overrides,
    fetch_url_text,
    merge_target,
    normalize_domain,
    resolve_hostname_if_needed,
    same_scope,
)

logger = logging.getLogger(__name__)


def extract_js_endpoints(js_text: str) -> set[str]:
    # 从 JS 文本中提取接口路径或 URL，用于发现隐藏 API 或关联子域名。
    endpoints = set()
    for match in JS_ENDPOINT_RE.findall(js_text):
        endpoint = (match or "").strip().strip('"\'')
        if endpoint:
            endpoints.add(endpoint)
    return endpoints


def extract_same_scope_urls(html: str, base_url: str, domain: str) -> tuple[set[str], set[str], set[str]]:
    # 解析 HTML 中的链接、脚本、表单地址，只保留与目标根域名同范围的 URL。
    urls: set[str] = set()
    js_urls: set[str] = set()
    inline_endpoints: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")

    for tag, attr in (("a", "href"), ("link", "href"), ("script", "src"), ("form", "action")):
        for node in soup.find_all(tag):
            raw = (node.get(attr) or "").strip()
            if not raw or raw.startswith(("javascript:", "mailto:", "#")):
                continue
            full = urljoin(base_url, raw)
            parsed = urlparse(full)
            if not parsed.hostname or not same_scope(parsed.hostname, domain):
                continue
            urls.add(full)
            if parsed.path.lower().endswith(".js"):
                js_urls.add(full)

    for script in soup.find_all("script"):
        if script.get("src"):
            continue
        # 内联脚本没有 src，需要直接从脚本文本中抽取接口路径。
        inline_endpoints.update(extract_js_endpoints(script.get_text(" ", strip=True)))

    return urls, js_urls, inline_endpoints


def fetch_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    *,
    connect_override_map: dict[str, str] | None = None,
) -> dict:
    # 连接时可使用覆盖 IP，但 TLS SNI 仍使用原始 hostname，以便获取对应证书。
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    connect_host = (connect_override_map or {}).get(normalize_domain(hostname), hostname)
    with socket.create_connection((connect_host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()

    subject = "/".join("=".join(part) for item in cert.get("subject", []) for part in item)
    # 证书 SAN 中经常包含同一组织的其他子域名，可作为资产发现线索。
    issuer = "/".join("=".join(part) for item in cert.get("issuer", []) for part in item)
    sans = [name for typ, name in cert.get("subjectAltName", []) if typ == "DNS"]
    return {"subject": subject, "issuer": issuer, "sans": sans}


def enrich_from_crawl_and_cert(
    domain: str,
    targets: dict[str, TargetRecord],
    probe_results: list,
    *,
    body: dict,
    nameservers: list[str] | None,
    dns_timeout: float,
    http_timeout: tuple[int, int],
    request_get_fn: Callable[..., requests.Response],
) -> int:
    # 记录富化前目标数量，函数最后返回新增目标数。
    count_before = len(targets)

    crawl_enabled = body.get("enable_crawl", True)
    js_enabled = body.get("enable_js_extract", True)
    cert_enabled = body.get("enable_certificate_parse", True)
    crawl_limit = int(body.get("crawl_limit", 10))
    js_fetch_limit = int(body.get("js_fetch_limit", 10))
    connect_override_map = connect_overrides(body)

    successful_urls = [pr.url for pr in probe_results if getattr(pr, "success", False) and getattr(pr, "url", "")]
    # 种子 URL 由主域名、用户传入 seed_urls 和探测成功 URL 共同组成。
    seed_urls = list(
        dict.fromkeys([f"https://{domain}", f"http://{domain}"] + (body.get("seed_urls") or []) + successful_urls)
    )[:crawl_limit]

    js_urls: list[tuple[str, str]] = []

    if crawl_enabled:
        for url in seed_urls:
            try:
                # 抓取页面 HTML 后，从页面链接、脚本地址和内联脚本中提取资产线索。
                html = fetch_url_text(
                    url,
                    timeout=http_timeout,
                    connect_override_map=connect_override_map,
                    request_get_fn=request_get_fn,
                )
                urls, discovered_js, inline_endpoints = extract_same_scope_urls(html, url, domain)
                for discovered_url in urls:
                    # 只接收同根域名范围内的链接，避免爬虫越界。
                    parsed = urlparse(discovered_url)
                    hostname = normalize_domain(parsed.hostname or "")
                    if not same_scope(hostname, domain):
                        continue
                    merge_target(
                        targets,
                        hostname,
                        source="web_crawl",
                        evidence=f"crawl from {url}",
                        url=discovered_url,
                    )
                for js_url in discovered_js:
                    # JS 文件 URL 同时作为 web_crawl 线索，并进入后续 JS 内容提取队列。
                    parsed = urlparse(js_url)
                    hostname = normalize_domain(parsed.hostname or "")
                    if not same_scope(hostname, domain):
                        continue
                    merge_target(
                        targets,
                        hostname,
                        source="web_crawl",
                        evidence=f"js discovered from {url}",
                        url=js_url,
                    )
                    js_urls.append((hostname, js_url))

                seed_host = normalize_domain(urlparse(url).hostname or "")
                if seed_host and inline_endpoints:
                    # 内联脚本提取到的端点绑定到当前页面所在主机。
                    merge_target(
                        targets,
                        seed_host,
                        source="js_extract",
                        evidence=f"inline script extraction: {url}",
                        url=url,
                        js_endpoints=inline_endpoints,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.debug("crawl failed [%s]: %s", url, exc)

    if js_enabled:
        for hostname, js_url in js_urls[:js_fetch_limit]:
            try:
                # 拉取外部 JS 文件内容，继续提取其中隐藏的接口路径。
                js_text = fetch_url_text(
                    js_url,
                    timeout=http_timeout,
                    connect_override_map=connect_override_map,
                    request_get_fn=request_get_fn,
                )
                endpoints = extract_js_endpoints(js_text)
                merge_target(
                    targets,
                    hostname,
                    source="js_extract",
                    evidence=f"js endpoint extraction: {js_url}",
                    url=js_url,
                    js_endpoints=endpoints,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("js extraction failed [%s]: %s", js_url, exc)

    if cert_enabled:
        # 只对 HTTPS 探测过的主机尝试解析证书，降低无效连接数量。
        https_hosts = {pr.subdomain for pr in probe_results if getattr(pr, "scheme", "") == "https"}
        for hostname in list(https_hosts)[:20]:
            try:
                cert_info = fetch_certificate(hostname, connect_override_map=connect_override_map)
                record = targets.setdefault(hostname, TargetRecord(subdomain=hostname))
                record.add_discovery("certificate")
                record.cert_subject = cert_info["subject"]
                record.cert_issuer = cert_info["issuer"]
                record.cert_sans.update(cert_info["sans"])
                for san in cert_info["sans"]:
                    # SAN 可能包含通配符域名，先去掉 *. 再判断是否属于目标范围。
                    normalized = normalize_domain(san.lstrip("*."))
                    if not same_scope(normalized, domain):
                        continue
                    added = merge_target(
                        targets,
                        normalized,
                        source="certificate",
                        evidence=f"certificate SAN from {hostname}",
                    )
                    if added:
                        resolve_hostname_if_needed(normalized, added, nameservers=nameservers, timeout=dns_timeout)
            except Exception as exc:  # noqa: BLE001
                logger.debug("certificate parse failed [%s]: %s", hostname, exc)

    return len(targets) - count_before


def run_active_discovery_stage(
    body: dict,
    *,
    domain: str,
    enumerate_subdomains_fn: Callable[..., list[dict]],
) -> dict[str, TargetRecord]:
    # 主动发现阶段主要依赖子域名字典枚举和 DNS A 记录解析。
    wordlist = body.get("wordlist")
    nameservers = body.get("nameservers")
    dns_timeout = float(body.get("dns_timeout", 3.0))

    targets: dict[str, TargetRecord] = {}
    if body.get("enable_active_enum", True):
        # enumerate_subdomains_fn 返回已解析到 IP 的子域名列表。
        for item in enumerate_subdomains_fn(
            target_domain=domain,
            wordlist=wordlist,
            nameservers=nameservers,
            timeout=dns_timeout,
        ):
            merge_target(
                targets,
                item["subdomain"],
                ips=item.get("ips") or [],
                source="active_dns",
                evidence="dictionary subdomain enumeration",
            )
    return targets
