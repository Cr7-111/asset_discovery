# 提供 HTTP/HTTPS 存活探测能力，获取状态码、页面标题和服务指纹。
"""
Web probing helpers for HTTP/HTTPS reachability and page metadata collection.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = (5, 10)
DEFAULT_PORTS: list[tuple[int, str]] = [
    # 默认覆盖常见 HTTP/HTTPS 端口，调用方也可以通过扫描参数覆盖。
    (80, "http"),
    (443, "https"),
    (8080, "http"),
    (8443, "https"),
]

HEADERS = {
    # 使用常见浏览器请求头，减少简单服务对非浏览器请求的差异响应。
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


@dataclass
class ProbeResult:
    """Single HTTP probe result."""

    subdomain: str
    ip: str
    port: int
    scheme: str
    url: str = ""
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    error: str | None = None
    success: bool = False
    headers: dict = field(default_factory=dict)


def _extract_title(html: str) -> str | None:
    # 从 HTML 中提取 <title>，作为资产识别和风险分析的重要页面指纹。
    try:
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("title")
        if tag and tag.string:
            return tag.string.strip()[:512]
    except Exception as exc:  # noqa: BLE001
        logger.debug("title extraction failed: %s", exc)
    return None


def _build_request_url_and_headers(
    url: str,
    *,
    connect_overrides: dict[str, str] | None = None,
) -> tuple[str, dict]:
    # 靶场 host 模式下，域名可能需要连接到 127.0.0.1，但请求仍要保留原 Host。
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").strip().lower()
    override_ip = (connect_overrides or {}).get(hostname)
    if not override_ip or not hostname:
        # 没有连接覆盖时，直接访问原始 URL。
        return url, {}

    # 使用覆盖 IP 建立连接，同时通过 Host 头让 Nginx 边缘代理识别原始域名。
    netloc = override_ip if not parsed.port else f"{override_ip}:{parsed.port}"
    target_url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    return target_url, {"Host": hostname}


def probe_url(
    url: str,
    timeout: tuple[int, int] = DEFAULT_TIMEOUT,
    verify_ssl: bool = False,
    connect_overrides: dict[str, str] | None = None,
) -> dict:
    """
    Probe a single URL and collect basic metadata.
    """
    result = {
        # 初始化为失败状态；只有 requests.get 成功返回响应后才标记 success=True。
        "url": url,
        "status_code": None,
        "title": None,
        "server": None,
        "error": None,
        "success": False,
    }

    try:
        # target_url 可能是原始域名，也可能是连接覆盖后的 IP 地址。
        target_url, extra_headers = _build_request_url_and_headers(
            url,
            connect_overrides=connect_overrides,
        )
        resp = requests.get(
            target_url,
            headers={**HEADERS, **extra_headers},
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
        )
        result["status_code"] = resp.status_code
        # Server 响应头和页面标题会被后续资产分析、标签和机器学习模块使用。
        result["server"] = resp.headers.get("Server")
        result["title"] = _extract_title(resp.text)
        result["success"] = True
        logger.debug("probe success %s => %d", url, resp.status_code)
    except requests.exceptions.SSLError as exc:
        # SSL 错误单独记录，便于区分证书问题和网络不可达问题。
        result["error"] = f"SSL error: {exc}"
        logger.warning("ssl error [%s]: %s", url, exc)
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection failed: {exc}"
        logger.debug("connection failed [%s]: %s", url, exc)
    except requests.exceptions.Timeout:
        result["error"] = "request timeout"
        logger.warning("request timeout [%s]", url)
    except requests.exceptions.TooManyRedirects:
        result["error"] = "too many redirects"
        logger.warning("too many redirects [%s]", url)
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        logger.error("unknown probe error [%s]: %s", url, exc)

    return result


def probe_host(
    subdomain: str,
    ip: str,
    ports: list[tuple[int, str]] | None = None,
    timeout: tuple[int, int] = DEFAULT_TIMEOUT,
    verify_ssl: bool = False,
    connect_overrides: dict[str, str] | None = None,
) -> list[ProbeResult]:
    """
    Probe multiple ports for one host.
    """
    results: list[ProbeResult] = []
    probe_ports = ports or DEFAULT_PORTS

    for port, scheme in probe_ports:
        # 标准端口省略端口号，非标准端口保留端口，保证生成的 URL 可直接访问。
        url = f"{scheme}://{subdomain}:{port}" if port not in (80, 443) else f"{scheme}://{subdomain}"
        raw = probe_url(
            url,
            timeout=timeout,
            verify_ssl=verify_ssl,
            connect_overrides=connect_overrides,
        )
        results.append(
            # 将原始字典封装为 ProbeResult，便于验证阶段统一处理字段。
            ProbeResult(
                subdomain=subdomain,
                ip=ip,
                port=port,
                scheme=scheme,
                url=url,
                status_code=raw["status_code"],
                title=raw["title"],
                server=raw["server"],
                error=raw["error"],
                success=raw["success"],
            )
        )

    return results


def probe_targets(
    targets: list[dict],
    ports: list[tuple[int, str]] | None = None,
    timeout: tuple[int, int] = DEFAULT_TIMEOUT,
    verify_ssl: bool = False,
    connect_overrides: dict[str, str] | None = None,
) -> list[ProbeResult]:
    """
    Probe multiple targets.
    """
    all_results: list[ProbeResult] = []

    for item in targets:
        subdomain = item["subdomain"]
        for ip in item["ips"]:
            # 同一子域名可能解析到多个 IP，因此按子域名/IP 组合逐个探测。
            logger.info("probing %s (%s)", subdomain, ip)
            results = probe_host(
                subdomain,
                ip,
                ports=ports,
                timeout=timeout,
                verify_ssl=verify_ssl,
                connect_overrides=connect_overrides,
            )
            all_results.extend(results)

    logger.info("web probing finished, total records=%d", len(all_results))
    return all_results
