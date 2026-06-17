# 离线流量日志解析模块，从 DNS、SNI、Host、URL、Referer 或 PCAP 中提取资产线索。
"""Offline passive traffic analysis helpers for asset discovery."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DOMAIN_RE = re.compile(r"(?<!@)\b([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})\b")
# 不同正则分别用于识别 URL、DNS 查询、TLS SNI、HTTP Host 和 Referer。
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DNS_RE = re.compile(r"(?:dns(?:_query)?|query)\s*[:=]\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
SNI_RE = re.compile(r"(?:sni|server_name|tls_sni)\s*[:=]\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
HOST_RE = re.compile(r"(?:http_host|host)\s*[:=]\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
REFERER_RE = re.compile(r"(?:referer)\s*[:=]\s*(https?://[^\s\"'<>]+)", re.IGNORECASE)


def _normalize_domain(value: str) -> str:
    # 支持直接传入域名或 URL，统一返回小写 hostname。
    raw = (value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    return (parsed.hostname or raw).strip().lower().rstrip(".")


def _same_scope(hostname: str, root_domain: str) -> bool:
    # 只保留目标根域名及其子域名，避免流量日志中其他外部域名进入结果。
    hostname = _normalize_domain(hostname)
    root_domain = _normalize_domain(root_domain)
    return bool(hostname) and (hostname == root_domain or hostname.endswith(f".{root_domain}"))


def _add_finding(findings: dict, domain: str, hostname: str, evidence: str, url: str = "") -> None:
    # 以 hostname 为 key 聚合同一资产的多条证据和 URL。
    normalized = _normalize_domain(hostname)
    if not _same_scope(normalized, domain):
        return

    item = findings.setdefault(normalized, {"hostname": normalized, "urls": set(), "evidence": []})
    if evidence and evidence not in item["evidence"]:
        item["evidence"].append(evidence)
    if url:
        item["urls"].add(url)


def _ingest_structured_record(record: dict, domain: str, findings: dict) -> None:
    # 结构化记录常来自测试输入或预处理后的流量数据。
    timestamp = str(record.get("timestamp") or "").strip()
    suffix = f" [{timestamp}]" if timestamp else ""

    dns_query = record.get("dns_query") or record.get("query")
    if dns_query:
        _add_finding(findings, domain, str(dns_query), f"traffic dns query: {dns_query}{suffix}")

    sni = record.get("sni") or record.get("server_name") or record.get("tls_sni")
    if sni:
        _add_finding(findings, domain, str(sni), f"traffic tls sni: {sni}{suffix}")

    host = record.get("http_host") or record.get("host")
    if host:
        _add_finding(findings, domain, str(host), f"traffic http host: {host}{suffix}")

    for field in ("url", "referer"):
        value = str(record.get(field) or "").strip()
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.hostname and _same_scope(parsed.hostname, domain):
            _add_finding(findings, domain, parsed.hostname, f"traffic {field}: {value}{suffix}", value)


def _ingest_text_line(line: str, domain: str, findings: dict) -> None:
    # 非结构化日志逐行用正则提取 DNS/SNI/Host/URL 信息。
    content = (line or "").strip()
    if not content:
        return

    for pattern, label in ((DNS_RE, "traffic dns query"), (SNI_RE, "traffic tls sni"), (HOST_RE, "traffic http host")):
        for match in pattern.findall(content):
            _add_finding(findings, domain, match, f"{label}: {match}")

    for url in URL_RE.findall(content):
        parsed = urlparse(url)
        if parsed.hostname and _same_scope(parsed.hostname, domain):
            label = "traffic referer" if REFERER_RE.search(content) and url in REFERER_RE.findall(content) else "traffic url"
            _add_finding(findings, domain, parsed.hostname, f"{label}: {url}", url)


def _ingest_text_blob(text: str, domain: str, findings: dict) -> None:
    # 多行日志文本按行复用解析函数。
    for line in (text or "").splitlines():
        _ingest_text_line(line, domain, findings)


def _ingest_pcap(path: Path, domain: str, findings: dict) -> None:
    # PCAP 解析依赖 scapy，可选能力；缺少依赖时降级跳过。
    try:
        from scapy.all import DNSQR, Raw, rdpcap  # type: ignore[import-not-found]
    except Exception:
        logger.warning("PCAP parsing skipped because scapy is not available: %s", path)
        return

    try:
        packets = rdpcap(str(path))
    except Exception as exc:  # noqa: BLE001
        logger.warning("read traffic pcap failed [%s]: %s", path, exc)
        return

    for packet in packets:
        try:
            # 从 DNS 查询层和原始载荷中提取域名线索。
            if packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                _add_finding(findings, domain, query, f"pcap dns query: {query}")
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
                _ingest_text_line(payload, domain, findings)
        except Exception as exc:  # noqa: BLE001
            logger.debug("pcap packet parse failed [%s]: %s", path, exc)


def discover_from_traffic_data(body: dict, domain: str) -> list[dict]:
    """Extract same-scope hosts from offline traffic records, logs, or optional PCAP."""
    # findings 用字典去重，同一 hostname 下保留多条证据。
    findings: dict[str, dict] = {}

    for record in body.get("traffic_records") or []:
        if isinstance(record, dict):
            _ingest_structured_record(record, domain, findings)

    for line in body.get("traffic_log_lines") or []:
        if isinstance(line, str):
            _ingest_text_line(line, domain, findings)

    text_blob = body.get("traffic_log_text") or ""
    if text_blob:
        _ingest_text_blob(str(text_blob), domain, findings)

    traffic_log_path = body.get("traffic_log_path")
    if traffic_log_path:
        # traffic_log_path 可指向文本日志或 pcap/pcapng 文件。
        path = Path(str(traffic_log_path))
        if path.exists():
            if path.suffix.lower() in {".pcap", ".pcapng"}:
                _ingest_pcap(path, domain, findings)
            else:
                try:
                    _ingest_text_blob(path.read_text(encoding="utf-8", errors="ignore"), domain, findings)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("read traffic log failed [%s]: %s", path, exc)
        else:
            logger.warning("traffic log path not found: %s", path)

    results = []
    for item in findings.values():
        # set 类型 URL 转为排序列表，保证 JSON 返回稳定。
        results.append(
            {
                "hostname": item["hostname"],
                "urls": sorted(item["urls"]),
                "evidence": item["evidence"][:20],
            }
        )
    return sorted(results, key=lambda value: value["hostname"])
