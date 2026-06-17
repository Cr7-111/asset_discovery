# 子域名主动枚举模块，基于字典拼接和 DNS A 记录解析发现存活子域名。
"""
子域名发现模块 - 基于 dnspython 的 A 记录解析
Subdomain Discovery Module - A-record resolution via dnspython
"""

import logging
from typing import Generator

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# 常用子域名字典（可替换为外部字典文件）
DEFAULT_WORDLIST: list[str] = [
    # 覆盖常见业务、管理、开发、办公和基础设施子域名前缀。
    "www", "mail", "ftp", "smtp", "pop", "imap", "api",
    "dev", "test", "staging", "app", "admin", "portal",
    "blog", "shop", "static", "cdn", "img", "media",
    "docs", "help", "support", "git", "gitlab", "jenkins",
    "vpn", "remote", "ns1", "ns2", "mx", "webmail",
    "oa", "erp", "crm", "hr", "finance", "internal",
]


def resolve_a_records(hostname: str,
                      nameservers: list[str] | None = None,
                      timeout: float = 3.0) -> list[str]:
    """
    对单个主机名进行 A 记录解析，返回 IP 列表。

    Args:
        hostname:    要解析的完整域名，例如 "www.example.com"
        nameservers: 自定义 DNS 服务器列表，默认使用系统 DNS
        timeout:     单次解析超时秒数

    Returns:
        IP 地址字符串列表；解析失败返回空列表
    """
    resolver = dns.resolver.Resolver()
    # lifetime 控制整体解析耗时，避免单个域名卡住扫描流程。
    resolver.lifetime = timeout
    if nameservers:
        # 靶场扫描时可指定 CoreDNS；公网扫描时也可使用系统 DNS。
        resolver.nameservers = nameservers

    try:
        answers = resolver.resolve(hostname, "A")
        ips = [rdata.address for rdata in answers]
        logger.debug("解析 %s => %s", hostname, ips)
        return ips
    except dns.resolver.NXDOMAIN:
        logger.debug("域名不存在: %s", hostname)
    except dns.resolver.NoAnswer:
        logger.debug("无 A 记录: %s", hostname)
    except dns.resolver.Timeout:
        logger.warning("解析超时: %s", hostname)
    except dns.exception.DNSException as exc:
        logger.warning("DNS 异常 [%s]: %s", hostname, exc)
    return []


def discover_subdomains(
    target_domain: str,
    wordlist: list[str] | None = None,
    nameservers: list[str] | None = None,
    timeout: float = 3.0,
) -> Generator[dict, None, None]:
    """
    枚举子域名并解析 A 记录，以生成器形式逐条 yield 结果。

    Args:
        target_domain: 目标根域名，例如 "example.com"
        wordlist:      子域名前缀列表；None 则使用内置字典
        nameservers:   自定义 DNS 服务器
        timeout:       单次解析超时

    Yields:
        dict 形如 {"subdomain": "www.example.com", "ips": ["1.2.3.4"]}
    """
    prefixes = wordlist or DEFAULT_WORDLIST
    # 规范化根域名，避免用户输入末尾点或大小写影响拼接。
    target_domain = target_domain.strip().lower().rstrip(".")

    logger.info("开始子域名枚举: %s (%d 个前缀)", target_domain, len(prefixes))

    # 同时也尝试根域名本身
    # 根域名和字典子域名都进入候选列表。
    candidates = [target_domain] + [f"{p}.{target_domain}" for p in prefixes]

    found = 0
    for hostname in candidates:
        # 只有成功解析到 A 记录的域名才作为主动发现结果返回。
        ips = resolve_a_records(hostname, nameservers=nameservers, timeout=timeout)
        if ips:
            found += 1
            yield {"subdomain": hostname, "ips": ips}

    logger.info("枚举完成，共发现 %d 个有效子域名", found)


def discover_subdomains_list(
    target_domain: str,
    wordlist: list[str] | None = None,
    nameservers: list[str] | None = None,
    timeout: float = 3.0,
) -> list[dict]:
    """
    discover_subdomains 的列表版本（一次性返回所有结果）。

    Returns:
        [{"subdomain": "...", "ips": [...]}, ...]
    """
    return list(
        discover_subdomains(target_domain, wordlist, nameservers, timeout)
    )
