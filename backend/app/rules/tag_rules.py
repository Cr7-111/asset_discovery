# 文件作用：资产标签规则引擎，根据域名、标题、Server 和端口为资产生成风险标签。
"""
tag_rules.py —— 关键词规则引擎（第三阶段）
基于 domain / title / server / port 字段进行规则匹配，
输出标签列表与命中规则明细，支持一条资产同时命中多个标签。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
# 数据结构
# ══════════════════════════════════════════════════════════════

@dataclass
class TagResult:
    """单个标签的命中结果"""
    tag_name:     str                  # 标签名称，如 "admin_panel"
    tag_source:   str = "rule_engine"  # 来源固定为 rule_engine
    confidence:   float = 1.0          # 规则命中置信度（关键词规则固定为 1.0）
    matched_rule: str = ""             # 命中的具体规则描述，方便审计


@dataclass
class RuleMatchResult:
    """一条资产的完整规则匹配结果"""
    asset_id:      int
    tags:          list = field(default_factory=list)   # list[TagResult]
    matched_count: int = 0


# ══════════════════════════════════════════════════════════════
# 规则定义
# 每条规则是一个 dict，结构：
#   tag        : str  —— 目标标签名
#   field      : str  —— 匹配字段：domain / title / server / port
#   pattern    : str  —— 正则表达式（忽略大小写）
#   description: str  —— 规则说明（写入 matched_rule 字段）
# 端口规则 field="port"，pattern 为端口号字符串精确匹配
# ══════════════════════════════════════════════════════════════

RULES: list[dict] = [
    # 规则表是资产分析模块的核心依据，每条规则命中后会生成一个资产标签。

    # ── dev_env：开发环境 ─────────────────────────────────────
    {"tag": "dev_env", "field": "domain",
     "pattern": r"(dev|develop|development|local|localhost)\.",
     "description": "域名含 dev/develop 等前缀"},
    {"tag": "dev_env", "field": "title",
     "pattern": r"(开发环境|development environment|dev env|debug mode)",
     "description": "标题含开发环境相关词"},
    {"tag": "dev_env", "field": "server",
     "pattern": r"(werkzeug|django.*dev|flask.*debug)",
     "description": "Server 头暴露开发框架调试模式"},

    # ── test_env：测试环境 ────────────────────────────────────
    {"tag": "test_env", "field": "domain",
     "pattern": r"(test|testing|qa|uat|staging|stage|pre|preview|sandbox)\.",
     "description": "域名含测试/预发布相关前缀"},
    {"tag": "test_env", "field": "title",
     "pattern": r"(测试环境|test environment|staging|uat|sandbox)",
     "description": "标题含测试环境相关词"},

    # ── admin_panel：管理后台 ─────────────────────────────────
    {"tag": "admin_panel", "field": "domain",
     "pattern": r"(admin|manager|manage|console|backend|backstage|ops)\.",
     "description": "域名含管理后台相关前缀"},
    {"tag": "admin_panel", "field": "title",
     "pattern": r"(管理后台|管理系统|后台管理|admin panel|admin console|control panel|运营后台|administrator)",
     "description": "标题含管理后台相关词"},
    {"tag": "admin_panel", "field": "title",
     "pattern": r"(phpmyadmin|adminer|webmin|cpanel|plesk)",
     "description": "标题含已知管理工具名称"},

    # ── login_page：登录页 ────────────────────────────────────
    {"tag": "login_page", "field": "title",
     "pattern": r"(登录|登陆|login|sign in|用户登录|账号登录)",
     "description": "标题含登录相关词"},
    {"tag": "login_page", "field": "domain",
     "pattern": r"(login|signin|auth|sso|passport|account)\.",
     "description": "域名含登录/认证相关前缀"},

    # ── api_service：API 服务 ─────────────────────────────────
    {"tag": "api_service", "field": "domain",
     "pattern": r"(api|gateway|gw|service|svc|graphql|grpc)\.",
     "description": "域名含 API/网关相关前缀"},
    {"tag": "api_service", "field": "title",
     "pattern": r"(api gateway|api service|graphql|swagger|openapi)",
     "description": "标题含 API 服务相关词"},
    {"tag": "api_service", "field": "server",
     "pattern": r"(kong|apisix|tyk|apigee)",
     "description": "Server 头暴露 API 网关产品"},

    # ── api_docs_exposed：API 文档暴露 ───────────────────────
    {"tag": "api_docs_exposed", "field": "title",
     "pattern": r"(swagger ui|swagger editor|redoc|api docs|knife4j|yapi|apifox|openapi 3)",
     "description": "标题含 Swagger/Redoc 等 API 文档工具"},
    {"tag": "api_docs_exposed", "field": "domain",
     "pattern": r"(swagger|apidoc|docs|api-doc)\.",
     "description": "域名指向 API 文档子站"},

    # ── database_exposed：数据库暴露 ─────────────────────────
    {"tag": "database_exposed", "field": "title",
     "pattern": r"(phpmyadmin|adminer|redis commander|mongo express|kibana|elasticsearch)",
     "description": "标题含数据库管理工具"},
    {"tag": "database_exposed", "field": "domain",
     "pattern": r"(db|database|mysql|redis|mongo|elastic|postgres|pgsql)\.",
     "description": "域名含数据库相关前缀"},
    {"tag": "database_exposed", "field": "port",
     "pattern": r"^(3306|5432|6379|27017|9200|5984|1521|1433)$",
     "description": "端口为常见数据库端口"},

    # ── default_page：默认页面 ────────────────────────────────
    {"tag": "default_page", "field": "title",
     "pattern": r"(apache test page|welcome to nginx|welcome to apache|it works|iis default|nginx welcome)",
     "description": "标题为 Web 服务器默认测试页"},
    {"tag": "default_page", "field": "title",
     "pattern": r"^(403 forbidden|404 not found)$",
     "description": "标题为纯错误码页"},

    # ── directory_listing：目录遍历 ───────────────────────────
    {"tag": "directory_listing", "field": "title",
     "pattern": r"(index of /|directory listing|parent directory)",
     "description": "标题含目录遍历特征词"},

    # ── middleware_exposed：中间件暴露 ────────────────────────
    {"tag": "middleware_exposed", "field": "title",
     "pattern": r"(jenkins|gitlab|jira|confluence|sonarqube|grafana|prometheus|kibana|rabbitmq|nacos|eureka|zipkin|skywalking|apollo|druid monitor|spring boot admin)",
     "description": "标题含 CI/CD、监控、注册中心等中间件名称"},
    {"tag": "middleware_exposed", "field": "domain",
     "pattern": r"(jenkins|gitlab|jira|confluence|grafana|kibana|nacos|eureka)\.",
     "description": "域名直接指向中间件系统"},
    {"tag": "middleware_exposed", "field": "server",
     "pattern": r"(Jetty|Tomcat|JBoss|WebLogic|WebSphere|GlassFish|WildFly)",
     "description": "Server 头暴露 Java 中间件版本"},

    # ── backup_related：备份相关 ──────────────────────────────
    {"tag": "backup_related", "field": "domain",
     "pattern": r"(backup|bak|archive|old|copy|mirror)\.",
     "description": "域名含备份相关词"},
    {"tag": "backup_related", "field": "title",
     "pattern": r"(backup|备份|archive|历史版本|旧版本)",
     "description": "标题含备份/归档相关词"},

    # ── high_risk_port：高危端口 ──────────────────────────────
    {"tag": "high_risk_port", "field": "port",
     "pattern": r"^(21|22|23|25|445|3389|5900|4444|8888|9090|9000|2375|2376|4243|8500|2181|9092|9300|15672|8161)$",
     "description": "端口为高风险服务端口（FTP/SSH/Telnet/RDP/VNC/Docker等）"},
]

# 预编译所有正则，避免每次匹配重复编译
_compiled: list[dict] = []
for _rule in RULES:
    try:
        # 正则统一忽略大小写，适配不同服务返回的标题和 Server 头。
        _compiled.append({**_rule, "_re": re.compile(_rule["pattern"], re.IGNORECASE)})
    except re.error as _e:
        logger.error("规则正则编译失败 [tag=%s]: %s", _rule["tag"], _e)


# ══════════════════════════════════════════════════════════════
# 核心匹配函数
# ══════════════════════════════════════════════════════════════

def match_rules(
    asset_id: int,
    domain:   Optional[str] = None,
    title:    Optional[str] = None,
    server:   Optional[str] = None,
    port:     Optional[int] = None,
) -> RuleMatchResult:
    """
    对单条资产执行全部规则匹配。

    Args:
        asset_id : 资产主键
        domain   : 子域名
        title    : 页面标题
        server   : Server 响应头
        port     : 端口号

    Returns:
        RuleMatchResult，包含命中的所有 TagResult
    """
    field_values: dict[str, str] = {
        # 将资产字段统一整理成字符串，避免 None 或数字端口直接参与正则匹配。
        "domain": (domain or "").lower(),
        "title":  (title  or "").lower(),
        "server": (server or ""),
        "port":   str(port) if port is not None else "",
    }

    result = RuleMatchResult(asset_id=asset_id)
    hit_tags: dict[str, TagResult] = {}  # tag_name -> TagResult，用于合并同标签多规则

    for rule in _compiled:
        # 逐条规则检查对应字段，命中后写入 tag_name 和 matched_rule。
        field_name = rule["field"]
        value      = field_values.get(field_name, "")
        tag_name   = rule["tag"]

        if not value:
            continue  # 字段为空，跳过不匹配

        try:
            if rule["_re"].search(value):
                if tag_name in hit_tags:
                    # 同一标签可由多条规则共同支撑，保留多条命中说明便于审计。
                    # 同一标签被多条规则命中，追加规则描述
                    hit_tags[tag_name].matched_rule += f" | {rule['description']}"
                else:
                    hit_tags[tag_name] = TagResult(
                        tag_name     = tag_name,
                        tag_source   = "rule_engine",
                        confidence   = 1.0,
                        matched_rule = rule["description"],
                    )
        except Exception as exc:
            logger.warning("规则匹配异常 [tag=%s field=%s]: %s", tag_name, field_name, exc)

    result.tags          = list(hit_tags.values())
    # matched_count 用于前端或日志快速了解该资产命中多少类标签。
    result.matched_count = len(result.tags)

    if result.matched_count:
        logger.debug("资产 %d 命中标签: %s", asset_id, [t.tag_name for t in result.tags])

    return result


def match_rules_batch(assets: list[dict]) -> list[RuleMatchResult]:
    """
    批量规则匹配。

    Args:
        assets: 资产字典列表，每个 dict 需含 asset_id/domain/title/server/port

    Returns:
        每条资产对应一个 RuleMatchResult
    """
    results = []
    for asset in assets:
        try:
            # 批量匹配仍复用单资产匹配函数，保证两种入口结果一致。
            res = match_rules(
                asset_id = int(asset.get("asset_id", 0)),
                domain   = asset.get("domain"),
                title    = asset.get("title"),
                server   = asset.get("server"),
                port     = asset.get("port"),
            )
            results.append(res)
        except Exception as exc:
            logger.error("批量规则匹配异常 [asset_id=%s]: %s", asset.get("asset_id"), exc)
    return results
