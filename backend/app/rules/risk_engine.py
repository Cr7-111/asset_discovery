# 定义规则型风险评分引擎，根据资产特征计算风险分值、等级和整改建议。
"""Rule-based risk scoring engine.

The previous auxiliary classifier is disabled. Risk levels are now derived only
from deterministic scoring rules so the core assessment flow remains stable
before the new LLM analysis module is introduced.
"""

import logging

logger = logging.getLogger(__name__)


_SERVER_EXPOSURE_KEYWORDS = [
    # 常见中间件、Web 服务器或语言运行时关键词，用于判断 Server 头是否泄露组件信息。
    "tomcat",
    "jetty",
    "jboss",
    "weblogic",
    "websphere",
    "glassfish",
    "wildfly",
    "nginx/",
    "apache/",
    "iis/",
    "openresty/",
    "lighttpd/",
    "gunicorn/",
    "werkzeug",
    "php/",
    "python/",
    "ruby",
]


def _check_server_exposure(server: str) -> bool:
    """Return whether the Server header exposes middleware/version details."""
    if not server:
        return False
    # 统一转小写后匹配，避免不同服务返回大小写不一致导致漏判。
    value = server.lower()
    return any(keyword in value for keyword in _SERVER_EXPOSURE_KEYWORDS)


def _get_tags(asset_data: dict) -> set:
    """Extract tag names from either list[dict] or list[str]."""
    # 风险服务可能传入数据库标签字典，也可能传入测试用的字符串列表，这里做兼容。
    tags = asset_data.get("tags", [])
    if not tags:
        return set()
    if isinstance(tags[0], dict):
        return {item.get("tag_name", "") for item in tags}
    return set(tags)


SCORE_RULES = [
    # 数据库类资产暴露风险最高，命中 database_exposed 标签时增加较高分值。
    {
        "key": "database_exposed",
        "score": 25,
        "description": "数据库管理界面或数据库端口暴露在公网",
        "suggestion": "关闭数据库公网访问，仅允许内网或白名单来源访问。",
        "check": lambda data: "database_exposed" in _get_tags(data),
    },
    # 管理后台直接暴露容易被暴力破解或未授权访问，因此赋予较高风险分。
    {
        "key": "admin_panel",
        "score": 20,
        "description": "管理后台或控制台暴露在公网",
        "suggestion": "将管理后台迁移至内网或 VPN，并启用访问控制和 MFA。",
        "check": lambda data: "admin_panel" in _get_tags(data),
    },
    # SSH、RDP、FTP、数据库等高危端口开放时增加风险分值。
    {
        "key": "high_risk_port",
        "score": 20,
        "description": "SSH/RDP/FTP/Telnet/数据库等高危端口开放",
        "suggestion": "关闭不必要端口，高危服务应通过 VPN 或白名单访问。",
        "check": lambda data: "high_risk_port" in _get_tags(data),
    },
    # 开发环境通常安全控制较弱，公网暴露时需要提示收敛访问范围。
    {
        "key": "dev_env",
        "score": 15,
        "description": "开发环境暴露在公网",
        "suggestion": "开发环境不应部署到公网，并应关闭 Debug 能力。",
        "check": lambda data: "dev_env" in _get_tags(data),
    },
    # 测试或预发布环境暴露会泄露接口、配置或调试信息。
    {
        "key": "test_env",
        "score": 15,
        "description": "测试或预发布环境暴露在公网",
        "suggestion": "测试环境应通过内网、VPN 或 IP 白名单限制访问。",
        "check": lambda data: "test_env" in _get_tags(data),
    },
    # API 文档对外开放可能暴露接口结构和调用参数。
    {
        "key": "api_docs_exposed",
        "score": 15,
        "description": "Swagger/OpenAPI 等 API 文档对公网开放",
        "suggestion": "生产环境应关闭 API 文档或增加身份认证。",
        "check": lambda data: "api_docs_exposed" in _get_tags(data),
    },
    # Server 响应头包含中间件或版本信息时，容易被用于定向漏洞利用。
    {
        "key": "middleware_server",
        "score": 10,
        "description": "Server 响应头暴露中间件或版本信息",
        "suggestion": "隐藏 Server 版本信息，降低被定向利用的风险。",
        "check": lambda data: _check_server_exposure(data.get("server", "")),
    },
    # 登录页面对公网可访问时，提示增加认证加固措施。
    {
        "key": "login_page",
        "score": 5,
        "description": "登录页面可被公网访问",
        "suggestion": "增加验证码、登录失败锁定、MFA 和访问来源限制。",
        "check": lambda data: "login_page" in _get_tags(data),
    },
    # 状态码为 200 表示资产真实可访问，作为基础暴露风险加入评分。
    {
        "key": "status_200",
        "score": 5,
        "description": "HTTP 状态码为 200，服务正常可访问",
        "suggestion": "确认该资产确需公网访问，否则应限制访问范围。",
        "check": lambda data: data.get("status_code") == 200,
    },
]


def score_to_level(score: int) -> str:
    """Convert a numeric score to a risk level."""
    # 分值区间保持简单明确，便于论文说明和前端展示。
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def calc_risk_score(asset_data: dict) -> dict:
    """Calculate deterministic rule-based risk score for one asset."""
    # 初始化风险分值、命中规则详情和整改建议列表。
    total_score = 0
    score_detail = []
    suggestions = []

    # 遍历预置风险规则，逐条判断当前资产是否命中对应风险项。
    for rule in SCORE_RULES:
        try:
            hit = rule["check"](asset_data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("risk rule check failed [key=%s]: %s", rule["key"], exc)
            hit = False

        if hit:
            # 命中规则后累加权重分值，并保留风险来源，便于前端展示和人工复核。
            total_score += rule["score"]
            score_detail.append(
                {
                    "key": rule["key"],
                    "score": rule["score"],
                    "description": rule["description"],
                }
            )
            suggestions.append(rule["suggestion"])

    # 将总分限制在 0-100 范围内，并根据分值区间转换为风险等级。
    total_score = min(total_score, 100)
    risk_level = score_to_level(total_score)

    logger.info(
        "rule risk score completed: asset_id=%s score=%d level=%s hits=%d",
        asset_data.get("asset_id"),
        total_score,
        risk_level,
        len(score_detail),
    )

    # 返回结构化风险结果，供入库、风险列表展示和资产详情页展示使用。
    return {
        "risk_score": total_score,
        "risk_level": risk_level,
        "score_detail": score_detail,
        "suggestions": suggestions,
    }
