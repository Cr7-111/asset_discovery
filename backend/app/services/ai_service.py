"""LLM-powered asset risk analysis service.

This module supports OpenAI-compatible chat completion APIs. If no API key is
configured, it returns a deterministic local fallback so demos remain stable.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import requests

from backend.app.core.config import load_project_env
from backend.app.core.db import (
    fetch_ai_analysis,
    fetch_asset_by_id,
    fetch_risk_by_asset,
    fetch_tags_by_asset,
    upsert_ai_analysis,
)

logger = logging.getLogger(__name__)

load_project_env()

DEFAULT_MODEL = "local-rule-fallback"

TAG_LABELS = {
    "admin_panel": "管理后台公网暴露",
    "login_page": "登录入口可直接访问",
    "api_service": "API 服务暴露",
    "api_docs_exposed": "API 文档暴露",
    "database_exposed": "数据库服务或管理界面暴露",
    "high_risk_port": "高危端口开放",
    "dev_env": "开发环境暴露",
    "test_env": "测试环境暴露",
    "directory_listing": "目录遍历风险",
    "middleware_exposed": "中间件信息暴露",
    "backup_related": "备份相关入口暴露",
    "default_page": "默认页面暴露",
}

TYPE_BY_TAG = [
    ("database_exposed", "数据库服务"),
    ("middleware_exposed", "中间件服务"),
    ("api_docs_exposed", "API 服务"),
    ("api_service", "API 服务"),
    ("admin_panel", "管理后台"),
    ("dev_env", "开发测试系统"),
    ("test_env", "开发测试系统"),
    ("login_page", "Web 应用"),
]


def analyze_asset_with_ai(asset_id: int) -> dict:
    """Generate and persist AI risk analysis for one asset."""
    # 读取资产、标签和规则评分结果，作为 LLM 综合研判的事实依据。
    asset = fetch_asset_by_id(asset_id)
    if asset is None:
        return {"status": "error", "error": f"asset_id={asset_id} not found", "asset_id": asset_id}

    tags = fetch_tags_by_asset(asset_id)
    risk = fetch_risk_by_asset(asset_id) or {}
    payload = _build_context(asset, tags, risk)

    model_name = _model_name()
    if os.getenv("AI_API_KEY"):
        try:
            # 已配置模型密钥时调用外部大语言模型生成分析结果。
            result = _call_llm(payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM analysis failed, fallback to local result [asset_id=%d]: %s", asset_id, exc)
            # 模型调用失败时使用本地降级分析，保证页面功能不中断。
            result = _fallback_analysis(payload, reason=f"大模型调用失败，已使用本地降级分析：{exc}")
            model_name = f"{model_name}+fallback"
    else:
        # 未配置模型密钥时直接使用本地规则生成基础分析内容。
        result = _fallback_analysis(payload, reason="当前未配置 AI_API_KEY，系统使用本地降级分析生成演示结果。")
        model_name = DEFAULT_MODEL

    # 对模型或降级结果进行字段规范化后写入 asset_ai_analysis 表。
    normalized = _normalize_result(result)
    upsert_ai_analysis(
        asset_id=asset_id,
        asset_type=normalized["asset_type"],
        risk_reason=normalized["risk_reason"],
        weak_points=normalized["weak_points"],
        suggestions=normalized["suggestions"],
        report_summary=normalized["report_summary"],
        model_name=model_name,
    )

    saved = fetch_ai_analysis(asset_id) or {}
    saved["status"] = "ok"
    return saved


def get_ai_analysis(asset_id: int) -> dict | None:
    """Return persisted AI analysis if it exists."""
    return fetch_ai_analysis(asset_id)


def _build_context(asset: dict, tags: list[dict], risk: dict) -> dict:
    return {
        "asset": {
            "asset_id": asset.get("asset_id"),
            "domain": asset.get("domain"),
            "ip": asset.get("ip"),
            "port": asset.get("port"),
            "status_code": asset.get("status_code"),
            "title": asset.get("title"),
            "server": asset.get("server"),
        },
        "tags": [
            {
                "tag_name": tag.get("tag_name"),
                "tag_source": tag.get("tag_source"),
                "confidence": tag.get("confidence"),
                "matched_rule": tag.get("matched_rule"),
            }
            for tag in tags
        ],
        "risk": {
            "risk_score": risk.get("risk_score"),
            "risk_level": risk.get("risk_level"),
            "score_detail": _decode_score_detail(risk.get("score_detail")),
            "suggestions": _split_suggestions(risk.get("suggestions")),
        },
    }


def _call_llm(payload: dict) -> dict:
    # 从环境变量读取 OpenAI 兼容接口配置，便于切换不同模型服务。
    base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    api_key = os.environ["AI_API_KEY"]
    model = _model_name()
    timeout = float(os.getenv("AI_TIMEOUT", "30"))

    url = f"{base_url}/chat/completions"
    # 通过提示词约束模型角色和输出格式，要求只返回可解析的 JSON 字段。
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是企业暴露面管理系统中的安全风险分析助手。"
                    "请基于输入资产、标签和规则风险评分进行分析，只返回 JSON，"
                    "不得返回 Markdown 或额外解释。"
                ),
            },
            {
                "role": "user",
                "content": (
                    "请输出字段：asset_type, risk_reason, weak_points, suggestions, report_summary。\n"
                    f"资产上下文如下：\n{json.dumps(payload, ensure_ascii=False)}"
                ),
            },
        ],
        "temperature": 0.2,
    }

    with _build_http_session() as session:
        response = session.post(
            url,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=timeout,
        )
    response.raise_for_status()
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    return _parse_json_content(content)


def _build_http_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = _use_env_proxy()
    return session


def _use_env_proxy() -> bool:
    value = os.getenv("AI_USE_ENV_PROXY", "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _fallback_analysis(payload: dict, reason: str) -> dict:
    tags = {tag["tag_name"] for tag in payload["tags"] if tag.get("tag_name")}
    weak_points = [label for tag, label in TAG_LABELS.items() if tag in tags]
    if not weak_points and payload["risk"].get("risk_score", 0):
        weak_points.append("资产存在规则评分命中的风险项")
    if not weak_points:
        weak_points.append("暂未发现明显高危标签，建议持续监控资产暴露变化")

    asset_type = _infer_cn_asset_type(tags)
    risk_level = payload["risk"].get("risk_level") or "unknown"
    risk_score = payload["risk"].get("risk_score")
    domain = payload["asset"].get("domain") or "该资产"

    suggestions = payload["risk"].get("suggestions") or []
    if not suggestions:
        suggestions = [
            "定期复核资产暴露面和访问控制策略",
            "保持服务组件版本更新并隐藏不必要的响应头信息",
        ]

    return {
        "asset_type": asset_type,
        "risk_reason": f"{reason} {domain} 当前规则风险等级为 {risk_level}，风险分值为 {risk_score}，主要风险点包括：{'、'.join(weak_points)}。",
        "weak_points": weak_points,
        "suggestions": suggestions[:5],
        "report_summary": f"{domain} 被识别为{asset_type}，当前属于 {risk_level} 风险资产，建议优先处理访问控制、服务暴露和版本信息泄露问题。",
    }


def _normalize_result(result: dict[str, Any]) -> dict:
    return {
        "asset_type": str(result.get("asset_type") or "未知资产"),
        "risk_reason": str(result.get("risk_reason") or "暂无风险原因说明"),
        "weak_points": _ensure_string_list(result.get("weak_points")),
        "suggestions": _ensure_string_list(result.get("suggestions")),
        "report_summary": str(result.get("report_summary") or "暂无报告摘要"),
    }


def _ensure_string_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _parse_json_content(content: str) -> dict:
    text = content.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if not match:
            raise
        return json.loads(match.group(0))


def _decode_score_detail(value) -> list:
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []


def _split_suggestions(value) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [line for line in value.splitlines() if line.strip()]
    return []


def _infer_cn_asset_type(tags: set[str]) -> str:
    for tag_name, asset_type in TYPE_BY_TAG:
        if tag_name in tags:
            return asset_type
    return "Web 资产"


def _model_name() -> str:
    return os.getenv("AI_MODEL", "gpt-4o-mini")
