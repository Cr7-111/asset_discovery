# 文件作用：从 NVD 原始漏洞数据中提取 CVE 训练样本和本地漏洞知识库。
"""从 NVD 2.0 JSON 数据中抽取 CVE 训练样本。

输出文件：
- data/cve_samples.csv：模型训练使用的文本分类数据
- data/cve_knowledge_base.csv：系统运行时用于匹配资产组件的本地 CVE 知识库
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


COMPONENT_KEYWORDS = {
    # 组件关键词用于把 CVE 描述映射到系统可识别的组件名称。
    # 后端运行时会根据资产组件名称在知识库中筛选相关 CVE。
    "Apache Tomcat": ["tomcat", "apache-coyote"],
    "Jenkins": ["jenkins"],
    "nginx": ["nginx"],
    "Apache HTTP Server": ["apache http server", "httpd"],
    "Redis": ["redis"],
    "MySQL": ["mysql", "mariadb"],
    "Spring": ["spring framework", "spring boot", "spring cloud"],
    "OpenSSH": ["openssh"],
    "OpenSSL": ["openssl"],
    "PHP": ["php"],
    "WordPress": ["wordpress"],
}


def main() -> None:
    # 1. 读取命令行参数：支持一次传入多个 NVD 年度 JSON 文件
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", help="Path(s) to nvdcve-2.0-YYYY.json")
    parser.add_argument("--samples", default="data/cve_samples.csv")
    parser.add_argument("--knowledge-base", default="data/cve_knowledge_base.csv")
    args = parser.parse_args()

    samples_path = Path(args.samples)
    kb_path = Path(args.knowledge_base)
    samples_path.parent.mkdir(parents=True, exist_ok=True)
    kb_path.parent.mkdir(parents=True, exist_ok=True)

    # 2. 合并多个年度 CVE 数据，并按 cve_id 去重
    # 使用字典按 cve_id 去重，避免多个年度数据中存在重复 CVE 记录。
    rows_by_id = {}
    for input_value in args.inputs:
        input_path = Path(input_value)
        print(f"Reading {input_path}")
        with input_path.open("r", encoding="utf-8") as file:
            payload = json.load(file)

        for row in extract_rows(payload):
            rows_by_id[row["cve_id"]] = row

    rows = list(rows_by_id.values())
    rows.sort(key=lambda row: (row["severity"], row["cve_id"]))

    # 3. 输出训练样本：cve_samples.csv 用于模型训练与评估
    write_csv(samples_path, rows, ["cve_id", "description", "training_text", "cvss_score", "severity"])
    # 4. 输出本地知识库：cve_knowledge_base.csv 后续用于资产组件与 CVE 情报匹配
    write_csv(kb_path, rows, ["cve_id", "description", "training_text", "cvss_score", "severity", "component_keywords"])
    print(f"Extracted {len(rows)} CVE rows")
    print(f"Training samples: {samples_path}")
    print(f"Knowledge base: {kb_path}")


def extract_rows(payload: dict) -> list[dict]:
    """从单个 NVD JSON 结构中抽取可训练的 CVE 记录。"""
    rows = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        # 1. 提取 CVE 编号，例如 CVE-2025-12345
        cve_id = cve.get("id") or ""
        # 2. 提取英文漏洞描述，作为基础自然语言文本
        description = english_description(cve.get("descriptions") or [])
        # 3. 提取严重等级和 CVSS 分数，其中 severity 是模型训练标签
        severity, cvss_score = best_severity(cve.get("metrics") or {})
        if not cve_id or not description or not severity:
            continue
        rows.append(
            {
                "cve_id": cve_id,
                "description": normalize_text(description),
                # 4. 构建增强训练文本：描述 + CWE + CVSS向量 + 引用标签 + 漏洞状态
                "training_text": build_training_text(cve, description),
                "cvss_score": cvss_score,
                "severity": severity.upper(),
                # 5. 抽取组件关键词，用于后续系统运行时匹配资产组件
                "component_keywords": ";".join(match_components(description)),
            }
        )
    return rows


def english_description(descriptions: list[dict]) -> str:
    # 从 descriptions 列表中选择英文描述，避免多语言文本混入训练集
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    return ""


def best_severity(metrics: dict) -> tuple[str, float | str]:
    # 按 CVSS 4.0、3.1、3.0、2.0 的顺序选择可用评分信息
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        metric = values[0]
        data = metric.get("cvssData") or {}
        severity = data.get("baseSeverity") or metric.get("baseSeverity")
        score = data.get("baseScore")
        if severity:
            return str(severity).upper(), score if score is not None else ""
    return "", ""


def build_training_text(cve: dict, description: str) -> str:
    """构建增强训练文本。

    训练文本由四类信息组成：
    1. CVE 英文描述；
    2. CWE 弱点编号，例如 CWE_79、CWE_89；
    3. CVSS 向量字段，例如 cvss_AV_N、cvss_AC_L；
    4. NVD 引用标签，例如 ref_exploit、ref_patch。

    注意：这里不把 cvss_score 直接加入训练文本，避免直接用分数推导严重等级。
    """
    # 1. 基础文本：CVE 漏洞英文描述
    parts = [description]
    # 2. 增强特征：CWE 弱点编号，例如 CWE_79、CWE_89
    parts.extend(extract_cwe_tokens(cve.get("weaknesses") or []))
    # 3. 增强特征：CVSS 向量字段，例如 cvss_AV_N、cvss_AC_L
    parts.extend(extract_cvss_vector_tokens(cve.get("metrics") or {}))
    # 4. 增强特征：参考链接标签，例如 ref_exploit、ref_patch
    parts.extend(extract_reference_tags(cve.get("references") or []))
    status = cve.get("vulnStatus")
    if status:
        # 5. 增强特征：漏洞状态，例如 status_Analyzed
        parts.append(f"status_{status}")
    return normalize_text(" ".join(str(part) for part in parts if part))


def extract_cwe_tokens(weaknesses: list[dict]) -> list[str]:
    """从 weaknesses 字段抽取 CWE 编号。"""
    tokens = []
    for weakness in weaknesses:
        for item in weakness.get("description") or []:
            value = str(item.get("value") or "").strip()
            if value:
                # 将 CWE-79 处理成 CWE_79，避免分词时被连字符拆散
                tokens.append(value.replace("-", "_"))
    return tokens


def extract_cvss_vector_tokens(metrics: dict) -> list[str]:
    """从 CVSS vectorString 中抽取攻击向量、复杂度、权限等结构化特征。"""
    tokens = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        cvss_data = values[0].get("cvssData") or {}
        vector = str(cvss_data.get("vectorString") or "")
        for segment in vector.split("/"):
            if ":" not in segment or segment.startswith("CVSS:"):
                continue
            name, value = segment.split(":", 1)
            if name and value:
                # 例如 AV:N 转为 cvss_AV_N，表示网络攻击向量
                tokens.append(f"cvss_{name}_{value}".replace("-", "_"))
        break
    return tokens


def extract_reference_tags(references: dict | list) -> list[str]:
    """抽取参考链接标签，作为漏洞是否有利用、补丁或厂商公告的辅助特征。"""
    rows = references.get("referenceData") if isinstance(references, dict) else references
    tokens = []
    for row in rows or []:
        for tag in row.get("tags") or []:
            normalized = str(tag).lower().replace(" ", "_").replace("-", "_")
            tokens.append(f"ref_{normalized}")
    return tokens


def normalize_text(text: str) -> str:
    # 统一去掉换行和多余空格，保证 CSV 中的训练文本保持单行、便于模型读取。
    return " ".join(text.replace("\n", " ").replace("\r", " ").split())


def match_components(description: str) -> list[str]:
    # 根据漏洞描述中的组件关键词，生成后续资产匹配用的组件标签
    lower = description.lower()
    matched = []
    for component, keywords in COMPONENT_KEYWORDS.items():
        if any(keyword in lower for keyword in keywords):
            matched.append(component)
    return matched


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    # 按指定字段顺序输出 CSV，保证训练脚本和后端知识库读取字段稳定。
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


if __name__ == "__main__":
    main()
