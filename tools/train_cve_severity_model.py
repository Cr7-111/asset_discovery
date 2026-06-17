# 文件作用：训练并评估 CVE 严重等级分类模型，保存模型文件和可视化评估结果。
"""训练并对比多个 CVE 严重等级分类模型。

本脚本会做三件事：
1. 使用同一份 CVE 文本数据训练三个模型；
2. 分别保存每个模型、分类报告和混淆矩阵；
3. 生成模型准确率、F1 值等指标对比表，便于论文展示。
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import time
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC


# CVSS 严重等级标签顺序，后续混淆矩阵和图表都会按照该顺序展示。
LABEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LABEL_COLORS = {
    "LOW": "#22c55e",
    "MEDIUM": "#f59e0b",
    "HIGH": "#ef4444",
    "CRITICAL": "#7f1d1d",
}


def main() -> None:
    # 1. 读取命令行参数：训练样本路径、模型保存目录、评估结果目录
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", default="data/cve_samples.csv")
    parser.add_argument("--models-dir", default="models/cve_severity")
    parser.add_argument("--eval-dir", default="docs/ml_eval")
    args = parser.parse_args()

    samples_path = Path(args.samples)
    models_dir = Path(args.models_dir)
    eval_dir = Path(args.eval_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    eval_dir.mkdir(parents=True, exist_ok=True)

    # 2. 导入 CVE 训练样本，数据来源为 extract_nvd_cve.py 生成的 cve_samples.csv
    df = load_samples(samples_path)
    # 3. 划分训练集和测试集，三种模型共用同一划分结果，保证实验对比公平
    train_x, test_x, train_y, test_y = split_samples(df)
    labels = [label for label in LABEL_ORDER if label in set(df["severity"])]

    # 4. 定义要对比的三个分类算法：逻辑回归、线性 SVM、随机森林
    # 三个模型使用相同的 TF-IDF 特征提取方式，保证对比尽量公平。
    model_defs = {
        "logistic_regression": LogisticRegression(
            max_iter=1200,
            class_weight="balanced",
            solver="lbfgs",
            random_state=42,
        ),
        "linear_svm": LinearSVC(
            class_weight="balanced",
            random_state=42,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=45,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            # Windows 沙箱环境下并行线程池可能触发权限问题，因此使用单线程保证稳定。
            n_jobs=1,
            random_state=42,
        ),
    }

    comparison_rows = []
    for model_name, classifier in model_defs.items():
        # 5. 逐个训练模型，并为每个模型单独生成评估文件
        print(f"\n=== Training {model_name} ===")
        row = train_one_model(
            model_name=model_name,
            classifier=classifier,
            train_x=train_x,
            train_y=train_y,
            test_x=test_x,
            test_y=test_y,
            labels=labels,
            models_dir=models_dir,
            eval_dir=eval_dir,
        )
        comparison_rows.append(row)

    # 6. 生成三种模型的总体对比表和对比图
    write_comparison_files(eval_dir, comparison_rows)
    # 7. 生成 CVE 严重等级样本分布图，便于论文展示数据集结构
    write_distribution_svg(eval_dir / "severity_distribution.svg", Counter(df["severity"]), labels)

    print("\n=== Model comparison ===")
    for row in comparison_rows:
        print(
            f"{row['model']}: accuracy={row['accuracy']:.4f}, "
            f"macro_f1={row['macro_f1']:.4f}, weighted_f1={row['weighted_f1']:.4f}, "
            f"train_seconds={row['train_seconds']:.2f}"
        )
    print(f"\nModels saved in: {models_dir}")
    print(f"Evaluation files saved in: {eval_dir}")


def load_samples(samples_path: Path) -> pd.DataFrame:
    """读取训练样本，并过滤掉无效标签或空描述。"""
    # 1. 导入 CSV 文件：每一行代表一条 CVE 漏洞样本
    df = pd.read_csv(samples_path)
    # 如果数据抽取脚本提供了 training_text，则优先使用增强训练文本；
    # 否则回退到 description，兼容旧版训练数据。
    if "training_text" not in df.columns:
        df["training_text"] = df["description"]
    df["training_text"] = df["training_text"].fillna(df.get("description", ""))
    # 2. 删除训练文本或标签为空的无效样本
    df = df.dropna(subset=["training_text", "severity"])
    # 3. 标准化标签，只保留 LOW、MEDIUM、HIGH、CRITICAL 四类
    df["severity"] = df["severity"].astype(str).str.upper().str.strip()
    df = df[df["severity"].isin(LABEL_ORDER)]
    if df.empty:
        raise ValueError("No valid CVE samples found")
    return df


def split_samples(df: pd.DataFrame):
    """统一划分训练集和测试集，三种模型共用同一划分结果。"""
    # stratify=df["severity"] 用于保持训练集和测试集中各严重等级比例基本一致
    return train_test_split(
        df["training_text"],
        df["severity"],
        test_size=0.2,
        random_state=42,
        stratify=df["severity"],
    )


def build_pipeline(classifier) -> Pipeline:
    """构建 TF-IDF + 分类器流水线。"""
    return Pipeline(
        steps=[
            (
                "tfidf",
                # 1. 使用 TF-IDF 将漏洞情报文本转换为机器学习可处理的数值向量
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    # 使用 1-3 gram 捕捉 remote code execution、privilege escalation 等关键短语。
                    ngram_range=(1, 3),
                    sublinear_tf=True,
                    min_df=2,
                    max_features=50000,
                ),
            ),
            # 2. 接入具体分类器，完成 LOW / MEDIUM / HIGH / CRITICAL 分类
            ("classifier", classifier),
        ]
    )


def train_one_model(
    *,
    model_name: str,
    classifier,
    train_x,
    train_y,
    test_x,
    test_y,
    labels: list[str],
    models_dir: Path,
    eval_dir: Path,
) -> dict:
    """训练单个模型，并输出该模型的评估文件。"""
    # 1. 构建模型流水线：TF-IDF 特征提取 + 分类算法
    pipeline = build_pipeline(classifier)
    # 2. 训练模型，并记录训练耗时
    start = time.perf_counter()
    pipeline.fit(train_x, train_y)
    train_seconds = time.perf_counter() - start

    # 3. 使用测试集进行预测
    pred_y = pipeline.predict(test_x)
    # 4. 计算准确率、宏平均指标、加权平均指标
    accuracy = accuracy_score(test_y, pred_y)
    macro_precision, macro_recall, macro_f1, _ = precision_recall_fscore_support(
        test_y,
        pred_y,
        labels=labels,
        average="macro",
        zero_division=0,
    )
    weighted_precision, weighted_recall, weighted_f1, _ = precision_recall_fscore_support(
        test_y,
        pred_y,
        labels=labels,
        average="weighted",
        zero_division=0,
    )

    # 5. 保存训练好的模型文件，后续系统集成时可直接加载 .pkl 文件
    model_path = models_dir / f"{model_name}.pkl"
    joblib.dump(pipeline, model_path)

    model_eval_dir = eval_dir / model_name
    if model_eval_dir.exists():
        shutil.rmtree(model_eval_dir)
    model_eval_dir.mkdir(parents=True, exist_ok=True)

    # 6. 生成分类报告和混淆矩阵，用于论文实验分析
    report_text = classification_report(test_y, pred_y, labels=labels, zero_division=0)
    report_dict = classification_report(test_y, pred_y, labels=labels, output_dict=True, zero_division=0)
    matrix = confusion_matrix(test_y, pred_y, labels=labels)

    (model_eval_dir / "classification_report.txt").write_text(report_text, encoding="utf-8")
    # 7. 保存 JSON 格式指标，便于后续程序读取或生成图表
    (model_eval_dir / "metrics.json").write_text(
        json.dumps(
            {
                "model": model_name,
                "model_path": str(model_path),
                "accuracy": accuracy,
                "macro_precision": macro_precision,
                "macro_recall": macro_recall,
                "macro_f1": macro_f1,
                "weighted_precision": weighted_precision,
                "weighted_recall": weighted_recall,
                "weighted_f1": weighted_f1,
                "train_seconds": train_seconds,
                "classification_report": report_dict,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    # 8. 保存混淆矩阵 CSV 和 SVG 图片
    write_confusion_matrix_csv(model_eval_dir / "confusion_matrix.csv", labels, matrix)
    write_confusion_matrix_svg(model_eval_dir / "confusion_matrix.svg", labels, matrix, title=model_name)

    print(f"Model saved: {model_path}")
    print(f"Accuracy: {accuracy:.4f}, weighted_f1: {weighted_f1:.4f}, train_seconds: {train_seconds:.2f}")

    return {
        "model": model_name,
        "model_path": str(model_path),
        "accuracy": accuracy,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "weighted_precision": weighted_precision,
        "weighted_recall": weighted_recall,
        "weighted_f1": weighted_f1,
        "train_seconds": train_seconds,
    }


def write_comparison_files(eval_dir: Path, rows: list[dict]) -> None:
    """输出三种模型的指标对比表和对比图。"""
    # 同时输出 CSV、JSON 和 SVG，分别满足论文表格、程序读取和图表展示需求。
    csv_path = eval_dir / "model_comparison.csv"
    json_path = eval_dir / "model_comparison.json"
    svg_path = eval_dir / "model_comparison.svg"
    train_time_svg_path = eval_dir / "train_time_comparison.svg"
    fields = [
        "model",
        "model_path",
        "accuracy",
        "macro_precision",
        "macro_recall",
        "macro_f1",
        "weighted_precision",
        "weighted_recall",
        "weighted_f1",
        "train_seconds",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    write_model_comparison_svg(svg_path, rows)
    write_train_time_comparison_svg(train_time_svg_path, rows)


def write_confusion_matrix_csv(path: Path, labels: list[str], matrix) -> None:
    # 混淆矩阵 CSV 以真实标签为行、预测标签为列，便于人工检查分类错误。
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["actual\\predicted", *labels])
        for label, row in zip(labels, matrix):
            writer.writerow([label, *[int(value) for value in row]])


def write_distribution_svg(path: Path, counts: Counter, labels: list[str]) -> None:
    # 生成纯 SVG 图，不依赖 matplotlib，方便在缺少绘图库的环境中复现实验图。
    width = 760
    height = 430
    margin_left = 90
    margin_bottom = 70
    chart_width = width - margin_left - 40
    chart_height = height - 90 - margin_bottom
    max_count = max(counts.values()) if counts else 1
    bar_gap = 30
    bar_width = (chart_width - bar_gap * (len(labels) - 1)) / max(len(labels), 1)

    parts = [svg_header(width, height), text(24, 36, "CVE Severity Distribution", 22, "bold")]
    parts.append(line(margin_left, 70, margin_left, 70 + chart_height))
    parts.append(line(margin_left, 70 + chart_height, margin_left + chart_width, 70 + chart_height))

    for index, label in enumerate(labels):
        count = counts.get(label, 0)
        bar_height = chart_height * (count / max_count)
        x = margin_left + index * (bar_width + bar_gap)
        y = 70 + chart_height - bar_height
        parts.append(rect(x, y, bar_width, bar_height, LABEL_COLORS.get(label, "#64748b")))
        parts.append(text(x + bar_width / 2, y - 8, str(count), 14, "bold", anchor="middle"))
        parts.append(text(x + bar_width / 2, 70 + chart_height + 28, label, 14, "normal", anchor="middle"))

    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_confusion_matrix_svg(path: Path, labels: list[str], matrix, *, title: str) -> None:
    # 使用颜色深浅表示预测数量，颜色越深表示该单元格样本越多。
    cell = 74
    left = 130
    top = 92
    width = left + cell * len(labels) + 40
    height = top + cell * len(labels) + 90
    max_value = max([int(value) for row in matrix for value in row] or [1])
    parts = [svg_header(width, height), text(24, 36, f"Confusion Matrix - {title}", 22, "bold")]
    parts.append(text(left + cell * len(labels) / 2, 68, "Predicted", 14, "bold", anchor="middle"))
    parts.append(text(24, top + cell * len(labels) / 2, "Actual", 14, "bold"))

    for index, label in enumerate(labels):
        parts.append(text(left + index * cell + cell / 2, top - 16, label, 12, "bold", anchor="middle"))
        parts.append(text(left - 14, top + index * cell + cell / 2 + 5, label, 12, "bold", anchor="end"))

    for row_index, row in enumerate(matrix):
        for col_index, value in enumerate(row):
            intensity = int(245 - 170 * (int(value) / max_value))
            color = f"rgb({intensity},{intensity + 6},{255})"
            x = left + col_index * cell
            y = top + row_index * cell
            parts.append(rect(x, y, cell, cell, color, stroke="#ffffff"))
            parts.append(text(x + cell / 2, y + cell / 2 + 5, str(int(value)), 16, "bold", anchor="middle"))

    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_model_comparison_svg(path: Path, rows: list[dict]) -> None:
    """生成 Accuracy、Macro F1、Weighted F1 三项指标的对比柱状图。"""
    # 三个指标放在同一组柱状图中，便于直观看出不同模型性能差异。
    width = 900
    height = 460
    left = 90
    top = 72
    chart_width = 760
    chart_height = 280
    metrics = [
        ("accuracy", "#2563eb"),
        ("macro_f1", "#16a34a"),
        ("weighted_f1", "#dc2626"),
    ]
    group_width = chart_width / max(len(rows), 1)
    bar_width = 46
    max_value = max([row[key] for row in rows for key, _ in metrics] or [1])
    max_value = max(max_value, 1)

    parts = [svg_header(width, height), text(24, 36, "Model Comparison", 22, "bold")]
    parts.append(line(left, top, left, top + chart_height))
    parts.append(line(left, top + chart_height, left + chart_width, top + chart_height))

    for row_index, row in enumerate(rows):
        group_x = left + row_index * group_width + 40
        for metric_index, (metric, color) in enumerate(metrics):
            value = row[metric]
            bar_height = chart_height * (value / max_value)
            x = group_x + metric_index * (bar_width + 8)
            y = top + chart_height - bar_height
            parts.append(rect(x, y, bar_width, bar_height, color))
            parts.append(text(x + bar_width / 2, y - 6, f"{value:.2f}", 12, "bold", anchor="middle"))
        parts.append(text(group_x + 80, top + chart_height + 28, row["model"], 12, "normal", anchor="middle"))

    legend_x = left
    legend_y = height - 54
    for index, (metric, color) in enumerate(metrics):
        x = legend_x + index * 180
        parts.append(rect(x, legend_y, 18, 18, color))
        parts.append(text(x + 26, legend_y + 14, metric, 13))

    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_train_time_comparison_svg(path: Path, rows: list[dict]) -> None:
    """Generate a bar chart comparing model training time."""
    width = 820
    height = 440
    left = 90
    top = 72
    chart_width = 680
    chart_height = 270
    colors = ["#2563eb", "#16a34a", "#dc2626", "#7c3aed"]
    max_seconds = max([float(row.get("train_seconds", 0)) for row in rows] or [1])
    max_seconds = max(max_seconds, 1)
    group_width = chart_width / max(len(rows), 1)
    bar_width = min(96, group_width * 0.45)

    parts = [svg_header(width, height), text(24, 36, "Training Time Comparison", 22, "bold")]
    parts.append(line(left, top, left, top + chart_height))
    parts.append(line(left, top + chart_height, left + chart_width, top + chart_height))
    parts.append(text(24, top + chart_height / 2, "Seconds", 13, "bold"))

    tick_count = 4
    for tick in range(tick_count + 1):
        value = max_seconds * tick / tick_count
        y = top + chart_height - chart_height * tick / tick_count
        parts.append(line(left - 5, y, left, y))
        parts.append(text(left - 12, y + 4, f"{value:.0f}", 11, "normal", anchor="end"))

    for index, row in enumerate(rows):
        value = float(row.get("train_seconds", 0))
        bar_height = chart_height * (value / max_seconds)
        x = left + index * group_width + (group_width - bar_width) / 2
        y = top + chart_height - bar_height
        parts.append(rect(x, y, bar_width, bar_height, colors[index % len(colors)]))
        parts.append(text(x + bar_width / 2, y - 6, f"{value:.2f}s", 12, "bold", anchor="middle"))
        parts.append(text(x + bar_width / 2, top + chart_height + 28, row["model"], 12, "normal", anchor="middle"))

    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def svg_header(width: int, height: int) -> str:
    # SVG 公共头部，统一白色背景和视口大小。
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
        '<rect width="100%" height="100%" fill="#ffffff"/>'
    )


def rect(x, y, width, height, fill, stroke="#0f172a") -> str:
    # 绘制柱状图或矩阵单元格使用的矩形。
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height:.1f}" fill="{fill}" stroke="{stroke}"/>'


def line(x1, y1, x2, y2) -> str:
    # 绘制图表坐标轴。
    return f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#334155" stroke-width="1.5"/>'


def text(x, y, value, size, weight="normal", anchor="start") -> str:
    # 绘制 SVG 文本标签，包括标题、数值和坐标轴文字。
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" '
        f'font-family="Arial, sans-serif" font-size="{size}" font-weight="{weight}" fill="#0f172a">'
        f"{value}</text>"
    )


if __name__ == "__main__":
    main()
