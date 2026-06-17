# 模型评估可视化代码

本文档用于生成 CVE 严重等级分类模型的前四类评估可视化图，适合直接复制到 Jupyter Notebook 中按单元格运行。

生成内容包括：

1. 各模型测试准确率比较
2. 各模型测试 F1 值比较
3. 各模型交叉验证平均值比较
4. 各模型训练集与测试集准确率比较

输出图片默认保存到 `docs/ml_eval/` 目录。

## 1. 导入依赖

```python
from pathlib import Path

import json
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
```

## 2. 设置路径和基础参数

```python
samples_path = Path("data/cve_samples.csv")
eval_dir = Path("docs/ml_eval")
eval_dir.mkdir(parents=True, exist_ok=True)

label_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# 如果完整数据训练时间较长，可以先设置为 20000 做调试；
# 正式论文结果建议设置为 None，使用完整数据集。
sample_limit = None
```

## 3. 读取并清洗训练数据

```python
df = pd.read_csv(samples_path)

# 优先使用增强后的 training_text 字段；如果没有，则使用 description。
if "training_text" not in df.columns:
    df["training_text"] = df["description"]

df["training_text"] = df["training_text"].fillna(df.get("description", ""))
df = df.dropna(subset=["training_text", "severity"])
df["severity"] = df["severity"].astype(str).str.upper().str.strip()
df = df[df["severity"].isin(label_order)]

if sample_limit is not None:
    df = (
        df.groupby("severity", group_keys=False)
        .apply(lambda item: item.sample(min(len(item), sample_limit // len(label_order)), random_state=42))
        .reset_index(drop=True)
    )

print("样本总数：", len(df))
print(df["severity"].value_counts())
```

## 4. 划分训练集和测试集

```python
train_x, test_x, train_y, test_y = train_test_split(
    df["training_text"],
    df["severity"],
    test_size=0.2,
    random_state=42,
    stratify=df["severity"],
)

print("训练集数量：", len(train_x))
print("测试集数量：", len(test_x))
```

## 5. 定义模型

```python
def build_pipeline(classifier):
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 3),
                    sublinear_tf=True,
                    min_df=2,
                    max_features=50000,
                ),
            ),
            ("classifier", classifier),
        ]
    )


model_defs = {
    "Logistic Regression": LogisticRegression(
        max_iter=1200,
        class_weight="balanced",
        solver="lbfgs",
        random_state=42,
    ),
    "Linear SVM": LinearSVC(
        class_weight="balanced",
        random_state=42,
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        max_depth=45,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=1,
        random_state=42,
    ),
}
```

## 6. 训练模型并计算测试指标

```python
rows = []
trained_models = {}

for model_name, classifier in model_defs.items():
    print(f"正在训练：{model_name}")
    model = build_pipeline(classifier)
    model.fit(train_x, train_y)

    train_pred = model.predict(train_x)
    test_pred = model.predict(test_x)

    row = {
        "model": model_name,
        "train_accuracy": accuracy_score(train_y, train_pred),
        "test_accuracy": accuracy_score(test_y, test_pred),
        "test_macro_f1": f1_score(test_y, test_pred, labels=label_order, average="macro", zero_division=0),
        "test_weighted_f1": f1_score(test_y, test_pred, labels=label_order, average="weighted", zero_division=0),
    }

    rows.append(row)
    trained_models[model_name] = model

metrics_df = pd.DataFrame(rows)
metrics_df
```

## 7. 计算交叉验证平均值

```python
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

cv_rows = []

for model_name, classifier in model_defs.items():
    print(f"正在进行交叉验证：{model_name}")
    model = build_pipeline(classifier)

    scores = cross_val_score(
        model,
        df["training_text"],
        df["severity"],
        cv=cv,
        scoring="accuracy",
        n_jobs=1,
    )

    cv_rows.append(
        {
            "model": model_name,
            "cv_accuracy_mean": scores.mean(),
            "cv_accuracy_std": scores.std(),
        }
    )

cv_df = pd.DataFrame(cv_rows)
metrics_df = metrics_df.merge(cv_df, on="model")

metrics_df.to_csv(eval_dir / "model_visualization_metrics.csv", index=False, encoding="utf-8-sig")
(eval_dir / "model_visualization_metrics.json").write_text(
    json.dumps(metrics_df.to_dict(orient="records"), ensure_ascii=False, indent=2),
    encoding="utf-8",
)

metrics_df
```

## 8. 通用绘图函数

```python
plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei", "Arial"]
plt.rcParams["axes.unicode_minus"] = False


def save_bar_chart(title, data, y_label, output_name, ylim=(0, 1.05)):
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(data["model"], data["value"], color=data["color"])

    ax.set_title(title, fontsize=15)
    ax.set_ylabel(y_label)
    ax.set_ylim(*ylim)
    ax.grid(axis="y", linestyle="--", alpha=0.35)

    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + 0.01,
            f"{height:.4f}",
            ha="center",
            va="bottom",
            fontsize=10,
        )

    plt.xticks(rotation=10)
    plt.tight_layout()
    plt.savefig(eval_dir / output_name, format="svg")
    plt.show()
```

## 9. 测试准确率比较图

```python
plot_df = pd.DataFrame(
    {
        "model": metrics_df["model"],
        "value": metrics_df["test_accuracy"],
        "color": ["#2563eb", "#16a34a", "#dc2626"],
    }
)

save_bar_chart(
    title="各模型测试准确率比较",
    data=plot_df,
    y_label="测试准确率",
    output_name="test_accuracy_comparison.svg",
)
```

## 10. 测试 F1 值比较图

```python
fig, ax = plt.subplots(figsize=(9, 5))

x = range(len(metrics_df))
bar_width = 0.35

ax.bar(
    [i - bar_width / 2 for i in x],
    metrics_df["test_macro_f1"],
    width=bar_width,
    label="Macro F1",
    color="#7c3aed",
)
ax.bar(
    [i + bar_width / 2 for i in x],
    metrics_df["test_weighted_f1"],
    width=bar_width,
    label="Weighted F1",
    color="#f97316",
)

ax.set_title("各模型测试 F1 值比较", fontsize=15)
ax.set_ylabel("F1 值")
ax.set_ylim(0, 1.05)
ax.set_xticks(list(x))
ax.set_xticklabels(metrics_df["model"], rotation=10)
ax.grid(axis="y", linestyle="--", alpha=0.35)
ax.legend()

for i, row in metrics_df.iterrows():
    ax.text(i - bar_width / 2, row["test_macro_f1"] + 0.01, f"{row['test_macro_f1']:.4f}", ha="center", fontsize=9)
    ax.text(i + bar_width / 2, row["test_weighted_f1"] + 0.01, f"{row['test_weighted_f1']:.4f}", ha="center", fontsize=9)

plt.tight_layout()
plt.savefig(eval_dir / "test_f1_comparison.svg", format="svg")
plt.show()
```

## 11. 交叉验证平均值比较图

```python
fig, ax = plt.subplots(figsize=(8, 5))

bars = ax.bar(
    metrics_df["model"],
    metrics_df["cv_accuracy_mean"],
    yerr=metrics_df["cv_accuracy_std"],
    capsize=6,
    color=["#2563eb", "#16a34a", "#dc2626"],
)

ax.set_title("各模型交叉验证平均准确率比较", fontsize=15)
ax.set_ylabel("交叉验证平均准确率")
ax.set_ylim(0, 1.05)
ax.grid(axis="y", linestyle="--", alpha=0.35)

for bar, mean_value in zip(bars, metrics_df["cv_accuracy_mean"]):
    ax.text(
        bar.get_x() + bar.get_width() / 2,
        mean_value + 0.015,
        f"{mean_value:.4f}",
        ha="center",
        va="bottom",
        fontsize=10,
    )

plt.xticks(rotation=10)
plt.tight_layout()
plt.savefig(eval_dir / "cross_validation_mean_comparison.svg", format="svg")
plt.show()
```

## 12. 训练集与测试集准确率比较图

```python
fig, ax = plt.subplots(figsize=(9, 5))

x = range(len(metrics_df))
bar_width = 0.35

ax.bar(
    [i - bar_width / 2 for i in x],
    metrics_df["train_accuracy"],
    width=bar_width,
    label="训练准确率",
    color="#0284c7",
)
ax.bar(
    [i + bar_width / 2 for i in x],
    metrics_df["test_accuracy"],
    width=bar_width,
    label="测试准确率",
    color="#ea580c",
)

ax.set_title("各模型训练准确率与测试准确率比较", fontsize=15)
ax.set_ylabel("准确率")
ax.set_ylim(0, 1.05)
ax.set_xticks(list(x))
ax.set_xticklabels(metrics_df["model"], rotation=10)
ax.grid(axis="y", linestyle="--", alpha=0.35)
ax.legend()

for i, row in metrics_df.iterrows():
    ax.text(i - bar_width / 2, row["train_accuracy"] + 0.01, f"{row['train_accuracy']:.4f}", ha="center", fontsize=9)
    ax.text(i + bar_width / 2, row["test_accuracy"] + 0.01, f"{row['test_accuracy']:.4f}", ha="center", fontsize=9)

plt.tight_layout()
plt.savefig(eval_dir / "train_test_accuracy_comparison.svg", format="svg")
plt.show()
```

## 13. 输出结果

运行完成后，会生成以下文件：

| 文件 | 含义 |
| --- | --- |
| `docs/ml_eval/model_visualization_metrics.csv` | 四类评估图使用的指标表 |
| `docs/ml_eval/model_visualization_metrics.json` | JSON 格式指标结果 |
| `docs/ml_eval/test_accuracy_comparison.svg` | 各模型测试准确率比较图 |
| `docs/ml_eval/test_f1_comparison.svg` | 各模型测试 F1 值比较图 |
| `docs/ml_eval/cross_validation_mean_comparison.svg` | 各模型交叉验证平均值比较图 |
| `docs/ml_eval/train_test_accuracy_comparison.svg` | 各模型训练集与测试集准确率比较图 |

## 14. 运行方式

1. 打开 Jupyter Notebook。
2. 将本文档中的代码按章节复制到 Notebook 单元格中。
3. 从第 1 节依次运行到第 12 节。
4. 运行完成后，在 `docs/ml_eval/` 目录查看生成的 SVG 图表。

如果完整数据运行时间较长，可以先把第 2 节中的 `sample_limit = None` 改成：

```python
sample_limit = 20000
```

调试通过后，再改回：

```python
sample_limit = None
```

使用完整数据重新生成论文图表。
