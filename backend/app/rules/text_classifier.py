# 文件作用：资产类型文本分类模块，根据标题、域名和 Server 文本预测资产类型。
"""
text_classifier.py —— TF-IDF 文本分类模块（第三阶段）
将 title + domain + server 拼接为文本，使用 TfidfVectorizer + LogisticRegression
进行资产类型分类。模型不存在时自动训练并保存，支持增量重训练。
"""

import os
import logging
import pickle
from pathlib import Path
from typing import Optional

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

logger = logging.getLogger(__name__)

# ── 路径配置（相对于 app.py 所在目录）──────────────────────────
BASE_DIR        = Path(__file__).resolve().parents[3]
TRAINING_CSV    = BASE_DIR / "data" / "training_samples.csv"
MODEL_PATH      = BASE_DIR / "models" / "tfidf_classifier.pkl"

# ── 分类类别 ────────────────────────────────────────────────────
CATEGORIES = [
    "web_site",          # 普通网站
    "admin_panel",       # 管理后台
    "api_service",       # API 服务
    "dev_test_system",   # 开发/测试系统
    "database_service",  # 数据库管理界面
    "middleware_service",# 中间件服务
    "unknown",           # 无法识别
]

# ── 默认训练样本（当 CSV 不存在时自动生成）──────────────────────
DEFAULT_SAMPLES = [
    # text, label
    ("www example com Apache welcome to nginx",               "web_site"),
    ("blog example com nginx personal blog home",             "web_site"),
    ("news example com IIS company news portal",              "web_site"),
    ("shop example com Apache online store",                  "web_site"),
    ("portal example com nginx enterprise portal",            "web_site"),
    ("official example com IIS corporate homepage",           "web_site"),
    ("admin example com Tomcat admin panel management",       "admin_panel"),
    ("manage example com Tomcat backend console",             "admin_panel"),
    ("backend example com nginx admin dashboard",             "admin_panel"),
    ("console example com Tomcat control panel",              "admin_panel"),
    ("oa example com office automation management",           "admin_panel"),
    ("erp example com JBoss enterprise resource planning",    "admin_panel"),
    ("crm example com Tomcat customer relationship",          "admin_panel"),
    ("api example com nginx api gateway",                     "api_service"),
    ("gateway example com Kong api gateway service",          "api_service"),
    ("service example com nginx microservice endpoint",       "api_service"),
    ("graphql example com graphql api service",               "api_service"),
    ("swagger example com swagger ui api docs",               "api_service"),
    ("openapi example com openapi rest service",              "api_service"),
    ("dev example com Werkzeug development debug",            "dev_test_system"),
    ("test example com nginx test environment staging",       "dev_test_system"),
    ("staging example com Apache staging pre-release",        "dev_test_system"),
    ("uat example com Tomcat acceptance testing",             "dev_test_system"),
    ("qa example com nginx quality assurance test",           "dev_test_system"),
    ("sandbox example com sandbox development",               "dev_test_system"),
    ("mysql example com phpMyAdmin database management",      "database_service"),
    ("redis example com Redis Commander redis",               "database_service"),
    ("mongo example com Mongo Express mongodb",               "database_service"),
    ("db example com Adminer database tool",                  "database_service"),
    ("elastic example com Kibana elasticsearch",              "database_service"),
    ("pgsql example com pgAdmin postgresql",                  "database_service"),
    ("jenkins example com Jenkins CI CD pipeline",            "middleware_service"),
    ("gitlab example com GitLab code repository",             "middleware_service"),
    ("grafana example com Grafana monitoring dashboard",      "middleware_service"),
    ("nacos example com Nacos service discovery",             "middleware_service"),
    ("rabbitmq example com RabbitMQ message queue",           "middleware_service"),
    ("kibana example com Kibana log analysis",                "middleware_service"),
    ("jira example com Jira project management",              "middleware_service"),
    ("unknown1 example com nginx 403 forbidden",              "unknown"),
    ("unknown2 example com Apache default page",              "unknown"),
    ("unknown3 example com IIS coming soon",                  "unknown"),
    ("unknown4 example com nginx maintenance",                "unknown"),
]


# ══════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════

def build_text(
    title:  Optional[str] = None,
    domain: Optional[str] = None,
    server: Optional[str] = None,
) -> str:
    """
    将 title / domain / server 拼接成分类用的文本。
    空字段用空字符串替代，拼接后去除多余空白。
    """
    parts = [
        # 页面标题通常包含业务类型或组件名称，是分类的重要文本来源。
        (title  or "").strip(),
        (domain or "").strip().replace(".", " "),  # 域名中的点替换为空格
        (server or "").strip(),
    ]
    return " ".join(p for p in parts if p).lower()


def _ensure_training_data() -> None:
    """若训练 CSV 不存在，自动生成默认样本文件。"""
    if TRAINING_CSV.exists():
        return
    # 默认样本用于首次运行兜底，保证没有外部训练集时也能得到可用模型。
    logger.info("训练数据不存在，自动生成默认样本: %s", TRAINING_CSV)
    TRAINING_CSV.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(DEFAULT_SAMPLES, columns=["text", "label"])
    df.to_csv(TRAINING_CSV, index=False, encoding="utf-8")
    logger.info("默认训练样本已写入，共 %d 条", len(df))


# ══════════════════════════════════════════════════════════════
# 训练函数
# ══════════════════════════════════════════════════════════════

def train_model(save_path: Path = MODEL_PATH) -> Pipeline:
    """
    从 CSV 加载训练数据，训练 TF-IDF + LogisticRegression Pipeline，
    保存模型到 pkl 文件。

    Returns:
        训练好的 sklearn Pipeline 对象
    """
    _ensure_training_data()

    logger.info("加载训练数据: %s", TRAINING_CSV)
    df = pd.read_csv(TRAINING_CSV, encoding="utf-8")

    # 数据清洗：去除空行、标签不合法的行
    df = df.dropna(subset=["text", "label"])
    # 只保留系统支持的资产类别，避免脏标签进入模型训练。
    df = df[df["label"].isin(CATEGORIES)]
    df["text"] = df["text"].astype(str).str.strip()

    if len(df) < 5:
        raise ValueError(f"训练样本不足（当前 {len(df)} 条），至少需要 5 条")

    X = df["text"].tolist()
    y = df["label"].tolist()

    logger.info("训练样本共 %d 条，类别分布:\n%s", len(df), df["label"].value_counts().to_string())

    # 构建 Pipeline：TF-IDF 向量化 + 逻辑回归分类
    # Pipeline 将文本向量化和分类器串联起来，预测时可以直接输入原始文本。
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),      # 使用 unigram + bigram
            max_features=5000,       # 最多保留 5000 个特征
            sublinear_tf=True,       # 使用 log(tf) 平滑
            min_df=1,                # 最低文档频率为 1
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            C=1.0,
            solver="lbfgs",
            multi_class="auto",
        )),
    ])

    # 有足够样本时做 train/test split，否则全量训练
    if len(df) >= 10:
        # 样本足够时保留测试集，便于输出分类报告检查模型效果。
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
        )
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)
        report = classification_report(y_test, y_pred, zero_division=0)
        logger.info("模型评估报告:\n%s", report)
    else:
        pipeline.fit(X, y)
        logger.info("样本数不足10条，跳过评估，直接全量训练")

    # 保存模型
    # 模型保存为 pkl 文件，后续启动时无需重复训练。
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "wb") as f:
        pickle.dump(pipeline, f)
    logger.info("模型已保存: %s", save_path)

    return pipeline


# ══════════════════════════════════════════════════════════════
# 加载 & 预测
# ══════════════════════════════════════════════════════════════

# 模块级缓存，避免每次预测都重新 load pkl
_pipeline_cache: Optional[Pipeline] = None


def load_model(model_path: Path = MODEL_PATH) -> Pipeline:
    """
    加载已保存的模型。若模型文件不存在则自动训练后返回。

    Returns:
        sklearn Pipeline 对象
    """
    global _pipeline_cache

    if _pipeline_cache is not None:
        # 模块级缓存避免每次预测都从磁盘读取模型。
        return _pipeline_cache

    if not model_path.exists():
        # 模型缺失时自动训练，降低首次部署的使用门槛。
        logger.info("模型文件不存在，开始自动训练...")
        _pipeline_cache = train_model(model_path)
    else:
        logger.info("加载已有模型: %s", model_path)
        with open(model_path, "rb") as f:
            _pipeline_cache = pickle.load(f)

    return _pipeline_cache


def predict(
    title:  Optional[str] = None,
    domain: Optional[str] = None,
    server: Optional[str] = None,
) -> dict:
    """
    对单条资产进行分类预测。

    Args:
        title  : 页面标题
        domain : 子域名
        server : Server 响应头

    Returns:
        {
            "asset_type":  "admin_panel",   # 预测类别
            "confidence":  0.87,            # 该类别置信度（最大概率）
            "all_probs":   {"web_site": 0.05, "admin_panel": 0.87, ...}
        }
    """
    pipeline = load_model()
    # 将资产指纹字段拼成模型输入文本。
    text     = build_text(title, domain, server)

    if not text.strip():
        # 三个字段全为空，无法分类
        return {
            "asset_type": "unknown",
            "confidence": 0.0,
            "all_probs":  {cat: 0.0 for cat in CATEGORIES},
        }

    try:
        # predict_proba 返回各资产类别概率，最大概率对应最终分类结果。
        proba      = pipeline.predict_proba([text])[0]
        classes    = pipeline.classes_
        all_probs  = {str(cls): round(float(p), 4) for cls, p in zip(classes, proba)}
        best_idx   = int(proba.argmax())
        asset_type = str(classes[best_idx])
        confidence = round(float(proba[best_idx]), 4)

        logger.debug("分类结果: text='%s...' -> %s (%.2f)", text[:40], asset_type, confidence)

        return {
            "asset_type": asset_type,
            "confidence": confidence,
            "all_probs":  all_probs,
        }

    except Exception as exc:
        logger.error("预测失败: %s | text='%s'", exc, text[:80])
        return {
            "asset_type": "unknown",
            "confidence": 0.0,
            "all_probs":  {cat: 0.0 for cat in CATEGORIES},
        }


def retrain_model() -> dict:
    """
    重新训练模型（清除缓存，强制从 CSV 重新训练）。

    Returns:
        {"status": "ok", "message": "..."}
    """
    global _pipeline_cache
    # 清除缓存后重新训练，保证新模型能在当前进程内立即生效。
    _pipeline_cache = None  # 清除缓存
    try:
        train_model()
        return {"status": "ok", "message": "模型重新训练完成"}
    except Exception as exc:
        logger.error("重训练失败: %s", exc)
        return {"status": "error", "message": str(exc)}
