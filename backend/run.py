# 文件作用：Flask 后端应用启动入口，负责创建应用、加载配置、注册路由和初始化数据库。
"""
Unified Flask application entry for the asset discovery system.
"""

import logging
import os
import sys
from datetime import timedelta
from pathlib import Path

from flask import Flask, jsonify, request, session
from flask_cors import CORS

# Allow direct execution via `python backend/run.py` in addition to
# module execution (`python -m backend.run`).
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.core.config import load_project_env
from backend.app.core.db import init_db
from backend.app.api import api_bp

load_project_env()


def configure_logging() -> logging.Logger:
    """Configure process-wide logging once."""
    root_logger = logging.getLogger()
    # 避免重复导入或测试执行时反复添加文件日志处理器。
    has_file_handler = any(
        isinstance(handler, logging.FileHandler)
        and getattr(handler, "baseFilename", "").endswith("asset_discovery.log")
        for handler in root_logger.handlers
    )
    if not has_file_handler:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler("asset_discovery.log", encoding="utf-8"),
            ],
        )
    return logging.getLogger(__name__)


logger = configure_logging()


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    # 允许前端携带 Cookie 调用后端接口，保证 session 登录态可用。
    CORS(app, supports_credentials=True)

    app.config.update(
        # 数据库、认证和会话配置优先从环境变量读取，便于本地、容器和测试环境切换。
        SECRET_KEY=os.getenv("SECRET_KEY", "asset-discovery-dev-secret"),
        MYSQL_HOST=os.getenv("MYSQL_HOST", "localhost"),
        MYSQL_PORT=int(os.getenv("MYSQL_PORT", "3307")),
        MYSQL_USER=os.getenv("MYSQL_USER", "root"),
        MYSQL_PASSWORD=os.getenv("MYSQL_PASSWORD", "password"),
        MYSQL_DATABASE=os.getenv("MYSQL_DATABASE", "asset_discovery"),
        AUTH_USERNAME=os.getenv("AUTH_USERNAME", "admin"),
        AUTH_PASSWORD=os.getenv("AUTH_PASSWORD", "Admin@123456"),
        AUTH_PASSWORD_HASH=os.getenv("AUTH_PASSWORD_HASH", ""),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )

    if test_config:
        # 单元测试可传入覆盖配置，避免影响真实运行环境。
        app.config.update(test_config)

    # 所有业务接口统一挂载到 /api 前缀下。
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.before_request
    def require_login():
        # 非 API 请求和 OPTIONS 预检请求不做登录拦截。
        if request.method == "OPTIONS" or not request.path.startswith("/api"):
            return None

        # 登录和注册接口必须允许匿名访问。
        if request.path in {"/api/auth/login", "/api/auth/register"}:
            return None

        # 其他接口统一依赖 session 中的 authenticated 标记判断登录态。
        if session.get("authenticated"):
            return None

        return jsonify({"error": "未登录或登录已过期", "code": "AUTH_REQUIRED"}), 401

    @app.route("/", methods=["GET"])
    def index():
        # 根路径返回服务摘要，方便开发阶段确认后端是否启动成功。
        return {
            "service": "Asset Discovery & Risk Assessment System",
            "version": "4.0.0",
            "api_docs": {
                "POST /api/scan": "启动多源资产扫描任务",
                "GET /api/assets": "查询全部资产",
                "GET /api/assets/<id>": "查询单条资产",
                "DELETE /api/assets/<id>": "删除单条资产",
                "POST /api/analyze/<id>": "分析单条资产",
                "POST /api/analyze/all": "批量分析全部资产",
                "GET /api/assets/<id>/analysis": "查询资产分析结果",
                "GET /api/assets/<id>/tags": "查询资产标签",
                "POST /api/risk/assess/<id>": "评估单条资产风险",
                "POST /api/risk/assess/all": "批量评估全部资产风险",
                "GET /api/risk/<id>": "查询资产风险详情",
                "GET /api/risks": "分页查询风险列表",
                "GET /api/dashboard/stats": "查询仪表盘统计信息",
            },
        }

    return app


def initialize_application(app: Flask) -> None:
    """Initialize database schema and warm up runtime dependencies."""
    logger.info("初始化数据库及业务表...")
    init_db(app.config)


app = create_app()


if __name__ == "__main__":
    # 直接运行后端入口时，先初始化数据库再启动 Flask 开发服务。
    initialize_application(app)
    logger.info("服务启动，监听 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
