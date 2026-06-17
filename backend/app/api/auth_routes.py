# 文件作用：提供用户注册、登录、退出、当前用户信息和头像更新等认证接口。
"""Auth-related API routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request, session
# Werkzeug 会在生成密码哈希时自动加入随机盐值，并在校验时完成哈希比对。
from werkzeug.security import check_password_hash, generate_password_hash

from backend.app.api.common import build_current_user, logger, login_user, public_user, validate_register_payload
from backend.app.services.auth_service import create_user, fetch_user_by_id, fetch_user_by_username, update_user_last_login, update_user_profile

auth_bp = Blueprint("auth_api", __name__)


@auth_bp.route("/auth/register", methods=["POST"])
def register():
    """Register a new user and establish a session."""
    # 读取注册表单数据，用户名需要去除首尾空格，密码保持原始输入用于哈希。
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    display_name = (body.get("display_name") or username).strip()
    avatar_url = str(body.get("avatar_url") or "")

    error = validate_register_payload(username, password)
    if error:
        # 注册参数不合法时直接返回 400，避免无效账号写入数据库。
        return jsonify({"error": error}), 400

    if fetch_user_by_username(username):
        # 用户名唯一，防止重复注册覆盖原账号。
        return jsonify({"error": "Username already exists"}), 409

    # 注册时不保存明文密码，而是生成带盐值的不可逆密码哈希。
    password_hash = generate_password_hash(password)
    user_id = create_user(
        username=username,
        password_hash=password_hash,
        display_name=display_name,
        role="user",
        avatar_url=avatar_url,
    )
    user = {
        # 组装最小用户信息用于建立登录会话，避免把 password_hash 返回给前端。
        "id": user_id,
        "username": username,
        "display_name": display_name,
        "avatar_url": avatar_url,
        "role": "user",
    }
    login_user(user)

    logger.info("Register success: username=%s", username)
    return jsonify({"message": "Register success", "user": public_user(user)}), 201


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    """Authenticate a user and establish a session."""
    # 登录接口只接收用户名和密码，不在前端传递角色等敏感字段。
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = fetch_user_by_username(username)
    if not user or not user.get("is_active"):
        # 用户不存在或被禁用时统一返回账号密码错误，避免暴露账号是否存在。
        logger.warning("Login failed: username=%s", username)
        return jsonify({"error": "Invalid username or password"}), 401

    if not check_password_hash(user["password_hash"], password):
        # check_password_hash 会从哈希串中取出盐值和算法参数，再与输入密码比对。
        logger.warning("Login failed: username=%s", username)
        return jsonify({"error": "Invalid username or password"}), 401

    login_user(user)
    # 登录成功后记录最后登录时间，用于用户管理页面展示和审计。
    update_user_last_login(user["id"])

    logger.info("Login success: username=%s", username)
    return jsonify({"message": "Login success", "user": build_current_user()})


@auth_bp.route("/auth/logout", methods=["POST"])
def logout():
    """Clear session information."""
    # 清空 Flask session 即可完成服务端登录态注销。
    username = session.get("username")
    session.clear()
    if username:
        logger.info("Logout: username=%s", username)
    return jsonify({"message": "Logged out"})


@auth_bp.route("/auth/me", methods=["GET"])
def get_current_user():
    """Return current authenticated user info."""
    # 所有依赖当前用户的接口都以 session["authenticated"] 作为登录态判断依据。
    if not session.get("authenticated"):
        return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401
    user_id = int(session.get("user_id") or 0)
    # 优先从数据库读取最新用户信息，保证头像、角色、状态变化能及时反映到前端。
    user = fetch_user_by_id(user_id) or build_current_user()
    return jsonify({"user": public_user(user)})


@auth_bp.route("/auth/me/avatar", methods=["PATCH"])
def update_current_user_avatar():
    """Update current user's avatar."""
    if not session.get("authenticated"):
        return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401

    body = request.get_json(silent=True) or {}
    avatar_url = str(body.get("avatar_url") or "")
    # 头像可能是 base64 字符串，这里限制长度，避免请求体过大影响会话和数据库。
    if len(avatar_url) > 100_000:
        return jsonify({"error": "Avatar image is too large"}), 400

    user_id = int(session.get("user_id") or 0)
    try:
        # 头像只写入数据库，不再写入 session，避免 Cookie 体积过大导致登录态异常。
        update_user_profile(user_id, avatar_url=avatar_url)
        user = fetch_user_by_id(user_id) or build_current_user()
        return jsonify({"message": "Avatar updated", "user": public_user(user)}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Update current user avatar failed [id=%d]: %s", user_id, exc)
        return jsonify({"error": str(exc)}), 500
