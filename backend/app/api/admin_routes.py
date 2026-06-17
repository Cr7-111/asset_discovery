# 文件作用：提供管理员用户管理接口，包括用户查询、创建、编辑、启停、角色调整和删除。
"""Admin-only user management routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request, session
from werkzeug.security import generate_password_hash

from backend.app.api.common import logger, require_admin, validate_register_payload
from backend.app.services.auth_service import (
    create_user,
    delete_user_by_id,
    fetch_all_users,
    fetch_user_by_id,
    fetch_user_by_username,
    update_user_profile,
)

admin_bp = Blueprint("admin_api", __name__)

VALID_ROLES = {"user", "admin"}


@admin_bp.route("/admin/users", methods=["GET"])
@require_admin
def list_users():
    try:
        # 管理员查看系统内全部用户账号，用于用户管理页面展示。
        users = fetch_all_users()
        return jsonify({"total": len(users), "users": users}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("List users failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@admin_bp.route("/admin/users", methods=["POST"])
@require_admin
def create_managed_user():
    # 管理员创建用户时允许指定显示名称、头像和角色。
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    display_name = (body.get("display_name") or username).strip()
    avatar_url = str(body.get("avatar_url") or "")
    role = (body.get("role") or "user").strip()

    error = validate_register_payload(username, password)
    if error:
        return jsonify({"error": error}), 400
    if role not in VALID_ROLES:
        # 角色只允许普通用户和管理员两类，避免写入未知权限值。
        return jsonify({"error": "Invalid role"}), 400
    if fetch_user_by_username(username):
        return jsonify({"error": "Username already exists"}), 409

    try:
        # 管理员创建用户同样使用密码哈希，不保存明文密码。
        user_id = create_user(
            username=username,
            password_hash=generate_password_hash(password),
            display_name=display_name,
            role=role,
            avatar_url=avatar_url,
        )
        user = fetch_user_by_id(user_id) or {
            "id": user_id,
            "username": username,
            "display_name": display_name,
            "avatar_url": avatar_url,
            "role": role,
            "is_active": 1,
        }
        logger.info("Admin created user: operator=%s username=%s role=%s", session.get("username"), username, role)
        return jsonify({"message": "User created", "user": user}), 201
    except Exception as exc:  # noqa: BLE001
        logger.error("Create managed user failed [username=%s]: %s", username, exc)
        return jsonify({"error": str(exc)}), 500


@admin_bp.route("/admin/users/<int:user_id>", methods=["PUT"])
@require_admin
def update_managed_user(user_id: int):
    # 综合编辑接口，可同时更新显示名称、头像、角色和账号状态。
    body = request.get_json(silent=True) or {}
    user = fetch_user_by_id(user_id)
    if user is None:
        return jsonify({"error": f"user_id={user_id} not found"}), 404

    display_name = body.get("display_name")
    avatar_url = body.get("avatar_url")
    role = body.get("role")
    is_active = body.get("is_active")

    if role is not None:
        role = str(role).strip()
        if role not in VALID_ROLES:
            return jsonify({"error": "Invalid role"}), 400
        # 角色变更前先检查是否会导致系统没有可用管理员。
        guard = _guard_admin_change(user, new_role=role)
        if guard:
            return guard

    if is_active is not None:
        is_active = bool(is_active)
        # 禁用账号前同样检查管理员保护规则。
        guard = _guard_admin_change(user, new_is_active=is_active)
        if guard:
            return guard

    try:
        update_user_profile(
            user_id,
            display_name=str(display_name).strip() if display_name is not None else None,
            role=role,
            is_active=is_active,
            avatar_url=str(avatar_url) if avatar_url is not None else None,
        )
        updated = fetch_user_by_id(user_id)
        return jsonify({"message": "User updated", "user": updated}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Update managed user failed [id=%d]: %s", user_id, exc)
        return jsonify({"error": str(exc)}), 500


@admin_bp.route("/admin/users/<int:user_id>/role", methods=["PATCH"])
@require_admin
def update_managed_user_role(user_id: int):
    # 独立角色更新接口，用于前端角色下拉框快速保存。
    body = request.get_json(silent=True) or {}
    role = (body.get("role") or "").strip()
    if role not in VALID_ROLES:
        return jsonify({"error": "Invalid role"}), 400

    user = fetch_user_by_id(user_id)
    if user is None:
        return jsonify({"error": f"user_id={user_id} not found"}), 404

    guard = _guard_admin_change(user, new_role=role)
    if guard:
        return guard

    try:
        update_user_profile(user_id, role=role)
        return jsonify({"message": "Role updated", "user": fetch_user_by_id(user_id)}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Update user role failed [id=%d]: %s", user_id, exc)
        return jsonify({"error": str(exc)}), 500


@admin_bp.route("/admin/users/<int:user_id>/status", methods=["PATCH"])
@require_admin
def update_managed_user_status(user_id: int):
    # 独立状态更新接口，用于管理员启用或禁用用户。
    body = request.get_json(silent=True) or {}
    if "is_active" not in body:
        return jsonify({"error": "missing required parameter 'is_active'"}), 400

    user = fetch_user_by_id(user_id)
    if user is None:
        return jsonify({"error": f"user_id={user_id} not found"}), 404

    is_active = bool(body.get("is_active"))
    guard = _guard_admin_change(user, new_is_active=is_active)
    if guard:
        return guard

    try:
        update_user_profile(user_id, is_active=is_active)
        return jsonify({"message": "Status updated", "user": fetch_user_by_id(user_id)}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Update user status failed [id=%d]: %s", user_id, exc)
        return jsonify({"error": str(exc)}), 500


@admin_bp.route("/admin/users/<int:user_id>", methods=["DELETE"])
@require_admin
def delete_managed_user(user_id: int):
    # 删除前先读取用户，便于执行当前用户和最后管理员保护。
    user = fetch_user_by_id(user_id)
    if user is None:
        return jsonify({"error": f"user_id={user_id} not found"}), 404

    if _is_current_user(user):
        return jsonify({"error": "Current user cannot be deleted"}), 400
    if _is_active_admin(user) and _active_admin_count() <= 1:
        return jsonify({"error": "At least one active admin is required"}), 400

    try:
        rows = delete_user_by_id(user_id)
        if rows == 0:
            return jsonify({"error": f"user_id={user_id} not found"}), 404
        logger.info("Admin deleted user: operator=%s user_id=%d", session.get("username"), user_id)
        return jsonify({"message": f"deleted user_id={user_id}"}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error("Delete managed user failed [id=%d]: %s", user_id, exc)
        return jsonify({"error": str(exc)}), 500


def _guard_admin_change(user: dict, *, new_role: str | None = None, new_is_active: bool | None = None):
    # 防止管理员误操作导致自己失去权限或系统没有可用管理员。
    if _is_current_user(user):
        if new_role is not None and new_role != "admin":
            return jsonify({"error": "Current admin cannot change own role"}), 400
        if new_is_active is False:
            return jsonify({"error": "Current user cannot be disabled"}), 400

    would_remove_active_admin = _is_active_admin(user) and (
        (new_role is not None and new_role != "admin") or new_is_active is False
    )
    if would_remove_active_admin and _active_admin_count() <= 1:
        return jsonify({"error": "At least one active admin is required"}), 400
    return None


def _active_admin_count() -> int:
    # 统计当前仍处于启用状态的管理员数量。
    return sum(1 for user in fetch_all_users() if _is_active_admin(user))


def _is_current_user(user: dict) -> bool:
    # 判断目标用户是否为当前登录用户。
    return int(user.get("id") or 0) == int(session.get("user_id") or 0)


def _is_active_admin(user: dict) -> bool:
    # 有管理员角色且账号启用，才算有效管理员。
    return user.get("role") == "admin" and bool(user.get("is_active"))
