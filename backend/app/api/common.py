"""Shared API helpers used by split route modules."""

from __future__ import annotations

import logging
from functools import wraps
from pathlib import Path

from flask import jsonify, session

logger = logging.getLogger(__name__)

LAB_DOMAIN = "corp-demo.test"
LAB_HOST_MODE_OVERRIDES = {
    LAB_DOMAIN: "127.0.0.1",
    "www.corp-demo.test": "127.0.0.1",
    "api.corp-demo.test": "127.0.0.1",
    "admin.corp-demo.test": "127.0.0.1",
    "dev.corp-demo.test": "127.0.0.1",
    "docs.corp-demo.test": "127.0.0.1",
    "jenkins.corp-demo.test": "127.0.0.1",
    "manager.corp-demo.test": "127.0.0.1",
    "console.corp-demo.test": "127.0.0.1",
    "sso.corp-demo.test": "127.0.0.1",
    "secure.corp-demo.test": "127.0.0.1",
    "status.corp-demo.test": "127.0.0.1",
    "vpn-gw.corp-demo.test": "127.0.0.1",
    "search.corp-demo.test": "127.0.0.1",
    "intel.corp-demo.test": "127.0.0.1",
    "legacy.corp-demo.test": "127.0.0.1",
}


def build_current_user() -> dict:
    return {
        "id": session.get("user_id"),
        "username": session.get("username"),
        "display_name": session.get("display_name") or session.get("username"),
        "avatar_url": "",
        "role": session.get("role") or "user",
    }


def public_user(user: dict) -> dict:
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "display_name": user.get("display_name") or user.get("username"),
        "avatar_url": user.get("avatar_url") or "",
        "role": user.get("role") or "user",
    }


def login_user(user: dict) -> None:
    session.clear()
    session.permanent = True
    session["authenticated"] = True
    session["user_id"] = user.get("id")
    session["username"] = user.get("username")
    session["display_name"] = user.get("display_name") or user.get("username")
    session["role"] = user.get("role") or "user"


def require_admin(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Permission denied", "code": "ADMIN_REQUIRED"}), 403
        return view_func(*args, **kwargs)

    return wrapper


def is_lab_target(domain: str) -> bool:
    normalized = (domain or "").strip().lower().rstrip(".")
    return normalized == LAB_DOMAIN or normalized.endswith(f".{LAB_DOMAIN}")


def apply_lab_scan_defaults(body: dict) -> dict:
    domain = (body.get("domain") or "").strip().lower()
    if not is_lab_target(domain):
        return body

    lab_dir = Path(__file__).resolve().parents[3] / "lab"
    traffic_log_path = lab_dir / "data" / "traffic" / "demo_traffic.log"

    normalized = dict(body)
    normalized.setdefault("verify_ssl", False)
    normalized.setdefault("enable_ct", False)
    normalized.setdefault("enable_passive_dns", True)
    normalized.setdefault("enable_traffic_sniff", True)
    normalized.setdefault("enable_search", True)
    normalized.setdefault("enable_crawl", True)
    normalized.setdefault("enable_js_extract", True)
    normalized.setdefault("enable_certificate_parse", True)
    normalized.setdefault("passive_dns_api_url", "http://intel.corp-demo.test/hostsearch/?q={domain}")
    normalized.setdefault("search_engine_url_template", "http://search.corp-demo.test/search?q={query}")

    nameservers = normalized.get("nameservers")
    if not nameservers or nameservers == ["172.28.0.53"]:
        normalized["nameservers"] = ["127.0.0.1"]

    current_traffic_path = str(normalized.get("traffic_log_path") or "").strip()
    if traffic_log_path.exists() and (not current_traffic_path or current_traffic_path.startswith("/opt/lab-data/")):
        normalized["traffic_log_path"] = str(traffic_log_path)

    existing_overrides = normalized.get("connect_overrides") or {}
    if not isinstance(existing_overrides, dict):
        existing_overrides = {}
    normalized["connect_overrides"] = {
        **LAB_HOST_MODE_OVERRIDES,
        **existing_overrides,
    }
    return normalized


def validate_register_payload(username: str, password: str) -> str | None:
    if not username or not password:
        return "Username and password are required"
    if len(username) > 64:
        return "Username must be 64 characters or fewer"
    if len(password) < 6:
        return "Password must be at least 6 characters"
    return None
