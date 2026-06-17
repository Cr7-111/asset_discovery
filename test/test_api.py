"""API tests for the unified Flask application."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture
def raw_client():
    with (
        patch("backend.app.core.db._pool", new=MagicMock()),
        patch("backend.app.core.db.init_db", return_value=None),
        patch("backend.app.core.db.init_analysis_tables", return_value=None),
        patch("backend.app.core.db.init_risk_table", return_value=None),
    ):
        from backend.run import create_app

        app = create_app({"TESTING": True})
        with app.test_client() as test_client:
            yield test_client


@pytest.fixture
def client(raw_client):
    with raw_client.session_transaction() as session:
        session["authenticated"] = True
        session["user_id"] = 1
        session["username"] = "admin"
        session["display_name"] = "系统管理员"
        session["role"] = "admin"
    yield raw_client


class TestHealthAndIndex:
    def test_index_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "service" in data
        assert "version" in data

    def test_index_contains_api_docs(self, client):
        response = client.get("/")
        data = json.loads(response.data)
        assert "api_docs" in data


class TestAuthAPI:
    @patch("backend.app.api.auth_routes.update_user_last_login", return_value=None)
    @patch(
        "backend.app.api.auth_routes.fetch_user_by_username",
        return_value={
            "id": 1,
            "username": "admin",
            "password_hash": generate_password_hash("Admin@123456"),
            "display_name": "System Admin",
            "role": "admin",
            "is_active": 1,
        },
    )
    def test_login_success(self, _mock_fetch_user, _mock_update_login, raw_client):
        response = raw_client.post(
            "/api/auth/login",
            data=json.dumps({"username": "admin", "password": "Admin@123456"}),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["user"]["username"] == "admin"
        assert data["user"]["role"] == "admin"

    @patch("backend.app.api.auth_routes.update_user_last_login", return_value=None)
    @patch(
        "backend.app.api.auth_routes.fetch_user_by_username",
        return_value={
            "id": 1,
            "username": "admin",
            "password_hash": generate_password_hash("Admin@123456"),
            "display_name": "System Admin",
            "role": "admin",
            "is_active": 1,
        },
    )
    def test_login_wrong_password_fails(self, _mock_fetch_user, _mock_update_login, raw_client):
        response = raw_client.post(
            "/api/auth/login",
            data=json.dumps({"username": "admin", "password": "wrong-password"}),
            content_type="application/json",
        )
        assert response.status_code == 401
        _mock_update_login.assert_not_called()

    @patch("backend.app.api.auth_routes.create_user", return_value=10)
    @patch("backend.app.api.auth_routes.fetch_user_by_username", return_value=None)
    def test_register_success_hashes_password(self, _mock_fetch_user, mock_create_user, raw_client):
        response = raw_client.post(
            "/api/auth/register",
            data=json.dumps(
                {
                    "username": "alice",
                    "display_name": "Alice",
                    "password": "secret123",
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data["user"]["username"] == "alice"

        kwargs = mock_create_user.call_args.kwargs
        assert kwargs["password_hash"] != "secret123"
        assert check_password_hash(kwargs["password_hash"], "secret123")

    @patch("backend.app.api.auth_routes.fetch_user_by_username", return_value={"id": 10, "username": "alice"})
    def test_register_duplicate_username_fails(self, _mock_fetch_user, raw_client):
        response = raw_client.post(
            "/api/auth/register",
            data=json.dumps({"username": "alice", "password": "secret123"}),
            content_type="application/json",
        )
        assert response.status_code == 409

    def test_protected_api_requires_login(self, raw_client):
        response = raw_client.get("/api/assets")
        assert response.status_code == 401


class TestAdminAPI:
    def test_admin_api_requires_admin_role(self, raw_client):
        with raw_client.session_transaction() as session:
            session["authenticated"] = True
            session["user_id"] = 2
            session["username"] = "bob"
            session["role"] = "user"

        response = raw_client.get("/api/admin/users")
        assert response.status_code == 403

    @patch(
        "backend.app.api.admin_routes.fetch_all_users",
        return_value=[
            {"id": 1, "username": "admin", "display_name": "System Admin", "role": "admin", "is_active": 1},
            {"id": 2, "username": "alice", "display_name": "Alice", "role": "user", "is_active": 1},
        ],
    )
    def test_admin_list_users(self, _mock_fetch, client):
        response = client.get("/api/admin/users")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["total"] == 2
        assert data["users"][0]["role"] == "admin"

    @patch(
        "backend.app.api.admin_routes.fetch_user_by_id",
        return_value={"id": 3, "username": "analyst", "display_name": "Analyst", "role": "user", "is_active": 1},
    )
    @patch("backend.app.api.admin_routes.create_user", return_value=3)
    @patch("backend.app.api.admin_routes.fetch_user_by_username", return_value=None)
    def test_admin_create_user(self, _mock_fetch_name, mock_create, _mock_fetch_id, client):
        response = client.post(
            "/api/admin/users",
            data=json.dumps(
                {
                    "username": "analyst",
                    "display_name": "Analyst",
                    "password": "secret123",
                    "role": "user",
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 201
        kwargs = mock_create.call_args.kwargs
        assert kwargs["role"] == "user"
        assert check_password_hash(kwargs["password_hash"], "secret123")

    @patch(
        "backend.app.api.admin_routes.fetch_user_by_id",
        return_value={"id": 1, "username": "admin", "display_name": "System Admin", "role": "admin", "is_active": 1},
    )
    def test_admin_cannot_demote_self(self, _mock_fetch, client):
        response = client.patch(
            "/api/admin/users/1/role",
            data=json.dumps({"role": "user"}),
            content_type="application/json",
        )
        assert response.status_code == 400

    @patch("backend.app.api.admin_routes.delete_user_by_id", return_value=1)
    @patch(
        "backend.app.api.admin_routes.fetch_user_by_id",
        return_value={"id": 2, "username": "alice", "display_name": "Alice", "role": "user", "is_active": 1},
    )
    def test_admin_delete_user(self, _mock_fetch, mock_delete, client):
        response = client.delete("/api/admin/users/2")
        assert response.status_code == 200
        mock_delete.assert_called_once_with(2)


class TestAssetsAPI:
    @patch(
        "backend.app.api.asset_routes.fetch_all_assets",
        return_value=[
            {
                "asset_id": 1,
                "domain": "www.test.com",
                "ip": "1.2.3.4",
                "port": 80,
                "status_code": 200,
                "title": "Test",
                "server": "nginx",
                "first_seen": "2024-01-01",
                "last_seen": "2024-06-01",
            }
        ],
    )
    def test_get_assets_returns_list(self, _mock_fetch, client):
        response = client.get("/api/assets")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "assets" in data
        assert data["total"] >= 0

    @patch("backend.app.api.asset_routes.fetch_asset_by_id", return_value=None)
    def test_get_asset_not_found(self, _mock_fetch, client):
        response = client.get("/api/assets/99999")
        assert response.status_code == 404

    @patch(
        "backend.app.api.asset_routes.fetch_asset_by_id",
        return_value={
            "asset_id": 1,
            "domain": "admin.test.com",
            "ip": "1.2.3.4",
            "port": 80,
            "status_code": 200,
            "title": "Admin",
            "server": "nginx",
            "first_seen": "2024-01-01",
            "last_seen": "2024-06-01",
        },
    )
    def test_get_asset_found(self, _mock_fetch, client):
        response = client.get("/api/assets/1")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["asset_id"] == 1

    def test_scan_missing_domain(self, client):
        response = client.post(
            "/api/scan",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_scan_route_applies_lab_defaults_for_corp_demo(self, client):
        captured = {}

        def fake_run_multi_source_scan(body):
            captured.update(body)
            return {
                "mode": "hybrid",
                "target_details": [],
                "results": [],
                "validated_results": [],
                "discovery_summary": {},
                "passive_summary": {},
                "active_summary": {},
                "validation_summary": {},
                "passive_target_details": [],
                "active_target_details": [],
            }

        with (
            patch("backend.app.api.scan_routes.run_multi_source_scan", side_effect=fake_run_multi_source_scan),
            patch(
                "backend.app.api.scan_routes.persist_scan_result",
                return_value={"run_id": 1, "discovery_records_saved": 0, "validation_records_saved": 0},
            ),
        ):
            response = client.post(
                "/api/scan",
                data=json.dumps({"domain": "corp-demo.test", "mode": "hybrid"}),
                content_type="application/json",
            )

        assert response.status_code == 200
        assert captured["nameservers"] == ["127.0.0.1"]
        assert captured["passive_dns_api_url"] == "http://intel.corp-demo.test/hostsearch/?q={domain}"
        assert captured["search_engine_url_template"] == "http://search.corp-demo.test/search?q={query}"
        assert captured["connect_overrides"]["www.corp-demo.test"] == "127.0.0.1"
        assert captured["traffic_log_path"].endswith(os.path.join("lab", "data", "traffic", "demo_traffic.log"))


class TestRiskAPI:
    @patch("backend.app.api.risk_routes.get_risk_detail", return_value=None)
    def test_get_risk_not_assessed(self, _mock_get, client):
        response = client.get("/api/risk/1")
        assert response.status_code == 404

    @patch(
        "backend.app.api.risk_routes.get_risk_detail",
        return_value={
            "id": 1,
            "asset_id": 1,
            "risk_score": 75,
            "risk_level": "high",
            "score_detail": [],
            "suggestions": "建议1",
            "assessed_at": "2024-06-01",
            "domain": "admin.test.com",
            "ip": "1.2.3.4",
            "port": 80,
            "title": "Admin",
            "server": "nginx",
        },
    )
    def test_get_risk_found(self, _mock_get, client):
        response = client.get("/api/risk/1")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["risk_score"] == 75
        assert data["risk_level"] == "high"

    @patch(
        "backend.app.api.risk_routes.get_risk_list",
        return_value={
            "total": 5,
            "page": 1,
            "per_page": 20,
            "items": [
                {
                    "asset_id": 1,
                    "risk_score": 80,
                    "risk_level": "critical",
                    "domain": "admin.test.com",
                }
            ],
        },
    )
    def test_list_risks(self, _mock_list, client):
        response = client.get("/api/risks")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "total" in data
        assert "items" in data
        assert "page" in data
        assert "per_page" in data

    @patch(
        "backend.app.api.risk_routes.get_risk_list",
        return_value={
            "total": 2,
            "page": 1,
            "per_page": 20,
            "items": [{"risk_score": 80, "risk_level": "critical", "domain": "x.com"}],
        },
    )
    def test_list_risks_with_level_filter(self, _mock_list, client):
        response = client.get("/api/risks?risk_level=critical")
        assert response.status_code == 200

    @patch(
        "backend.app.api.risk_routes.get_dashboard_stats",
        return_value={
            "total_assets": 100,
            "assessed_assets": 80,
            "avg_score": 42.5,
            "level_counts": {"low": 20, "medium": 30, "high": 20, "critical": 10},
            "type_counts": {"web_site": 40},
        },
    )
    def test_dashboard_stats(self, _mock_stats, client):
        response = client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "total_assets" in data
        assert "level_counts" in data
        assert "avg_score" in data


class TestAnalysisAPI:
    @patch("backend.app.api.analysis_routes.get_asset_analysis", return_value=None)
    def test_get_analysis_not_found(self, _mock_get, client):
        response = client.get("/api/assets/1/analysis")
        assert response.status_code == 404

    @patch(
        "backend.app.api.analysis_routes.get_asset_tags",
        return_value=[
            {
                "id": 1,
                "asset_id": 1,
                "tag_name": "admin_panel",
                "tag_source": "rule_engine",
                "confidence": 1.0,
                "matched_rule": "命中管理后台规则",
                "created_at": "2024-06-01",
            }
        ],
    )
    def test_get_tags_found(self, _mock_tags, client):
        response = client.get("/api/assets/1/tags")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "tags" in data
        assert "total" in data
        assert data["total"] == 1


class TestMLAnalysisAPI:
    @patch(
        "backend.app.api.ml_routes.analyze_asset_with_ml",
        return_value={
            "status": "ok",
            "asset_id": 1,
            "component": "Apache Tomcat",
            "component_confidence": 95,
            "severity_counts": {"LOW": 0, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 1},
            "ml_risk_score": 88,
            "ml_risk_level": "critical",
            "matched_cves": [],
            "weak_points": ["远程代码执行"],
        },
    )
    def test_generate_ml_analysis(self, _mock_analyze, client):
        response = client.post("/api/ml/analyze/1")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["component"] == "Apache Tomcat"
        assert data["ml_risk_level"] == "critical"

    @patch(
        "backend.app.api.ml_routes.get_saved_ml_analysis",
        return_value={
            "asset_id": 1,
            "component": "Apache Tomcat",
            "component_confidence": 95,
            "ml_risk_score": 88,
            "ml_risk_level": "critical",
            "matched_cves": [],
        },
    )
    def test_get_saved_ml_analysis(self, _mock_get, client):
        response = client.get("/api/ml/analyze/1")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["asset_id"] == 1
        assert data["ml_risk_score"] == 88
