import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from backend.app.services.discovery.orchestrator import run_multi_source_scan


@pytest.fixture
def client():
    with (
        patch("backend.app.core.db._pool"),
        patch("backend.app.core.db.init_db", return_value=None),
        patch("backend.app.core.db.init_analysis_tables", return_value=None),
        patch("backend.app.core.db.init_risk_table", return_value=None),
    ):
        from backend.run import create_app

        app = create_app({"TESTING": True})
        with app.test_client() as test_client:
            with test_client.session_transaction() as session:
                session["authenticated"] = True
                session["username"] = "admin"
                session["display_name"] = "system-admin"
            yield test_client


def test_run_multi_source_scan_merges_sources_without_network():
    body = {
        "domain": "example.com",
        "enable_ct": False,
        "enable_crawl": False,
        "enable_js_extract": False,
        "enable_certificate_parse": False,
        "passive_dns_records": [
            {"hostname": "api.example.com", "ips": ["1.1.1.1"]},
        ],
        "search_results": [
            {"domain": "dev.example.com", "url": "https://dev.example.com/login"},
        ],
        "icp_records": ["record.example.com", "www.example.com"],
        "cloud_assets": [
            {"domain": "cdn.example.com", "ip": "2.2.2.2", "provider": "aliyun"},
        ],
    }

    mock_probe = [
        SimpleNamespace(
            subdomain="api.example.com",
            ip="1.1.1.1",
            port=443,
            scheme="https",
            status_code=200,
            title="API",
            server="nginx",
            success=True,
            error=None,
            url="https://api.example.com",
        ),
        SimpleNamespace(
            subdomain="cdn.example.com",
            ip="2.2.2.2",
            port=443,
            scheme="https",
            status_code=200,
            title="CDN",
            server="nginx",
            success=True,
            error=None,
            url="https://cdn.example.com",
        ),
    ]

    with patch(
        "backend.app.services.discovery.orchestrator.discover_subdomains_list",
        return_value=[{"subdomain": "www.example.com", "ips": ["3.3.3.3"]}],
    ), patch("backend.app.services.discovery.orchestrator.probe_targets", return_value=mock_probe):
        result = run_multi_source_scan(body)

    assert result["mode"] == "hybrid"
    assert result["subdomains_found"] >= 4
    assert result["probes_total"] == 2
    assert "active_dns" in result["discovery_summary"]["source_stats"]
    assert "passive_dns" in result["discovery_summary"]["source_stats"]
    assert "search_engine" in result["discovery_summary"]["source_stats"]
    assert "cloud_api" in result["discovery_summary"]["source_stats"]
    assert result["passive_summary"]["targets_found"] >= 3
    assert result["active_summary"]["targets_found"] == 1


def test_run_multi_source_scan_passive_mode_skips_active_discovery():
    body = {
        "domain": "example.com",
        "mode": "passive",
        "enable_ct": False,
        "enable_search": False,
        "enable_icp": False,
        "enable_cloud": False,
        "enable_crawl": False,
        "enable_js_extract": False,
        "enable_certificate_parse": False,
        "passive_dns_records": [
            {"hostname": "api.example.com", "ips": ["1.1.1.1"]},
        ],
    }

    with patch("backend.app.services.discovery.orchestrator.discover_subdomains_list") as mock_active, patch(
        "backend.app.services.discovery.orchestrator.probe_targets",
        return_value=[],
    ):
        result = run_multi_source_scan(body)

    mock_active.assert_not_called()
    assert result["mode"] == "passive"
    assert result["active_summary"]["targets_found"] == 0
    assert "active_dns" not in result["discovery_summary"]["source_stats"]
    assert result["passive_summary"]["targets_found"] == 1


def test_scan_route_returns_layered_scan_fields(client):
    payload = {
        "domain": "example.com",
        "mode": "hybrid",
        "subdomains_found": 2,
        "probes_total": 1,
        "results": [
            {
                "subdomain": "www.example.com",
                "ip": "1.1.1.1",
                "port": 443,
                "scheme": "https",
                "status_code": 200,
                "title": "Home",
                "server": "nginx",
                "success": True,
                "error": None,
                "sources": ["active_dns", "ct_log"],
                "urls": ["https://www.example.com"],
                "js_endpoints": ["/api/users"],
                "cert_subject": "CN=www.example.com",
                "cert_issuer": "CN=Test CA",
                "confidence_score": 60,
                "validation_status": "alive",
            }
        ],
        "validated_results": [
            {
                "subdomain": "www.example.com",
                "ip": "1.1.1.1",
                "port": 443,
                "scheme": "https",
                "status_code": 200,
                "title": "Home",
                "server": "nginx",
                "success": True,
                "error": None,
            }
        ],
        "discovery_summary": {
            "source_stats": {"active_dns": 1, "ct_log": 1},
            "enriched_targets": 1,
            "targets_with_ip": 1,
            "mode": "hybrid",
        },
        "passive_summary": {"targets_found": 1, "source_stats": {"ct_log": 1}},
        "active_summary": {"targets_found": 1, "source_stats": {"active_dns": 1}},
        "validation_summary": {"resolved_targets": 1, "alive_results": 1, "probes_total": 1, "enriched_targets": 1},
        "passive_target_details": [{"subdomain": "www.example.com", "sources": ["ct_log"]}],
        "active_target_details": [{"subdomain": "www.example.com", "sources": ["active_dns"]}],
        "target_details": [
            {
                "subdomain": "www.example.com",
                "ips": ["1.1.1.1"],
                "sources": ["active_dns", "ct_log"],
                "urls": ["https://www.example.com"],
                "evidence": ["dictionary subdomain enumeration"],
                "js_endpoints": ["/api/users"],
                "cert_subject": "CN=www.example.com",
                "cert_issuer": "CN=Test CA",
                "cert_sans": ["www.example.com"],
                "confidence_score": 60,
                "validation_status": "alive",
            }
        ],
    }

    with (
        patch("backend.app.api.scan_routes.run_multi_source_scan", return_value=payload),
        patch("backend.app.api.scan_routes.persist_scan_result", return_value={"run_id": 88, "discovery_records_saved": 2, "validation_records_saved": 1}),
        patch("backend.app.api.scan_routes.upsert_asset", return_value=1),
    ):
        response = client.post(
            "/api/scan",
            data=json.dumps({"domain": "example.com", "mode": "hybrid"}),
            content_type="application/json",
        )

    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["mode"] == "hybrid"
    assert "discovery_summary" in data
    assert "passive_summary" in data
    assert "active_summary" in data
    assert "validation_summary" in data
    assert "passive_target_details" in data
    assert "active_target_details" in data
    assert "target_details" in data
    assert data["run_id"] == 88
    assert data["discovery_records_saved"] == 2
    assert data["validation_records_saved"] == 1
    assert data["saved"] == 1


def test_run_multi_source_scan_uses_public_passive_dns_api_text_response():
    class MockResponse:
        status_code = 200
        text = "api.example.com,1.1.1.1\nmail.example.com,2.2.2.2"
        headers = {"Content-Type": "text/plain"}

        def raise_for_status(self):
            return None

        def json(self):
            raise ValueError("not json")

    body = {
        "domain": "example.com",
        "mode": "passive",
        "enable_ct": False,
        "enable_search": False,
        "enable_icp": False,
        "enable_cloud": False,
        "enable_crawl": False,
        "enable_js_extract": False,
        "enable_certificate_parse": False,
    }

    with patch("backend.app.services.discovery.orchestrator.requests.get", return_value=MockResponse()) as mock_get, patch(
        "backend.app.services.discovery.orchestrator.probe_targets",
        return_value=[],
    ):
        result = run_multi_source_scan(body)

    assert result["subdomains_found"] == 2
    assert result["discovery_summary"]["source_stats"]["passive_dns"] == 2
    assert "api.hackertarget.com/hostsearch" in mock_get.call_args[0][0]
