from pathlib import Path

from backend.app.services.discovery.traffic import discover_from_traffic_data


def test_discover_from_structured_traffic_records():
    body = {
        "traffic_records": [
            {
                "timestamp": "2026-04-24T08:00:00",
                "dns_query": "api.example.com",
                "sni": "gateway.example.com",
                "http_host": "admin.example.com",
                "url": "https://admin.example.com/login",
                "referer": "https://portal.example.com/",
            }
        ]
    }

    result = discover_from_traffic_data(body, "example.com")
    hosts = {item["hostname"] for item in result}

    assert "api.example.com" in hosts
    assert "gateway.example.com" in hosts
    assert "admin.example.com" in hosts
    assert "portal.example.com" in hosts


def test_discover_from_log_text_and_file():
    log_path = Path("test_traffic_sample.log")
    try:
        log_path.write_text(
            "\n".join(
                [
                    "DNS Query: dns.example.com",
                    "TLS SNI=sso.example.com",
                    "Host: app.example.com URL=https://app.example.com/home",
                    "Referer=https://ref.example.com/landing",
                ]
            ),
            encoding="utf-8",
        )

        body = {"traffic_log_path": str(log_path)}
        result = discover_from_traffic_data(body, "example.com")
        hosts = {item["hostname"] for item in result}
    finally:
        if log_path.exists():
            log_path.unlink()

    assert hosts == {"app.example.com", "dns.example.com", "ref.example.com", "sso.example.com"}
