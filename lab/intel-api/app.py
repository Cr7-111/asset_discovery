from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


PASSIVE_DNS_ROWS = [
    ("console.corp-demo.test", "172.28.0.10"),
    ("status.corp-demo.test", "172.28.0.10"),
    ("secure.corp-demo.test", "172.28.0.10"),
    ("manager.corp-demo.test", "172.28.0.10"),
    ("legacy.corp-demo.test", "172.28.0.250"),
]

SEARCH_ROWS = [
    ("Corporate Console", "https://console.corp-demo.test/login"),
    ("Status Board", "https://status.corp-demo.test/health"),
    ("Developer Portal", "https://dev.corp-demo.test/"),
    ("Jenkins CI", "https://jenkins.corp-demo.test/"),
    ("Application Manager", "https://manager.corp-demo.test/manager/html"),
]


class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabIntel/1.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)

        if parsed.path == "/hostsearch/":
            self._send_passive_dns(parsed)
            return
        if parsed.path == "/search":
            self._send_search(parsed)
            return
        if parsed.path == "/ground-truth":
            self._send_ground_truth()
            return

        self._send_text(404, "not found")

    def log_message(self, fmt: str, *args) -> None:
        return None

    def _send_passive_dns(self, parsed) -> None:
        domain = parse_qs(parsed.query).get("q", [""])[0]
        rows = [
            f"{hostname},{ip}"
            for hostname, ip in PASSIVE_DNS_ROWS
            if hostname.endswith(domain)
        ]
        self._send_text(200, "\n".join(rows), content_type="text/plain; charset=utf-8")

    def _send_search(self, parsed) -> None:
        query = parse_qs(parsed.query).get("q", [""])[0]
        links = "\n".join(
            f'<li><a href="{href}">{title}</a></li>'
            for title, href in SEARCH_ROWS
        )
        html = f"""<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <title>Corp Demo Search</title>
  </head>
  <body>
    <h1>Corp Demo Search</h1>
    <p>query={query}</p>
    <ul>
      {links}
    </ul>
  </body>
</html>
"""
        self._send_text(200, html, content_type="text/html; charset=utf-8")

    def _send_ground_truth(self) -> None:
        path = Path("/app/ground_truth/ground_truth.json")
        payload = path.read_text(encoding="utf-8") if path.exists() else "{}"
        self._send_text(200, payload, content_type="application/json; charset=utf-8")

    def _send_text(self, status: int, body: str, *, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), LabHandler).serve_forever()
