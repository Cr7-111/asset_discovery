"""Shared discovery data models for multi-source asset discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

SOURCE_CONFIDENCE = {
    "ct_log": 20,
    "passive_dns": 25,
    "traffic_sniff": 35,
    "search_engine": 15,
    "icp_record": 15,
    "cloud_api": 15,
    "active_dns": 15,
    "web_crawl": 10,
    "js_extract": 10,
    "certificate": 20,
}


def now_iso() -> str:
    """Return a stable ISO timestamp string for discovery events."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@dataclass
class TargetRecord:
    """Unified in-memory record used across passive, active, and validation stages."""

    subdomain: str
    ips: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    evidences: list[str] = field(default_factory=list)
    js_endpoints: set[str] = field(default_factory=set)
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_sans: set[str] = field(default_factory=set)
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    confidence_score: int = 0
    validation_status: str = "discovered"

    def touch(self, timestamp: str | None = None) -> None:
        stamp = timestamp or now_iso()
        if stamp < self.first_seen:
            self.first_seen = stamp
        if stamp > self.last_seen:
            self.last_seen = stamp

    def add_discovery(
        self,
        source: str,
        evidence: str = "",
        *,
        score: int | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Record discovery evidence and increase confidence once per new source."""
        if source and source not in self.sources:
            self.sources.add(source)
            self.confidence_score += SOURCE_CONFIDENCE.get(source, 0) if score is None else score
        elif score:
            self.confidence_score += score

        if evidence and evidence not in self.evidences:
            self.evidences.append(evidence)

        self.touch(timestamp)

    def mark_resolved(self) -> None:
        """Mark DNS resolution success once."""
        if self.validation_status == "discovered":
            self.validation_status = "resolved"
            self.confidence_score += 10
        self.touch()

    def mark_probed(self, success: bool) -> None:
        """Mark validation progress after HTTP probing."""
        if success:
            if self.validation_status != "alive":
                self.confidence_score += 15
            self.validation_status = "alive"
        elif self.validation_status not in {"alive", "failed"}:
            self.validation_status = "probed"
        self.touch()

    def to_public_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "ips": sorted(ip for ip in self.ips if ip),
            "sources": sorted(self.sources),
            "urls": sorted(self.urls),
            "evidence": self.evidences[:20],
            "js_endpoints": sorted(self.js_endpoints)[:50],
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_sans": sorted(self.cert_sans),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence_score": self.confidence_score,
            "validation_status": self.validation_status,
        }
