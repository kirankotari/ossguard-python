"""Post-deployment vulnerability monitoring — watches SBOMs for new CVEs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ossguard.apis.osv import OSVClient, VulnInfo
from ossguard.parsers.sbom import parse_sbom


@dataclass
class WatchAlert:
    """A single vulnerability alert for a deployed component."""

    package_name: str
    package_version: str
    ecosystem: str
    vulns: list[VulnInfo] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        if not self.vulns:
            return "UNKNOWN"
        return min(self.vulns, key=lambda v: severity_order.get(v.severity, 99)).severity


@dataclass
class WatchReport:
    """Full watch scan result."""

    sbom_path: str
    sbom_name: str
    scan_time: str
    alerts: list[WatchAlert] = field(default_factory=list)
    total_components: int = 0
    affected_components: int = 0
    total_vulns: int = 0

    @property
    def is_clean(self) -> bool:
        return len(self.alerts) == 0

    def to_json(self) -> str:
        """Export report as JSON."""
        return json.dumps({
            "sbom_path": self.sbom_path,
            "sbom_name": self.sbom_name,
            "scan_time": self.scan_time,
            "total_components": self.total_components,
            "affected_components": self.affected_components,
            "total_vulns": self.total_vulns,
            "alerts": [
                {
                    "package": a.package_name,
                    "version": a.package_version,
                    "ecosystem": a.ecosystem,
                    "max_severity": a.max_severity,
                    "vulns": [
                        {
                            "id": v.id,
                            "severity": v.severity,
                            "summary": v.summary,
                            "fixed_version": v.fixed_version,
                            "url": v.url,
                        }
                        for v in a.vulns
                    ],
                }
                for a in self.alerts
            ],
        }, indent=2)


def watch_sbom(sbom_path: str | Path) -> WatchReport:
    """Scan an SBOM for current vulnerabilities.

    Args:
        sbom_path: Path to the SBOM file (SPDX or CycloneDX JSON).

    Returns:
        WatchReport with all current vulnerability alerts.
    """
    from datetime import datetime, timezone

    sbom = parse_sbom(sbom_path)
    packages = [
        (d.name, d.version, d.ecosystem)
        for d in sbom.dependencies
        if d.ecosystem  # only query packages with known ecosystems
    ]

    # Batch query OSV
    with OSVClient() as osv:
        vuln_map = osv.query_batch(packages)

    alerts: list[WatchAlert] = []
    total_vulns = 0

    for dep in sbom.dependencies:
        vulns = vuln_map.get(dep.name, [])
        if vulns:
            alerts.append(WatchAlert(
                package_name=dep.name,
                package_version=dep.version,
                ecosystem=dep.ecosystem,
                vulns=vulns,
            ))
            total_vulns += len(vulns)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    alerts.sort(key=lambda a: severity_order.get(a.max_severity, 99))

    return WatchReport(
        sbom_path=str(sbom_path),
        sbom_name=sbom.name,
        scan_time=datetime.now(timezone.utc).isoformat(),
        alerts=alerts,
        total_components=len(sbom.dependencies),
        affected_components=len(alerts),
        total_vulns=total_vulns,
    )


def send_webhook(report: WatchReport, webhook_url: str) -> bool:
    """Send a watch report to a webhook URL."""
    try:
        resp = httpx.post(
            webhook_url,
            json=json.loads(report.to_json()),
            timeout=10.0,
        )
        return resp.status_code < 400
    except Exception:
        return False
