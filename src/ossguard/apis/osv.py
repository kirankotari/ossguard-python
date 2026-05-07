"""Client for the OSV (Open Source Vulnerabilities) API."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

OSV_API_BASE = "https://api.osv.dev/v1"

# Map our ecosystem names to OSV ecosystem names
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "crates.io": "crates.io",
    "maven": "Maven",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "pub": "Pub",
}


@dataclass
class VulnInfo:
    """A single vulnerability entry."""

    id: str
    summary: str = ""
    severity: str = ""  # CRITICAL, HIGH, MEDIUM, LOW
    aliases: list[str] = field(default_factory=list)
    fixed_version: str = ""
    url: str = ""

    @property
    def display_severity(self) -> str:
        colors = {
            "CRITICAL": "[bold red]CRITICAL[/]",
            "HIGH": "[red]HIGH[/]",
            "MEDIUM": "[yellow]MEDIUM[/]",
            "LOW": "[green]LOW[/]",
        }
        return colors.get(self.severity, self.severity)


class OSVClient:
    """Client for querying OSV vulnerability database."""

    def __init__(self, timeout: float = 30.0):
        self._client = httpx.Client(
            base_url=OSV_API_BASE,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> OSVClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def query(self, name: str, version: str, ecosystem: str) -> list[VulnInfo]:
        """Query vulnerabilities for a single package."""
        osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem, ecosystem)
        if not osv_ecosystem:
            return []

        payload: dict = {"package": {"name": name, "ecosystem": osv_ecosystem}}
        if version:
            payload["version"] = version

        try:
            resp = self._client.post("/query", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return _parse_vulns(data.get("vulns", []))
        except Exception:
            return []

    def query_batch(self, packages: list[tuple[str, str, str]]) -> dict[str, list[VulnInfo]]:
        """Query vulnerabilities for multiple packages in one request.

        Args:
            packages: List of (name, version, ecosystem) tuples.

        Returns:
            Dict mapping "name" to list of VulnInfo.
        """
        queries = []
        for name, version, ecosystem in packages:
            osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem, ecosystem)
            if not osv_ecosystem:
                queries.append({})
                continue
            q: dict = {"package": {"name": name, "ecosystem": osv_ecosystem}}
            if version:
                q["version"] = version
            queries.append(q)

        if not queries:
            return {}

        try:
            resp = self._client.post("/querybatch", json={"queries": queries})
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return {}

        results: dict[str, list[VulnInfo]] = {}
        for i, result in enumerate(data.get("results", [])):
            name = packages[i][0]
            vulns = _parse_vulns(result.get("vulns", []))
            if vulns:
                results[name] = vulns

        return results


def _parse_vulns(vulns: list[dict]) -> list[VulnInfo]:
    """Parse OSV vulnerability entries."""
    parsed = []
    for v in vulns:
        severity = _extract_severity(v)
        aliases = v.get("aliases", [])
        fixed = _extract_fixed_version(v)

        parsed.append(
            VulnInfo(
                id=v.get("id", ""),
                summary=v.get("summary", "")[:120],
                severity=severity,
                aliases=aliases,
                fixed_version=fixed,
                url=f"https://osv.dev/vulnerability/{v.get('id', '')}",
            )
        )

    return parsed


def _extract_severity(vuln: dict) -> str:
    """Extract the highest severity from a vulnerability entry."""
    # Check database_specific severity
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        if score_str:
            try:
                score = float(score_str)
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
            except ValueError:
                pass
        # CVSS vector string
        vector = sev.get("type", "")
        if vector == "CVSS_V3":
            score_text = sev.get("score", "")
            if score_text:
                try:
                    s = float(score_text)
                    if s >= 9.0:
                        return "CRITICAL"
                    elif s >= 7.0:
                        return "HIGH"
                    elif s >= 4.0:
                        return "MEDIUM"
                    else:
                        return "LOW"
                except ValueError:
                    pass

    # Check ecosystem-specific severity
    db_specific = vuln.get("database_specific", {})
    severity = db_specific.get("severity", "")
    if isinstance(severity, str) and severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return severity.upper()

    return "UNKNOWN"


def _extract_fixed_version(vuln: dict) -> str:
    """Extract the first fixed version from affected ranges."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""
