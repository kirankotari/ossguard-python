"""Security-aware dependency updater — suggest updates prioritized by security impact."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ossguard.analyzers.dep_health import DepHealthReport, DepHealthResult, analyze_dependencies
from ossguard.apis.deps_dev import DepsDevClient
from ossguard.parsers.dependencies import Dependency, parse_dependencies


@dataclass
class UpdateCandidate:
    """A single dependency update candidate."""

    name: str
    current_version: str
    latest_version: str
    ecosystem: str
    source_file: str
    vuln_count: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    has_security_fix: bool = False
    priority: str = "low"  # "critical", "high", "medium", "low"
    reason: str = ""


@dataclass
class UpdateReport:
    """Report of all available updates."""

    candidates: list[UpdateCandidate] = field(default_factory=list)
    security_updates: int = 0
    total_updates: int = 0
    up_to_date: int = 0


def check_updates(
    project_path: str | Path,
    security_only: bool = False,
) -> UpdateReport:
    """Check for available dependency updates, prioritized by security impact.

    Args:
        project_path: Path to the project.
        security_only: Only show updates that fix vulnerabilities.

    Returns:
        UpdateReport with prioritized candidates.
    """
    path = Path(project_path).resolve()
    deps = parse_dependencies(path)

    if not deps:
        return UpdateReport()

    # Get health report for vuln info
    dep_report = analyze_dependencies(deps, include_dev=False)

    # Build a map of dep name -> DepHealthResult
    result_map: dict[str, DepHealthResult] = {}
    for r in dep_report.results:
        result_map[r.dep.name] = r

    candidates: list[UpdateCandidate] = []
    up_to_date = 0
    security_count = 0

    with DepsDevClient() as client:
        for dep in deps:
            if dep.is_dev:
                continue

            # Get latest version
            pkg_info = client.get_package(dep.name, dep.ecosystem)
            if not pkg_info or not pkg_info.latest_version:
                continue

            latest = pkg_info.latest_version
            current = dep.version or ""

            if current == latest:
                up_to_date += 1
                continue

            # Check vuln info
            result = result_map.get(dep.name)
            vuln_count = len(result.vulns) if result else 0
            critical = sum(1 for v in (result.vulns if result else []) if v.severity == "CRITICAL")
            high = sum(1 for v in (result.vulns if result else []) if v.severity == "HIGH")
            has_fix = any(v.fixed_version for v in (result.vulns if result else []))

            # Determine priority
            priority = "low"
            reason = "Newer version available"
            if critical > 0:
                priority = "critical"
                reason = f"{critical} critical vulnerability(ies) — update immediately"
            elif high > 0:
                priority = "high"
                reason = f"{high} high vulnerability(ies)"
            elif vuln_count > 0:
                priority = "medium"
                reason = f"{vuln_count} vulnerability(ies) with fixes available"
            elif has_fix:
                priority = "medium"
                reason = "Security fix available"

            if security_only and vuln_count == 0 and not has_fix:
                continue

            if vuln_count > 0 or has_fix:
                security_count += 1

            candidates.append(UpdateCandidate(
                name=dep.name,
                current_version=current,
                latest_version=latest,
                ecosystem=dep.ecosystem,
                source_file=dep.source_file,
                vuln_count=vuln_count,
                critical_vulns=critical,
                high_vulns=high,
                has_security_fix=has_fix,
                priority=priority,
                reason=reason,
            ))

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    candidates.sort(key=lambda c: priority_order.get(c.priority, 4))

    return UpdateReport(
        candidates=candidates,
        security_updates=security_count,
        total_updates=len(candidates),
        up_to_date=up_to_date,
    )
