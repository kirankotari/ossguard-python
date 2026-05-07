"""Dependency health analysis — combines OSV vulns, deps.dev metadata, and Scorecard."""

from __future__ import annotations

from dataclasses import dataclass, field

from ossguard.apis.deps_dev import DepsDevClient, PackageInfo
from ossguard.apis.osv import OSVClient, VulnInfo
from ossguard.parsers.dependencies import Dependency


@dataclass
class DepHealthResult:
    """Health analysis result for a single dependency."""

    dep: Dependency
    vulns: list[VulnInfo] = field(default_factory=list)
    package_info: PackageInfo | None = None
    health_score: float = 0.0  # 0-10 scale

    @property
    def vuln_count(self) -> int:
        return len(self.vulns)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulns if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulns if v.severity == "HIGH")

    @property
    def license(self) -> str:
        return self.package_info.license if self.package_info else ""

    @property
    def latest_version(self) -> str:
        return self.package_info.latest_version if self.package_info else ""

    @property
    def is_outdated(self) -> bool:
        if not self.dep.version or not self.latest_version:
            return False
        return self.dep.version != self.latest_version

    @property
    def risk_level(self) -> str:
        if self.critical_count > 0:
            return "CRITICAL"
        elif self.high_count > 0:
            return "HIGH"
        elif self.vuln_count > 0:
            return "MEDIUM"
        elif self.is_outdated:
            return "LOW"
        return "OK"


@dataclass
class DepHealthReport:
    """Aggregated dependency health report."""

    results: list[DepHealthResult] = field(default_factory=list)
    total_deps: int = 0
    total_vulns: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    outdated_count: int = 0
    aggregate_score: float = 0.0  # 0-10 scale

    @property
    def risk_summary(self) -> str:
        if self.critical_vulns > 0:
            return "CRITICAL"
        elif self.high_vulns > 0:
            return "HIGH"
        elif self.total_vulns > 0:
            return "MEDIUM"
        elif self.outdated_count > 0:
            return "LOW"
        return "HEALTHY"


def analyze_dependencies(
    deps: list[Dependency],
    include_dev: bool = False,
) -> DepHealthReport:
    """Analyze health of project dependencies using OSV and deps.dev APIs.

    Args:
        deps: List of dependencies to analyze.
        include_dev: Whether to include dev dependencies.

    Returns:
        DepHealthReport with vulnerability and health data.
    """
    # Filter dev deps if not requested
    target_deps = deps if include_dev else [d for d in deps if not d.is_dev]

    if not target_deps:
        return DepHealthReport()

    results: list[DepHealthResult] = []

    # Batch query OSV for vulnerabilities
    osv_packages = [(d.name, d.version, d.ecosystem) for d in target_deps]

    with OSVClient() as osv:
        vuln_map = osv.query_batch(osv_packages)

    # Query deps.dev for metadata (done per-package since batch isn't available)
    pkg_info_map: dict[str, PackageInfo] = {}
    with DepsDevClient() as ddc:
        for dep in target_deps:
            if dep.version:
                info = ddc.get_version(dep.name, dep.version, dep.ecosystem)
            else:
                info = ddc.get_package(dep.name, dep.ecosystem)
            if info:
                pkg_info_map[dep.name] = info

    # Build results
    total_vulns = 0
    critical = 0
    high = 0
    medium = 0
    outdated = 0

    for dep in target_deps:
        vulns = vuln_map.get(dep.name, [])
        pkg_info = pkg_info_map.get(dep.name)
        score = _calculate_health_score(dep, vulns, pkg_info)

        result = DepHealthResult(
            dep=dep,
            vulns=vulns,
            package_info=pkg_info,
            health_score=score,
        )
        results.append(result)

        total_vulns += result.vuln_count
        critical += result.critical_count
        high += result.high_count
        medium += sum(1 for v in vulns if v.severity == "MEDIUM")
        if result.is_outdated:
            outdated += 1

    # Sort by risk (worst first)
    results.sort(key=lambda r: r.health_score)

    # Calculate aggregate score
    if results:
        avg_score = sum(r.health_score for r in results) / len(results)
    else:
        avg_score = 10.0

    return DepHealthReport(
        results=results,
        total_deps=len(target_deps),
        total_vulns=total_vulns,
        critical_vulns=critical,
        high_vulns=high,
        medium_vulns=medium,
        outdated_count=outdated,
        aggregate_score=round(avg_score, 1),
    )


def _calculate_health_score(
    dep: Dependency,
    vulns: list[VulnInfo],
    pkg_info: PackageInfo | None,
) -> float:
    """Calculate a 0-10 health score for a dependency.

    10 = perfectly healthy, 0 = critically vulnerable.
    """
    score = 10.0

    # Deduct for vulnerabilities
    for v in vulns:
        if v.severity == "CRITICAL":
            score -= 3.0
        elif v.severity == "HIGH":
            score -= 2.0
        elif v.severity == "MEDIUM":
            score -= 1.0
        elif v.severity == "LOW":
            score -= 0.5
        else:
            score -= 0.5

    # Deduct for being outdated
    if pkg_info and dep.version and pkg_info.latest_version:
        if dep.version != pkg_info.latest_version:
            score -= 0.5

    # Clamp to 0-10
    return max(0.0, min(10.0, round(score, 1)))
