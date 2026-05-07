"""SBOM drift detection — diff two SBOMs and compute risk delta."""

from __future__ import annotations

from dataclasses import dataclass, field

from ossguard.apis.osv import OSVClient, VulnInfo
from ossguard.parsers.dependencies import Dependency
from ossguard.parsers.sbom import SBOMInfo, parse_sbom


@dataclass
class DriftEntry:
    """A single change between two SBOMs."""

    change_type: str  # "added", "removed", "upgraded", "downgraded"
    dep: Dependency
    old_version: str = ""
    new_version: str = ""
    vulns: list[VulnInfo] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if any(v.severity == "CRITICAL" for v in self.vulns):
            return "CRITICAL"
        if any(v.severity == "HIGH" for v in self.vulns):
            return "HIGH"
        if self.vulns:
            return "MEDIUM"
        if self.change_type == "added":
            return "NEW"
        if self.change_type == "downgraded":
            return "WARN"
        return "OK"


@dataclass
class DriftReport:
    """Aggregated SBOM drift report."""

    old_name: str = ""
    new_name: str = ""
    entries: list[DriftEntry] = field(default_factory=list)
    added: int = 0
    removed: int = 0
    upgraded: int = 0
    downgraded: int = 0
    new_vulns: int = 0

    @property
    def total_changes(self) -> int:
        return self.added + self.removed + self.upgraded + self.downgraded

    @property
    def risk_delta(self) -> str:
        if any(e.risk_level == "CRITICAL" for e in self.entries):
            return "CRITICAL INCREASE"
        if any(e.risk_level == "HIGH" for e in self.entries):
            return "HIGH INCREASE"
        if self.new_vulns > 0:
            return "MODERATE INCREASE"
        if self.added > self.removed:
            return "SLIGHT INCREASE"
        if self.removed > self.added:
            return "DECREASED"
        return "UNCHANGED"


def analyze_drift(
    old_sbom_path: str,
    new_sbom_path: str,
    check_vulns: bool = True,
) -> DriftReport:
    """Compare two SBOMs and produce a drift report.

    Args:
        old_sbom_path: Path to the older SBOM file.
        new_sbom_path: Path to the newer SBOM file.
        check_vulns: Whether to query OSV for vulns on added/changed deps.

    Returns:
        DriftReport with all changes and risk assessment.
    """
    old_sbom = parse_sbom(old_sbom_path)
    new_sbom = parse_sbom(new_sbom_path)

    # Build lookup maps: (name, ecosystem) -> Dependency
    old_map = {(d.name, d.ecosystem): d for d in old_sbom.dependencies}
    new_map = {(d.name, d.ecosystem): d for d in new_sbom.dependencies}

    entries: list[DriftEntry] = []
    deps_to_check: list[tuple[str, str, str]] = []

    # Find added and changed dependencies
    for key, new_dep in new_map.items():
        if key not in old_map:
            entry = DriftEntry(
                change_type="added",
                dep=new_dep,
                new_version=new_dep.version,
            )
            entries.append(entry)
            if new_dep.version and new_dep.ecosystem:
                deps_to_check.append((new_dep.name, new_dep.version, new_dep.ecosystem))
        else:
            old_dep = old_map[key]
            if old_dep.version != new_dep.version:
                change = _classify_version_change(old_dep.version, new_dep.version)
                entry = DriftEntry(
                    change_type=change,
                    dep=new_dep,
                    old_version=old_dep.version,
                    new_version=new_dep.version,
                )
                entries.append(entry)
                if new_dep.version and new_dep.ecosystem:
                    deps_to_check.append((new_dep.name, new_dep.version, new_dep.ecosystem))

    # Find removed dependencies
    for key, old_dep in old_map.items():
        if key not in new_map:
            entries.append(DriftEntry(
                change_type="removed",
                dep=old_dep,
                old_version=old_dep.version,
            ))

    # Check vulnerabilities on new/changed deps
    new_vulns = 0
    if check_vulns and deps_to_check:
        with OSVClient() as osv:
            vuln_map = osv.query_batch(deps_to_check)
        for entry in entries:
            if entry.change_type in ("added", "upgraded", "downgraded"):
                vulns = vuln_map.get(entry.dep.name, [])
                entry.vulns = vulns
                new_vulns += len(vulns)

    # Count changes
    added = sum(1 for e in entries if e.change_type == "added")
    removed = sum(1 for e in entries if e.change_type == "removed")
    upgraded = sum(1 for e in entries if e.change_type == "upgraded")
    downgraded = sum(1 for e in entries if e.change_type == "downgraded")

    # Sort: risky changes first
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARN": 3, "NEW": 4, "OK": 5}
    entries.sort(key=lambda e: risk_order.get(e.risk_level, 99))

    return DriftReport(
        old_name=old_sbom.name,
        new_name=new_sbom.name,
        entries=entries,
        added=added,
        removed=removed,
        upgraded=upgraded,
        downgraded=downgraded,
        new_vulns=new_vulns,
    )


def _classify_version_change(old_ver: str, new_ver: str) -> str:
    """Classify whether a version change is an upgrade or downgrade."""
    old_parts = _version_tuple(old_ver)
    new_parts = _version_tuple(new_ver)

    if new_parts > old_parts:
        return "upgraded"
    elif new_parts < old_parts:
        return "downgraded"
    return "upgraded"  # default if can't determine


def _version_tuple(version: str) -> tuple[int, ...]:
    """Convert a version string to a comparable tuple."""
    import re
    parts = re.findall(r'\d+', version)
    return tuple(int(p) for p in parts) if parts else (0,)
