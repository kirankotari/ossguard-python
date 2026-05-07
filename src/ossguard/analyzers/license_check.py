"""License compliance checker — detect conflicts and incompatibilities."""

from __future__ import annotations

from dataclasses import dataclass, field

from ossguard.apis.deps_dev import DepsDevClient
from ossguard.parsers.dependencies import Dependency


@dataclass
class LicenseInfo:
    """License info for a single dependency."""

    name: str
    version: str
    license: str
    category: str = ""  # "permissive", "copyleft", "weak_copyleft", "unknown"
    ecosystem: str = ""


@dataclass
class LicenseConflict:
    """A detected license conflict."""

    package_a: str
    license_a: str
    package_b: str
    license_b: str
    reason: str


@dataclass
class LicenseReport:
    """Full license compliance report."""

    project_license: str = ""
    licenses: list[LicenseInfo] = field(default_factory=list)
    conflicts: list[LicenseConflict] = field(default_factory=list)
    unknown_licenses: list[str] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)  # category -> count
    compliant: bool = True


# License classification database
_PERMISSIVE = {
    "MIT",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "0BSD",
    "Unlicense",
    "CC0-1.0",
    "Zlib",
    "BSL-1.0",
    "MIT-0",
    "BlueOak-1.0.0",
}

_WEAK_COPYLEFT = {
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "MPL-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "CDDL-1.0",
    "OSL-3.0",
}

_STRONG_COPYLEFT = {
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "GPL-2.0-only",
    "GPL-3.0-only",
    "AGPL-3.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-or-later",
}

# Compatibility matrix: which project licenses allow which dependency licenses
# True = compatible, False = incompatible
_COMPATIBILITY = {
    "MIT": {"permissive": True, "weak_copyleft": True, "copyleft": False},
    "Apache-2.0": {"permissive": True, "weak_copyleft": True, "copyleft": False},
    "BSD-3-Clause": {"permissive": True, "weak_copyleft": True, "copyleft": False},
    "GPL-2.0": {"permissive": True, "weak_copyleft": True, "copyleft": True},
    "GPL-3.0": {"permissive": True, "weak_copyleft": True, "copyleft": True},
    "AGPL-3.0": {"permissive": True, "weak_copyleft": True, "copyleft": True},
    "LGPL-2.1": {"permissive": True, "weak_copyleft": True, "copyleft": False},
    "MPL-2.0": {"permissive": True, "weak_copyleft": True, "copyleft": False},
}


def check_licenses(
    deps: list[Dependency],
    project_license: str = "",
) -> LicenseReport:
    """Check license compliance for all dependencies.

    Args:
        deps: List of dependencies.
        project_license: The project's own license (e.g., "Apache-2.0").

    Returns:
        LicenseReport with compliance status, conflicts, and categorization.
    """
    licenses: list[LicenseInfo] = []
    unknown: list[str] = []
    summary: dict[str, int] = {"permissive": 0, "weak_copyleft": 0, "copyleft": 0, "unknown": 0}

    # Fetch license info from deps.dev
    with DepsDevClient() as client:
        for dep in deps:
            if dep.is_dev:
                continue

            info = None
            if dep.version:
                info = client.get_version(dep.name, dep.version, dep.ecosystem)
            if not info:
                info = client.get_package(dep.name, dep.ecosystem)

            lic_str = info.license if info else ""
            category = _classify_license(lic_str)

            licenses.append(
                LicenseInfo(
                    name=dep.name,
                    version=dep.version,
                    license=lic_str,
                    category=category,
                    ecosystem=dep.ecosystem,
                )
            )

            if not lic_str or category == "unknown":
                unknown.append(dep.name)

            summary[category] = summary.get(category, 0) + 1

    # Check for conflicts
    conflicts = _detect_conflicts(licenses, project_license)

    compliant = len(conflicts) == 0 and len(unknown) == 0

    return LicenseReport(
        project_license=project_license,
        licenses=licenses,
        conflicts=conflicts,
        unknown_licenses=unknown,
        summary=summary,
        compliant=compliant,
    )


def _classify_license(license_str: str) -> str:
    """Classify a license string into a category."""
    if not license_str:
        return "unknown"

    normalized = license_str.strip()

    # Check exact match first
    if normalized in _PERMISSIVE:
        return "permissive"
    if normalized in _WEAK_COPYLEFT:
        return "weak_copyleft"
    if normalized in _STRONG_COPYLEFT:
        return "copyleft"

    # Check partial/case-insensitive match
    upper = normalized.upper()
    for lic in _PERMISSIVE:
        if lic.upper() in upper:
            return "permissive"
    for lic in _STRONG_COPYLEFT:
        if lic.upper() in upper:
            return "copyleft"
    for lic in _WEAK_COPYLEFT:
        if lic.upper() in upper:
            return "weak_copyleft"

    return "unknown"


def _detect_conflicts(licenses: list[LicenseInfo], project_license: str) -> list[LicenseConflict]:
    """Detect license conflicts between dependencies and the project license."""
    conflicts: list[LicenseConflict] = []

    if not project_license:
        # Can't check compatibility without knowing the project license
        # But we can still detect obviously problematic combinations
        copyleft_deps = [lic for lic in licenses if lic.category == "copyleft"]
        permissive_deps = [lic for lic in licenses if lic.category == "permissive"]

        if copyleft_deps and permissive_deps:
            for cp in copyleft_deps[:3]:
                conflicts.append(
                    LicenseConflict(
                        package_a=cp.name,
                        license_a=cp.license,
                        package_b="(project)",
                        license_b="unknown",
                        reason=f"{cp.name} uses copyleft license {cp.license}. "
                        "Ensure your project license is compatible.",
                    )
                )
        return conflicts

    # Check each dep against project license
    compat = _COMPATIBILITY.get(project_license, {})
    if not compat:
        # Unknown project license — check copyleft deps
        compat = {"permissive": True, "weak_copyleft": True, "copyleft": False}

    for dep_lic in licenses:
        if dep_lic.category == "unknown":
            continue

        is_compatible = compat.get(dep_lic.category, True)
        if not is_compatible:
            conflicts.append(
                LicenseConflict(
                    package_a=dep_lic.name,
                    license_a=dep_lic.license,
                    package_b="(project)",
                    license_b=project_license,
                    reason=f"{dep_lic.name} ({dep_lic.license}, {dep_lic.category}) "
                    f"is incompatible with project license {project_license}.",
                )
            )

    return conflicts
