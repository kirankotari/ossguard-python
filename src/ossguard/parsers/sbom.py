"""Parse SBOM files (SPDX and CycloneDX JSON formats)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ossguard.parsers.dependencies import Dependency


@dataclass
class SBOMInfo:
    """Parsed SBOM metadata."""

    format: str  # "spdx" or "cyclonedx"
    name: str
    version: str
    dependencies: list[Dependency]
    raw: dict


# Map SPDX/CycloneDX purl types to our ecosystem names
_PURL_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "pypi",
    "golang": "go",
    "cargo": "crates.io",
    "maven": "maven",
    "gem": "rubygems",
    "nuget": "nuget",
    "composer": "packagist",
    "pub": "pub",
}


def parse_sbom(sbom_path: str | Path) -> SBOMInfo:
    """Parse an SBOM file (auto-detects SPDX vs CycloneDX)."""
    path = Path(sbom_path)
    with open(path) as f:
        data = json.load(f)

    if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx(data)
    elif "spdxVersion" in data:
        return _parse_spdx(data)
    else:
        raise ValueError(f"Unrecognized SBOM format in {path}")


def _parse_cyclonedx(data: dict) -> SBOMInfo:
    """Parse CycloneDX JSON SBOM."""
    deps = []
    metadata = data.get("metadata", {})
    component = metadata.get("component", {})

    for comp in data.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        ecosystem = ""
        purl = comp.get("purl", "")

        if purl:
            ecosystem = _ecosystem_from_purl(purl)

        if not ecosystem:
            comp_type = comp.get("type", "")
            if comp_type == "library":
                # Try to infer from name patterns
                ecosystem = _guess_ecosystem(name)

        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem=ecosystem,
            source_file="sbom (CycloneDX)",
        ))

    return SBOMInfo(
        format="cyclonedx",
        name=component.get("name", ""),
        version=component.get("version", ""),
        dependencies=deps,
        raw=data,
    )


def _parse_spdx(data: dict) -> SBOMInfo:
    """Parse SPDX JSON SBOM."""
    deps = []
    doc_name = data.get("name", "")

    for pkg in data.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        ecosystem = ""

        # Check external refs for purl
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                ecosystem = _ecosystem_from_purl(ref.get("referenceLocator", ""))
                break

        if not ecosystem:
            ecosystem = _guess_ecosystem(name)

        # Skip the root document package
        spdx_id = pkg.get("SPDXID", "")
        if spdx_id == "SPDXRef-DOCUMENT":
            continue

        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem=ecosystem,
            source_file="sbom (SPDX)",
        ))

    return SBOMInfo(
        format="spdx",
        name=doc_name,
        version="",
        dependencies=deps,
        raw=data,
    )


def _ecosystem_from_purl(purl: str) -> str:
    """Extract ecosystem from a package URL (purl)."""
    # purl format: pkg:type/namespace/name@version
    if not purl.startswith("pkg:"):
        return ""
    parts = purl[4:].split("/", 1)
    purl_type = parts[0].lower()
    return _PURL_ECOSYSTEM_MAP.get(purl_type, purl_type)


def _guess_ecosystem(name: str) -> str:
    """Guess ecosystem from package name patterns."""
    if "/" in name and not name.startswith("github.com"):
        return "npm"  # scoped npm packages like @scope/name
    if name.startswith("github.com/") or name.startswith("golang.org/"):
        return "go"
    return ""
