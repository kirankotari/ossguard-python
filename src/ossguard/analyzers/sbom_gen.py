"""Local SBOM generator — produce SPDX or CycloneDX JSON from dependency manifests."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ossguard.detector import detect_project
from ossguard.parsers.dependencies import Dependency, parse_dependencies


def generate_sbom(
    project_path: str | Path,
    sbom_format: str = "spdx",
) -> str:
    """Generate an SBOM from project dependency manifests.

    Args:
        project_path: Path to the project.
        sbom_format: "spdx" or "cyclonedx".

    Returns:
        JSON string of the SBOM.
    """
    path = Path(project_path).resolve()
    info = detect_project(path)
    deps = parse_dependencies(path)

    if sbom_format == "cyclonedx":
        return _generate_cyclonedx(info.repo_name, deps)
    return _generate_spdx(info.repo_name, deps)


def _generate_spdx(project_name: str, deps: list[Dependency]) -> str:
    """Generate SPDX 2.3 JSON SBOM."""
    doc_namespace = f"https://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    packages = []
    relationships = []

    # Root package
    root_spdx_id = "SPDXRef-RootPackage"
    packages.append(
        {
            "SPDXID": root_spdx_id,
            "name": project_name,
            "versionInfo": "",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "primaryPackagePurpose": "APPLICATION",
        }
    )

    relationships.append(
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": root_spdx_id,
            "relationshipType": "DESCRIBES",
        }
    )

    for i, dep in enumerate(deps):
        spdx_id = f"SPDXRef-Package-{i}"
        purl = _make_purl(dep)

        pkg = {
            "SPDXID": spdx_id,
            "name": dep.name,
            "versionInfo": dep.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
        }
        if purl:
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ]
        packages.append(pkg)

        rel_type = "DEV_DEPENDENCY_OF" if dep.is_dev else "DEPENDENCY_OF"
        relationships.append(
            {
                "spdxElementId": spdx_id,
                "relatedSpdxElement": root_spdx_id,
                "relationshipType": rel_type,
            }
        )

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-sbom",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": now,
            "creators": ["Tool: ossguard"],
            "licenseListVersion": "3.22",
        },
        "packages": packages,
        "relationships": relationships,
    }

    return json.dumps(sbom, indent=2)


def _generate_cyclonedx(project_name: str, deps: list[Dependency]) -> str:
    """Generate CycloneDX 1.5 JSON SBOM."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    components = []
    dependencies_list = []

    root_ref = project_name

    for dep in deps:
        purl = _make_purl(dep)
        comp = {
            "type": "library",
            "name": dep.name,
            "version": dep.version or "",
        }
        if purl:
            comp["purl"] = purl
            comp["bom-ref"] = purl
        else:
            comp["bom-ref"] = f"{dep.name}@{dep.version}"

        if dep.ecosystem:
            comp["group"] = dep.ecosystem

        # Scope
        if dep.is_dev:
            comp["scope"] = "optional"
        else:
            comp["scope"] = "required"

        components.append(comp)

        dependencies_list.append(
            {
                "ref": comp["bom-ref"],
                "dependsOn": [],
            }
        )

    # Root dependency
    dependencies_list.insert(
        0,
        {
            "ref": root_ref,
            "dependsOn": [c.get("bom-ref", "") for c in components],
        },
    )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "ossguard", "name": "ossguard", "version": "0.1.0"}],
            "component": {
                "type": "application",
                "name": project_name,
                "bom-ref": root_ref,
            },
        },
        "components": components,
        "dependencies": dependencies_list,
    }

    return json.dumps(sbom, indent=2)


def _make_purl(dep: Dependency) -> str:
    """Create a Package URL (purl) for a dependency."""
    eco_map = {
        "npm": "npm",
        "pypi": "pypi",
        "go": "golang",
        "cargo": "cargo",
        "maven": "maven",
        "composer": "composer",
        "rubygems": "gem",
    }
    purl_type = eco_map.get(dep.ecosystem, dep.ecosystem)
    if not purl_type:
        return ""

    name = dep.name
    if dep.ecosystem == "go":
        # Go uses full module path
        return f"pkg:{purl_type}/{name}@{dep.version}" if dep.version else f"pkg:{purl_type}/{name}"

    if dep.ecosystem == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:{purl_type}/{group}/{artifact}@{dep.version}" if dep.version else ""

    version_part = f"@{dep.version}" if dep.version else ""
    return f"pkg:{purl_type}/{name}{version_part}"
