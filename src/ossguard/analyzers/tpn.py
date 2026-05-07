"""Third-party notice generation from dependencies or SBOMs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ossguard.apis.deps_dev import DepsDevClient
from ossguard.parsers.dependencies import Dependency


@dataclass
class ThirdPartyEntry:
    """A single third-party component for notice generation."""

    name: str
    version: str
    license: str
    homepage: str = ""
    repo_url: str = ""
    ecosystem: str = ""


@dataclass
class TPNReport:
    """Third-party notice report."""

    project_name: str
    entries: list[ThirdPartyEntry] = field(default_factory=list)
    unknown_licenses: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        """Generate plain-text third-party notice."""
        lines = [
            "THIRD-PARTY SOFTWARE NOTICES AND INFORMATION",
            f"Project: {self.project_name}",
            "",
            "This project incorporates components from the projects listed below.",
            f"{'=' * 72}",
            "",
        ]

        for i, entry in enumerate(sorted(self.entries, key=lambda e: e.name.lower()), 1):
            lines.append(f"{i}. {entry.name} ({entry.version})")
            lines.append(f"   License: {entry.license or 'UNKNOWN'}")
            if entry.homepage:
                lines.append(f"   Homepage: {entry.homepage}")
            if entry.repo_url:
                lines.append(f"   Source: {entry.repo_url}")
            lines.append("")

        if self.unknown_licenses:
            lines.append(f"{'=' * 72}")
            lines.append("WARNING: The following packages have unknown licenses:")
            for name in self.unknown_licenses:
                lines.append(f"  - {name}")
            lines.append("")

        if self.conflicts:
            lines.append(f"{'=' * 72}")
            lines.append("WARNING: Potential license conflicts detected:")
            for conflict in self.conflicts:
                lines.append(f"  - {conflict}")
            lines.append("")

        return "\n".join(lines)

    def to_html(self) -> str:
        """Generate HTML third-party notice."""
        entries_html = ""
        for entry in sorted(self.entries, key=lambda e: e.name.lower()):
            link = ""
            if entry.homepage:
                link = f' — <a href="{entry.homepage}">{entry.homepage}</a>'
            elif entry.repo_url:
                link = f' — <a href="{entry.repo_url}">{entry.repo_url}</a>'

            entries_html += f"""<tr>
  <td><strong>{entry.name}</strong></td>
  <td>{entry.version}</td>
  <td>{entry.license or '<span style="color:red">UNKNOWN</span>'}</td>
  <td>{link}</td>
</tr>
"""

        warnings = ""
        if self.unknown_licenses:
            items = "".join(f"<li>{n}</li>" for n in self.unknown_licenses)
            warnings += f'<div class="warning"><h3>Unknown Licenses</h3><ul>{items}</ul></div>'

        if self.conflicts:
            items = "".join(f"<li>{c}</li>" for c in self.conflicts)
            warnings += f'<div class="warning"><h3>License Conflicts</h3><ul>{items}</ul></div>'

        return f"""<!DOCTYPE html>
<html>
<head>
<title>Third-Party Notices — {self.project_name}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; }}
tr:nth-child(even) {{ background: #fafafa; }}
.warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 1rem; margin: 1rem 0; border-radius: 4px; }}
.summary {{ background: #e8f4e8; padding: 1rem; border-radius: 4px; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>Third-Party Notices</h1>
<p>Project: <strong>{self.project_name}</strong></p>
<div class="summary">
<p>This project incorporates <strong>{len(self.entries)}</strong> third-party components.</p>
</div>
{warnings}
<table>
<thead><tr><th>Package</th><th>Version</th><th>License</th><th>Link</th></tr></thead>
<tbody>
{entries_html}
</tbody>
</table>
</body>
</html>"""

    def to_json(self) -> str:
        """Generate JSON third-party notice."""
        return json.dumps(
            {
                "project": self.project_name,
                "total_components": len(self.entries),
                "unknown_licenses": self.unknown_licenses,
                "conflicts": self.conflicts,
                "components": [
                    {
                        "name": e.name,
                        "version": e.version,
                        "license": e.license,
                        "homepage": e.homepage,
                        "repo_url": e.repo_url,
                        "ecosystem": e.ecosystem,
                    }
                    for e in sorted(self.entries, key=lambda x: x.name.lower())
                ],
            },
            indent=2,
        )


# Known copyleft licenses that may conflict with permissive licenses
_COPYLEFT_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"}
_PERMISSIVE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"}


def generate_tpn(
    deps: list[Dependency],
    project_name: str = "",
) -> TPNReport:
    """Generate third-party notices by looking up license info for all dependencies.

    Args:
        deps: List of dependencies to generate notices for.
        project_name: Name of the project these deps belong to.

    Returns:
        TPNReport with license info and conflict detection.
    """
    entries: list[ThirdPartyEntry] = []
    unknown: list[str] = []
    found_licenses: dict[str, str] = {}  # name -> license

    with DepsDevClient() as client:
        for dep in deps:
            if dep.is_dev:
                continue

            info = None
            if dep.version:
                info = client.get_version(dep.name, dep.version, dep.ecosystem)
            if not info:
                info = client.get_package(dep.name, dep.ecosystem)

            license_str = info.license if info else ""
            homepage = info.homepage if info else ""
            repo_url = info.repo_url if info else ""

            entries.append(
                ThirdPartyEntry(
                    name=dep.name,
                    version=dep.version,
                    license=license_str,
                    homepage=homepage,
                    repo_url=repo_url,
                    ecosystem=dep.ecosystem,
                )
            )

            if not license_str:
                unknown.append(dep.name)
            else:
                found_licenses[dep.name] = license_str

    # Detect license conflicts
    conflicts = _detect_conflicts(found_licenses)

    return TPNReport(
        project_name=project_name,
        entries=entries,
        unknown_licenses=unknown,
        conflicts=conflicts,
    )


def _detect_conflicts(licenses: dict[str, str]) -> list[str]:
    """Detect potential license conflicts between dependencies."""
    conflicts = []
    has_copyleft = []
    has_permissive = []

    for name, lic in licenses.items():
        # Normalize license string for comparison
        lic_upper = lic.upper().strip()
        for copyleft in _COPYLEFT_LICENSES:
            if copyleft.upper() in lic_upper:
                has_copyleft.append((name, lic))
                break
        for permissive in _PERMISSIVE_LICENSES:
            if permissive.upper() in lic_upper:
                has_permissive.append((name, lic))
                break

    if has_copyleft and has_permissive:
        copyleft_names = ", ".join(f"{n} ({lic})" for n, lic in has_copyleft[:3])
        conflicts.append(
            f"Copyleft licenses detected alongside permissive: {copyleft_names}. "
            "Review compatibility with your project license."
        )

    return conflicts
