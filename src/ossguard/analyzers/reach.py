"""Reachability analysis — filter vulnerabilities by actual import/usage."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ossguard.apis.osv import OSVClient, VulnInfo
from ossguard.parsers.dependencies import Dependency


@dataclass
class ReachResult:
    """Reachability analysis for a single dependency."""

    dep: Dependency
    is_reachable: bool = False
    import_locations: list[str] = field(default_factory=list)
    vulns: list[VulnInfo] = field(default_factory=list)

    @property
    def vuln_count(self) -> int:
        return len(self.vulns)


@dataclass
class ReachReport:
    """Full reachability analysis report."""

    results: list[ReachResult] = field(default_factory=list)
    total_deps: int = 0
    reachable_deps: int = 0
    total_vulns: int = 0
    reachable_vulns: int = 0
    filtered_vulns: int = 0

    @property
    def noise_reduction_pct(self) -> float:
        if self.total_vulns == 0:
            return 0.0
        return round((self.filtered_vulns / self.total_vulns) * 100, 1)


def analyze_reachability(
    deps: list[Dependency],
    project_path: str | Path,
) -> ReachReport:
    """Analyze which dependencies are actually imported/used in the source code.

    This performs static analysis by scanning source files for import statements.
    It then cross-references with vulnerability data to filter out unreachable vulns.

    Args:
        deps: List of project dependencies.
        project_path: Path to the project source code.

    Returns:
        ReachReport with reachable vs unreachable vulnerability breakdown.
    """
    path = Path(project_path).resolve()

    # Step 1: Scan source code for imports
    imported_packages = _scan_imports(path)

    # Step 2: Match imports to dependencies
    reachable_deps = []
    unreachable_deps = []

    for dep in deps:
        if dep.is_dev:
            continue

        is_reachable = _is_dep_imported(dep, imported_packages)
        locations = _find_import_locations(dep, imported_packages)

        if is_reachable:
            reachable_deps.append((dep, locations))
        else:
            unreachable_deps.append(dep)

    # Step 3: Query vulns only for all non-dev deps
    all_non_dev = [d for d in deps if not d.is_dev]
    packages = [(d.name, d.version, d.ecosystem) for d in all_non_dev]

    with OSVClient() as osv:
        vuln_map = osv.query_batch(packages)

    # Step 4: Build results
    results: list[ReachResult] = []
    total_vulns = 0
    reachable_vulns = 0

    for dep, locations in reachable_deps:
        vulns = vuln_map.get(dep.name, [])
        total_vulns += len(vulns)
        reachable_vulns += len(vulns)
        results.append(
            ReachResult(
                dep=dep,
                is_reachable=True,
                import_locations=locations,
                vulns=vulns,
            )
        )

    for dep in unreachable_deps:
        vulns = vuln_map.get(dep.name, [])
        total_vulns += len(vulns)
        results.append(
            ReachResult(
                dep=dep,
                is_reachable=False,
                vulns=vulns,
            )
        )

    # Sort: reachable with vulns first
    results.sort(key=lambda r: (not r.is_reachable, -r.vuln_count))

    return ReachReport(
        results=results,
        total_deps=len(all_non_dev),
        reachable_deps=len(reachable_deps),
        total_vulns=total_vulns,
        reachable_vulns=reachable_vulns,
        filtered_vulns=total_vulns - reachable_vulns,
    )


def _scan_imports(project_path: Path) -> dict[str, list[str]]:
    """Scan project source files for import statements.

    Returns:
        Dict mapping package name to list of file paths where it's imported.
    """
    imports: dict[str, list[str]] = {}

    # Define file extensions and their import patterns
    patterns = {
        ".py": [
            re.compile(r"^import\s+(\w+)"),
            re.compile(r"^from\s+(\w+)"),
        ],
        ".js": [
            re.compile(r"""require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)"""),
            re.compile(r"""from\s+['"]([^'"./][^'"]*)['"]\s*"""),
            re.compile(r"""import\s+['"]([^'"./][^'"]*)['"]\s*"""),
        ],
        ".ts": [
            re.compile(r"""from\s+['"]([^'"./][^'"]*)['"]\s*"""),
            re.compile(r"""import\s+['"]([^'"./][^'"]*)['"]\s*"""),
        ],
        ".go": [
            re.compile(r'"([a-zA-Z0-9._/-]+)"'),
        ],
        ".rs": [
            re.compile(r"^use\s+(\w+)"),
            re.compile(r"^extern\s+crate\s+(\w+)"),
        ],
        ".rb": [
            re.compile(r"^require\s+['\"]([^'\"]+)['\"]"),
            re.compile(r"^gem\s+['\"]([^'\"]+)['\"]"),
        ],
        ".java": [
            re.compile(r"^import\s+(?:static\s+)?([a-zA-Z0-9_.]+)"),
        ],
    }

    # Also match tsx, jsx, mjs
    patterns[".tsx"] = patterns[".ts"]
    patterns[".jsx"] = patterns[".js"]
    patterns[".mjs"] = patterns[".js"]

    # Walk source files (skip common non-source dirs)
    skip_dirs = {
        "node_modules",
        ".git",
        "__pycache__",
        "venv",
        ".venv",
        "env",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        "target",
        "vendor",
    }

    for file_path in _walk_files(project_path, skip_dirs):
        ext = file_path.suffix.lower()
        if ext not in patterns:
            continue

        try:
            content = file_path.read_text(errors="ignore")
            for line in content.splitlines():
                stripped = line.strip()
                for pattern in patterns[ext]:
                    match = pattern.search(stripped)
                    if match:
                        pkg_name = match.group(1)
                        # Normalize: get top-level package name
                        pkg_name = _normalize_import_name(pkg_name, ext)
                        if pkg_name:
                            rel_path = str(file_path.relative_to(project_path))
                            if pkg_name not in imports:
                                imports[pkg_name] = []
                            if rel_path not in imports[pkg_name]:
                                imports[pkg_name].append(rel_path)
        except Exception:
            continue

    return imports


def _walk_files(root: Path, skip_dirs: set[str]):
    """Walk directory tree, yielding files and skipping specified directories."""
    try:
        for item in root.iterdir():
            if item.is_dir():
                if item.name not in skip_dirs:
                    yield from _walk_files(item, skip_dirs)
            elif item.is_file():
                yield item
    except PermissionError:
        pass


def _normalize_import_name(name: str, ext: str) -> str:
    """Normalize an import name to match against dependency names."""
    if not name:
        return ""

    # For Python: first segment of dotted import
    if ext == ".py":
        return name.split(".")[0].replace("_", "-")

    # For JS/TS: handle scoped packages (@scope/name)
    if ext in (".js", ".ts", ".tsx", ".jsx", ".mjs"):
        if name.startswith("@"):
            parts = name.split("/")
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
        return name.split("/")[0]

    # For Go: full module path
    if ext == ".go":
        return name

    # For Rust: crate name (underscores to hyphens)
    if ext == ".rs":
        return name.replace("_", "-")

    return name.split(".")[0]


def _is_dep_imported(dep: Dependency, imports: dict[str, list[str]]) -> bool:
    """Check if a dependency is found in the import scan."""
    name = dep.name.lower()

    # Direct match
    if name in {k.lower() for k in imports}:
        return True

    # Python: package name with hyphens vs underscores
    alt_name = name.replace("-", "_")
    if alt_name in {k.lower() for k in imports}:
        return True

    alt_name = name.replace("_", "-")
    if alt_name in {k.lower() for k in imports}:
        return True

    # npm scoped packages
    if "/" in name:
        if name in {k.lower() for k in imports}:
            return True

    return False


def _find_import_locations(dep: Dependency, imports: dict[str, list[str]]) -> list[str]:
    """Find all file locations where a dependency is imported."""
    name = dep.name.lower()
    for key, locations in imports.items():
        if key.lower() == name:
            return locations
        if key.lower().replace("-", "_") == name.replace("-", "_"):
            return locations
    return []
