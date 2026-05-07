"""Parse dependency files to extract package names and versions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dependency:
    """A single project dependency."""

    name: str
    version: str = ""
    ecosystem: str = ""  # npm, pypi, go, crates.io, maven, rubygems, nuget
    source_file: str = ""
    is_dev: bool = False

    @property
    def display_name(self) -> str:
        if self.version:
            return f"{self.name}@{self.version}"
        return self.name


def parse_dependencies(project_path: str | Path) -> list[Dependency]:
    """Parse all dependency files in a project and return a list of dependencies."""
    path = Path(project_path).resolve()
    deps: list[Dependency] = []

    if not path.is_dir():
        return deps

    # Parse each type of dependency file
    _parse_package_json(path, deps)
    _parse_requirements_txt(path, deps)
    _parse_pyproject_toml(path, deps)
    _parse_go_mod(path, deps)
    _parse_cargo_toml(path, deps)
    _parse_gemfile_lock(path, deps)
    _parse_pom_xml(path, deps)
    _parse_composer_json(path, deps)

    # Deduplicate
    seen = set()
    unique = []
    for dep in deps:
        key = (dep.name, dep.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(dep)

    return unique


def _parse_package_json(project_path: Path, deps: list[Dependency]) -> None:
    """Parse npm package.json."""
    pkg_file = project_path / "package.json"
    if not pkg_file.exists():
        return

    try:
        with open(pkg_file) as f:
            pkg = json.load(f)

        for name, version in pkg.get("dependencies", {}).items():
            deps.append(Dependency(
                name=name,
                version=_clean_version(version),
                ecosystem="npm",
                source_file="package.json",
                is_dev=False,
            ))
        for name, version in pkg.get("devDependencies", {}).items():
            deps.append(Dependency(
                name=name,
                version=_clean_version(version),
                ecosystem="npm",
                source_file="package.json",
                is_dev=True,
            ))
    except Exception:
        pass


def _parse_requirements_txt(project_path: Path, deps: list[Dependency]) -> None:
    """Parse pip requirements.txt."""
    for req_file in ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt"]:
        req_path = project_path / req_file
        if not req_path.exists():
            continue

        is_dev = "dev" in req_file
        try:
            for line in req_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # Handle version specifiers: package==1.0, package>=1.0, package~=1.0
                match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=~!]+\s*[\d.*]+)?', line)
                if match:
                    name = match.group(1)
                    version_spec = match.group(2) or ""
                    version = re.sub(r'[><=~!]+\s*', '', version_spec).strip()
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        source_file=req_file,
                        is_dev=is_dev,
                    ))
        except Exception:
            pass


def _parse_pyproject_toml(project_path: Path, deps: list[Dependency]) -> None:
    """Parse pyproject.toml dependencies."""
    toml_path = project_path / "pyproject.toml"
    if not toml_path.exists():
        return

    try:
        content = toml_path.read_text()

        # Simple TOML parsing for dependencies array
        # Look for dependencies = [...] under [project]
        in_project = False
        in_deps = False
        bracket_depth = 0

        for line in content.splitlines():
            stripped = line.strip()

            if stripped == "[project]":
                in_project = True
                continue
            elif stripped.startswith("[") and stripped != "[project]":
                if in_project and not stripped.startswith("[project."):
                    in_project = False
                    in_deps = False
                continue

            if in_project and stripped.startswith("dependencies"):
                in_deps = True
                bracket_depth = stripped.count("[") - stripped.count("]")
                # Extract deps from same line if single-line array
                _extract_pyproject_deps(stripped, deps, is_dev=False)
                if bracket_depth <= 0 and "[" in stripped:
                    in_deps = False
                continue

            if in_deps:
                bracket_depth += stripped.count("[") - stripped.count("]")
                _extract_pyproject_deps(stripped, deps, is_dev=False)
                if bracket_depth <= 0:
                    in_deps = False

    except Exception:
        pass


def _extract_pyproject_deps(line: str, deps: list[Dependency], is_dev: bool) -> None:
    """Extract dependency specs from a pyproject.toml line."""
    # Match quoted dependency specs like "requests>=2.28.0" or "rich"
    for match in re.finditer(r'"([a-zA-Z0-9_.-]+)(?:\[.*?\])?(?:\s*([><=~!]+\s*[\d.*]+))?', line):
        name = match.group(1)
        version_spec = match.group(2) or ""
        version = re.sub(r'[><=~!]+\s*', '', version_spec).strip()
        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="pypi",
            source_file="pyproject.toml",
            is_dev=is_dev,
        ))


def _parse_go_mod(project_path: Path, deps: list[Dependency]) -> None:
    """Parse go.mod."""
    go_mod = project_path / "go.mod"
    if not go_mod.exists():
        return

    try:
        content = go_mod.read_text()
        in_require = False

        for line in content.splitlines():
            stripped = line.strip()

            if stripped.startswith("require ("):
                in_require = True
                continue
            elif stripped == ")" and in_require:
                in_require = False
                continue

            if in_require or stripped.startswith("require "):
                # Parse: module/path v1.2.3
                match = re.match(r'^(?:require\s+)?([a-zA-Z0-9_./-]+)\s+(v[\d.]+)', stripped)
                if match:
                    deps.append(Dependency(
                        name=match.group(1),
                        version=match.group(2),
                        ecosystem="go",
                        source_file="go.mod",
                    ))
    except Exception:
        pass


def _parse_cargo_toml(project_path: Path, deps: list[Dependency]) -> None:
    """Parse Cargo.toml."""
    cargo_path = project_path / "Cargo.toml"
    if not cargo_path.exists():
        return

    try:
        content = cargo_path.read_text()
        in_deps = False
        is_dev = False

        for line in content.splitlines():
            stripped = line.strip()

            if stripped == "[dependencies]":
                in_deps = True
                is_dev = False
                continue
            elif stripped == "[dev-dependencies]":
                in_deps = True
                is_dev = True
                continue
            elif stripped.startswith("["):
                in_deps = False
                continue

            if in_deps:
                # name = "version" or name = { version = "..." }
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([\d.*^~]+)"', stripped)
                if match:
                    deps.append(Dependency(
                        name=match.group(1),
                        version=_clean_version(match.group(2)),
                        ecosystem="crates.io",
                        source_file="Cargo.toml",
                        is_dev=is_dev,
                    ))
                else:
                    # name = { version = "..." }
                    match = re.match(
                        r'^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([\d.*^~]+)"', stripped
                    )
                    if match:
                        deps.append(Dependency(
                            name=match.group(1),
                            version=_clean_version(match.group(2)),
                            ecosystem="crates.io",
                            source_file="Cargo.toml",
                            is_dev=is_dev,
                        ))
    except Exception:
        pass


def _parse_gemfile_lock(project_path: Path, deps: list[Dependency]) -> None:
    """Parse Gemfile.lock for Ruby dependencies."""
    lock_path = project_path / "Gemfile.lock"
    if not lock_path.exists():
        return

    try:
        content = lock_path.read_text()
        in_specs = False

        for line in content.splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            elif not line.startswith(" ") and in_specs:
                in_specs = False
                continue

            if in_specs:
                # Match "    gem-name (1.2.3)"
                match = re.match(r'^\s{4}([a-zA-Z0-9_.-]+)\s+\(([\d.]+)', line)
                if match:
                    deps.append(Dependency(
                        name=match.group(1),
                        version=match.group(2),
                        ecosystem="rubygems",
                        source_file="Gemfile.lock",
                    ))
    except Exception:
        pass


def _parse_pom_xml(project_path: Path, deps: list[Dependency]) -> None:
    """Parse Maven pom.xml (basic XML parsing without lxml)."""
    pom_path = project_path / "pom.xml"
    if not pom_path.exists():
        return

    try:
        content = pom_path.read_text()
        # Simple regex-based parsing for dependency blocks
        dep_pattern = re.compile(
            r'<dependency>\s*'
            r'<groupId>([^<]+)</groupId>\s*'
            r'<artifactId>([^<]+)</artifactId>\s*'
            r'(?:<version>([^<]+)</version>)?',
            re.DOTALL,
        )
        for match in dep_pattern.finditer(content):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = (match.group(3) or "").strip()
            deps.append(Dependency(
                name=f"{group_id}:{artifact_id}",
                version=version,
                ecosystem="maven",
                source_file="pom.xml",
            ))
    except Exception:
        pass


def _parse_composer_json(project_path: Path, deps: list[Dependency]) -> None:
    """Parse PHP composer.json."""
    composer_path = project_path / "composer.json"
    if not composer_path.exists():
        return

    try:
        with open(composer_path) as f:
            data = json.load(f)

        for name, version in data.get("require", {}).items():
            if name == "php" or name.startswith("ext-"):
                continue
            deps.append(Dependency(
                name=name,
                version=_clean_version(version),
                ecosystem="packagist",
                source_file="composer.json",
            ))
        for name, version in data.get("require-dev", {}).items():
            if name == "php" or name.startswith("ext-"):
                continue
            deps.append(Dependency(
                name=name,
                version=_clean_version(version),
                ecosystem="packagist",
                source_file="composer.json",
                is_dev=True,
            ))
    except Exception:
        pass


def _clean_version(version: str) -> str:
    """Clean version specifiers (^, ~, >=, etc.) to get a bare version."""
    return re.sub(r'^[\^~>=<!\s*]+', '', version).strip()
