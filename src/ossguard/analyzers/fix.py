"""Auto-remediation — fix common security issues automatically."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ossguard.analyzers.dep_health import analyze_dependencies
from ossguard.detector import detect_project
from ossguard.parsers.dependencies import Dependency, parse_dependencies


@dataclass
class FixAction:
    """A single remediation action taken or proposed."""

    description: str
    file_path: str = ""
    action_type: str = ""  # "update_dep", "add_file", "patch_config"
    applied: bool = False
    details: str = ""


@dataclass
class FixReport:
    """Report of all remediation actions."""

    actions: list[FixAction] = field(default_factory=list)
    applied_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0

    @property
    def total(self) -> int:
        return len(self.actions)


def auto_fix(
    project_path: str | Path,
    dry_run: bool = False,
    fix_deps: bool = True,
    fix_configs: bool = True,
) -> FixReport:
    """Auto-fix common security issues in a project.

    Supported fixes:
    - Bump vulnerable dependencies to fixed versions
    - Add missing security configuration files
    - Patch insecure configuration patterns

    Args:
        project_path: Path to the project.
        dry_run: If True, only report what would be fixed.
        fix_deps: Whether to fix dependency versions.
        fix_configs: Whether to fix missing config files.

    Returns:
        FixReport with all actions taken.
    """
    path = Path(project_path).resolve()
    actions: list[FixAction] = []
    applied = 0
    skipped = 0
    failed = 0

    # Fix 1: Bump vulnerable deps to fixed versions
    if fix_deps:
        deps = parse_dependencies(path)
        if deps:
            dep_report = analyze_dependencies(deps, include_dev=False)
            for result in dep_report.results:
                for vuln in result.vulns:
                    if vuln.fixed_version:
                        action = FixAction(
                            description=f"Bump {result.dep.name} to {vuln.fixed_version} (fixes {vuln.id})",
                            file_path=result.dep.source_file,
                            action_type="update_dep",
                            details=f"{result.dep.version} → {vuln.fixed_version}",
                        )
                        if not dry_run:
                            success = _bump_dependency(
                                path, result.dep, vuln.fixed_version
                            )
                            action.applied = success
                            if success:
                                applied += 1
                            else:
                                failed += 1
                        else:
                            skipped += 1
                        actions.append(action)

    # Fix 2: Add missing config files
    if fix_configs:
        info = detect_project(path)

        if not info.has_security_md:
            action = FixAction(
                description="Add SECURITY.md vulnerability disclosure policy",
                file_path="SECURITY.md",
                action_type="add_file",
            )
            if not dry_run:
                from ossguard.generators.security_md import generate_security_md
                content = generate_security_md(repo_name=info.repo_name)
                (path / "SECURITY.md").write_text(content)
                action.applied = True
                applied += 1
            else:
                skipped += 1
            actions.append(action)

        if not info.has_dependabot:
            action = FixAction(
                description="Add Dependabot configuration for automated dependency updates",
                file_path=".github/dependabot.yml",
                action_type="add_file",
            )
            if not dry_run:
                from ossguard.generators.dependabot import generate_dependabot_config
                content = generate_dependabot_config(info.package_managers)
                dep_path = path / ".github" / "dependabot.yml"
                dep_path.parent.mkdir(parents=True, exist_ok=True)
                dep_path.write_text(content)
                action.applied = True
                applied += 1
            else:
                skipped += 1
            actions.append(action)

        if not info.has_scorecard:
            action = FixAction(
                description="Add Scorecard workflow for automated security assessment",
                file_path=".github/workflows/scorecard.yml",
                action_type="add_file",
            )
            if not dry_run:
                from ossguard.generators.scorecard import generate_scorecard_workflow
                content = generate_scorecard_workflow()
                sc_path = path / ".github" / "workflows" / "scorecard.yml"
                sc_path.parent.mkdir(parents=True, exist_ok=True)
                sc_path.write_text(content)
                action.applied = True
                applied += 1
            else:
                skipped += 1
            actions.append(action)

    # Fix 3: Patch insecure patterns
    _check_and_fix_npm_scripts(path, actions, dry_run)

    # Recount
    applied = sum(1 for a in actions if a.applied)
    skipped = sum(1 for a in actions if not a.applied and not dry_run)
    if dry_run:
        skipped = len(actions)

    return FixReport(
        actions=actions,
        applied_count=applied,
        skipped_count=skipped,
        failed_count=failed,
    )


def _bump_dependency(project_path: Path, dep: Dependency, new_version: str) -> bool:
    """Attempt to bump a dependency version in its source file."""
    try:
        if dep.source_file == "package.json":
            return _bump_package_json(project_path / "package.json", dep.name, new_version)
        elif dep.source_file == "requirements.txt":
            return _bump_requirements_txt(project_path / "requirements.txt", dep.name, new_version)
        elif dep.source_file == "pyproject.toml":
            return _bump_pyproject_toml(project_path / "pyproject.toml", dep.name, new_version)
        elif dep.source_file == "Cargo.toml":
            return _bump_cargo_toml(project_path / "Cargo.toml", dep.name, new_version)
    except Exception:
        pass
    return False


def _bump_package_json(file_path: Path, name: str, new_version: str) -> bool:
    """Bump a dependency in package.json."""
    if not file_path.exists():
        return False
    try:
        with open(file_path) as f:
            data = json.load(f)

        updated = False
        for section in ["dependencies", "devDependencies"]:
            if name in data.get(section, {}):
                old = data[section][name]
                # Preserve prefix (^, ~, etc.)
                prefix = ""
                for p in ["^", "~", ">=", ">"]:
                    if old.startswith(p):
                        prefix = p
                        break
                data[section][name] = f"{prefix}{new_version}"
                updated = True

        if updated:
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            return True
    except Exception:
        pass
    return False


def _bump_requirements_txt(file_path: Path, name: str, new_version: str) -> bool:
    """Bump a dependency in requirements.txt."""
    if not file_path.exists():
        return False
    try:
        lines = file_path.read_text().splitlines()
        updated = False
        new_lines = []
        for line in lines:
            match = re.match(rf'^({re.escape(name)})\s*([><=~!]+)\s*[\d.*]+', line, re.IGNORECASE)
            if match:
                pkg = match.group(1)
                op = match.group(2)
                new_lines.append(f"{pkg}{op}{new_version}")
                updated = True
            else:
                new_lines.append(line)

        if updated:
            file_path.write_text("\n".join(new_lines) + "\n")
            return True
    except Exception:
        pass
    return False


def _bump_pyproject_toml(file_path: Path, name: str, new_version: str) -> bool:
    """Bump a dependency in pyproject.toml (simple regex approach)."""
    if not file_path.exists():
        return False
    try:
        content = file_path.read_text()
        # Match "name>=version" or "name==version" etc.
        pattern = rf'"{re.escape(name)}(\[.*?\])?\s*([><=~!]+)\s*[\d.*]+"'
        match = re.search(pattern, content)
        if match:
            extras = match.group(1) or ""
            op = match.group(2)
            new_spec = f'"{name}{extras}{op}{new_version}"'
            content = content[:match.start()] + new_spec + content[match.end():]
            file_path.write_text(content)
            return True
    except Exception:
        pass
    return False


def _bump_cargo_toml(file_path: Path, name: str, new_version: str) -> bool:
    """Bump a dependency in Cargo.toml."""
    if not file_path.exists():
        return False
    try:
        content = file_path.read_text()
        # Simple case: name = "version"
        pattern = rf'^({re.escape(name)}\s*=\s*)"[\d.*^~]+"'
        replacement = rf'\g<1>"{new_version}"'
        new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        if new_content != content:
            file_path.write_text(new_content)
            return True
    except Exception:
        pass
    return False


def _check_and_fix_npm_scripts(
    project_path: Path, actions: list[FixAction], dry_run: bool
) -> None:
    """Check for insecure npm script patterns (e.g. no --ignore-scripts)."""
    npmrc = project_path / ".npmrc"
    if (project_path / "package.json").exists() and not npmrc.exists():
        action = FixAction(
            description="Add .npmrc with security-hardened defaults (ignore-scripts=true for installs)",
            file_path=".npmrc",
            action_type="patch_config",
        )
        if not dry_run:
            npmrc.write_text("# Security: prevent lifecycle script execution on install\nignore-scripts=true\n")
            action.applied = True
        actions.append(action)
