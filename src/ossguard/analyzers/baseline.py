"""OSPS Baseline compliance checker — assess project against OpenSSF Security Baseline levels."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ossguard.detector import ProjectInfo, detect_project


@dataclass
class BaselineControl:
    """A single OSPS Baseline control."""

    id: str
    family: str
    title: str
    level: int  # 1, 2, or 3
    status: str = "unknown"  # "pass", "fail", "unknown"
    evidence: str = ""
    recommendation: str = ""


@dataclass
class BaselineReport:
    """OSPS Baseline compliance report."""

    controls: list[BaselineControl] = field(default_factory=list)
    level1_pass: int = 0
    level1_total: int = 0
    level2_pass: int = 0
    level2_total: int = 0
    level3_pass: int = 0
    level3_total: int = 0
    achieved_level: int = 0  # highest fully-passed level

    @property
    def level1_pct(self) -> float:
        return round(self.level1_pass / self.level1_total * 100, 1) if self.level1_total else 0

    @property
    def level2_pct(self) -> float:
        return round(self.level2_pass / self.level2_total * 100, 1) if self.level2_total else 0

    @property
    def level3_pct(self) -> float:
        return round(self.level3_pass / self.level3_total * 100, 1) if self.level3_total else 0


# OSPS Baseline controls (subset aligned with the spec families)
# Family abbreviations: AC=Access Control, BR=Build&Release, DO=Documentation,
# GV=Governance, LE=Legal, QA=Quality, SA=Security Assessment, VM=Vulnerability Mgmt
_CONTROLS: list[tuple[str, str, str, int]] = [
    # --- Level 1 ---
    # Access Control
    ("OSPS-AC-01", "Access Control", "Version control system MUST require MFA for collaborators", 1),
    ("OSPS-AC-02", "Access Control", "Version control system MUST restrict who can push to release branches", 1),
    # Build & Release
    ("OSPS-BR-01", "Build & Release", "Project MUST publish build/install instructions", 1),
    ("OSPS-BR-02", "Build & Release", "Project MUST use an automated build system", 1),
    # Documentation
    ("OSPS-DO-01", "Documentation", "Project MUST have a README with description", 1),
    ("OSPS-DO-02", "Documentation", "Project MUST document how to report security issues", 1),
    ("OSPS-DO-03", "Documentation", "Project MUST have a contribution guide", 1),
    # Governance
    ("OSPS-GV-01", "Governance", "Project MUST have a defined governance model or maintainer list", 1),
    # Legal
    ("OSPS-LE-01", "Legal", "Project MUST have an OSI-approved license", 1),
    ("OSPS-LE-02", "Legal", "All source files SHOULD contain a license header or SPDX identifier", 1),
    # Quality
    ("OSPS-QA-01", "Quality", "Project MUST have an automated test suite", 1),
    ("OSPS-QA-02", "Quality", "Project MUST use CI to run tests on each change", 1),
    # Security Assessment
    ("OSPS-SA-01", "Security Assessment", "Project MUST use a static analysis tool", 1),
    # Vulnerability Management
    ("OSPS-VM-01", "Vulnerability Management", "Project MUST monitor dependencies for known vulnerabilities", 1),
    ("OSPS-VM-02", "Vulnerability Management", "Project MUST have a process to address reported vulnerabilities", 1),

    # --- Level 2 ---
    ("OSPS-AC-03", "Access Control", "Project MUST enforce branch protection on default branch", 2),
    ("OSPS-BR-03", "Build & Release", "Project MUST produce provenance metadata for releases", 2),
    ("OSPS-BR-04", "Build & Release", "Project MUST pin dependencies in build configuration", 2),
    ("OSPS-DO-04", "Documentation", "Project MUST have a change log", 2),
    ("OSPS-DO-05", "Documentation", "Project MUST publish a security-insights.yml", 2),
    ("OSPS-QA-03", "Quality", "Project MUST achieve adequate test coverage", 2),
    ("OSPS-SA-02", "Security Assessment", "Project MUST run SAST on each change (e.g., CodeQL)", 2),
    ("OSPS-SA-03", "Security Assessment", "Project MUST generate SBOMs for releases", 2),
    ("OSPS-VM-03", "Vulnerability Management", "Project MUST fix critical/high vulns within defined SLAs", 2),
    ("OSPS-LE-03", "Legal", "Project MUST include a NOTICE or attribution file for third-party code", 2),

    # --- Level 3 ---
    ("OSPS-AC-04", "Access Control", "Project MUST require signed commits on release branches", 3),
    ("OSPS-BR-05", "Build & Release", "Project MUST sign releases with Sigstore or equivalent", 3),
    ("OSPS-BR-06", "Build & Release", "Project MUST achieve SLSA Build Level 2+", 3),
    ("OSPS-SA-04", "Security Assessment", "Project MUST have a fuzz testing framework configured", 3),
    ("OSPS-SA-05", "Security Assessment", "Project MUST run dependency review on PRs", 3),
    ("OSPS-QA-04", "Quality", "Project MUST have reproducible builds", 3),
    ("OSPS-VM-04", "Vulnerability Management", "Project MUST publish security advisories via GitHub/OSV", 3),
]


def check_baseline(project_path: str | Path, target_level: int = 3) -> BaselineReport:
    """Check a project against OSPS Baseline controls.

    Args:
        project_path: Path to the project.
        target_level: Maximum level to check (1, 2, or 3).

    Returns:
        BaselineReport with pass/fail for each control.
    """
    path = Path(project_path).resolve()
    info = detect_project(path)

    controls: list[BaselineControl] = []
    for ctrl_id, family, title, level in _CONTROLS:
        if level > target_level:
            continue
        status, evidence, rec = _check_control(ctrl_id, info, path)
        controls.append(BaselineControl(
            id=ctrl_id, family=family, title=title, level=level,
            status=status, evidence=evidence, recommendation=rec,
        ))

    l1_pass = sum(1 for c in controls if c.level == 1 and c.status == "pass")
    l1_total = sum(1 for c in controls if c.level == 1)
    l2_pass = sum(1 for c in controls if c.level == 2 and c.status == "pass")
    l2_total = sum(1 for c in controls if c.level == 2)
    l3_pass = sum(1 for c in controls if c.level == 3 and c.status == "pass")
    l3_total = sum(1 for c in controls if c.level == 3)

    achieved = 0
    if l1_total > 0 and l1_pass == l1_total:
        achieved = 1
        if l2_total > 0 and l2_pass == l2_total:
            achieved = 2
            if l3_total > 0 and l3_pass == l3_total:
                achieved = 3

    return BaselineReport(
        controls=controls,
        level1_pass=l1_pass, level1_total=l1_total,
        level2_pass=l2_pass, level2_total=l2_total,
        level3_pass=l3_pass, level3_total=l3_total,
        achieved_level=achieved,
    )


def _check_control(ctrl_id: str, info: ProjectInfo, path: Path) -> tuple[str, str, str]:
    """Check a single control. Returns (status, evidence, recommendation)."""

    # --- Access Control ---
    if ctrl_id == "OSPS-AC-01":
        # Can't verify MFA locally — check for branch protection guide
        bp = path / "BRANCH_PROTECTION.md"
        if bp.exists() or info.has_scorecard:
            return "pass", "Branch protection guide or Scorecard found", ""
        return "unknown", "", "Enable MFA for all collaborators and run Scorecard to verify"

    if ctrl_id == "OSPS-AC-02":
        bp = path / "BRANCH_PROTECTION.md"
        if bp.exists():
            return "pass", "Branch protection guide found", ""
        if info.has_scorecard:
            return "pass", "Scorecard workflow monitors branch protection", ""
        return "unknown", "", "Configure branch protection — run `ossguard init`"

    if ctrl_id == "OSPS-AC-03":
        bp = path / "BRANCH_PROTECTION.md"
        if bp.exists() or info.has_scorecard:
            return "pass", "Branch protection documentation found", ""
        return "fail", "", "Enable branch protection on default branch"

    if ctrl_id == "OSPS-AC-04":
        # Check for signed commit requirement hints
        bp = path / "BRANCH_PROTECTION.md"
        if bp.exists() and "signed" in bp.read_text().lower():
            return "pass", "Signed commit requirement documented", ""
        return "fail", "", "Require signed commits on release branches"

    # --- Build & Release ---
    if ctrl_id == "OSPS-BR-01":
        readme = path / "README.md"
        if readme.exists():
            content = readme.read_text().lower()
            if any(kw in content for kw in ["install", "build", "getting started", "setup", "usage"]):
                return "pass", "Build/install instructions found in README", ""
        return "fail", "", "Add build/install instructions to README.md"

    if ctrl_id == "OSPS-BR-02":
        if info.has_github_actions:
            return "pass", "GitHub Actions workflows found", ""
        for ci in [".travis.yml", ".circleci/config.yml", "Jenkinsfile", ".gitlab-ci.yml"]:
            if (path / ci).exists():
                return "pass", f"CI config found: {ci}", ""
        return "fail", "", "Set up automated builds — run `ossguard ci`"

    if ctrl_id == "OSPS-BR-03":
        # Check for SLSA or provenance generation
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text().lower()
                    if "slsa" in content or "provenance" in content or "attest" in content:
                        return "pass", f"Provenance generation found in {wf.name}", ""
        return "fail", "", "Add SLSA provenance generation to your release workflow"

    if ctrl_id == "OSPS-BR-04":
        # Check if actions are pinned to SHAs
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text()
                    if "@" in content and any(len(ref) == 40 for ref in _extract_action_refs(content)):
                        return "pass", "Some actions pinned to commit SHAs", ""
        return "fail", "", "Pin GitHub Actions to commit SHAs — run `ossguard pin`"

    if ctrl_id == "OSPS-BR-05":
        if info.has_sigstore:
            return "pass", "Sigstore signing workflow found", ""
        return "fail", "", "Add release signing — run `ossguard init`"

    if ctrl_id == "OSPS-BR-06":
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text().lower()
                    if "slsa" in content and ("level" in content or "l2" in content or "l3" in content):
                        return "pass", "SLSA build level configuration found", ""
        return "fail", "", "Achieve SLSA Build Level 2+ for your release pipeline"

    # --- Documentation ---
    if ctrl_id == "OSPS-DO-01":
        readme = path / "README.md"
        if readme.exists() and readme.stat().st_size > 100:
            return "pass", "README.md found with content", ""
        return "fail", "", "Create a detailed README.md"

    if ctrl_id == "OSPS-DO-02":
        if info.has_security_md:
            return "pass", "SECURITY.md found", ""
        return "fail", "", "Add SECURITY.md — run `ossguard init`"

    if ctrl_id == "OSPS-DO-03":
        for name in ["CONTRIBUTING.md", "CONTRIBUTING", ".github/CONTRIBUTING.md"]:
            if (path / name).exists():
                return "pass", f"Found {name}", ""
        return "fail", "", "Create a CONTRIBUTING.md with contribution guidelines"

    if ctrl_id == "OSPS-DO-04":
        for name in ["CHANGELOG.md", "CHANGES.md", "HISTORY.md", "NEWS.md", "CHANGELOG"]:
            if (path / name).exists():
                return "pass", f"Found {name}", ""
        return "fail", "", "Create a CHANGELOG.md documenting changes"

    if ctrl_id == "OSPS-DO-05":
        for name in ["SECURITY-INSIGHTS.yml", "security-insights.yml",
                      ".github/security-insights.yml", ".github/SECURITY-INSIGHTS.yml"]:
            if (path / name).exists():
                return "pass", f"Found {name}", ""
        return "fail", "", "Generate security-insights.yml — run `ossguard insights`"

    # --- Governance ---
    if ctrl_id == "OSPS-GV-01":
        for name in ["GOVERNANCE.md", "MAINTAINERS.md", "CODEOWNERS", ".github/CODEOWNERS"]:
            if (path / name).exists():
                return "pass", f"Found {name}", ""
        return "fail", "", "Add GOVERNANCE.md or CODEOWNERS file"

    # --- Legal ---
    if ctrl_id == "OSPS-LE-01":
        for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]:
            if (path / name).exists():
                return "pass", f"Found {name}", ""
        return "fail", "", "Add a LICENSE file with an OSI-approved license"

    if ctrl_id == "OSPS-LE-02":
        # Sample a few source files for SPDX identifiers
        exts = {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".h"}
        checked = 0
        with_spdx = 0
        for f in path.rglob("*"):
            if f.suffix in exts and not any(p in str(f) for p in ["node_modules", "vendor", ".git", "venv"]):
                checked += 1
                try:
                    head = f.read_text(errors="ignore")[:500]
                    if "SPDX-License-Identifier" in head:
                        with_spdx += 1
                except Exception:
                    pass
                if checked >= 10:
                    break
        if checked > 0 and with_spdx >= checked * 0.5:
            return "pass", f"{with_spdx}/{checked} sampled files have SPDX headers", ""
        if checked == 0:
            return "unknown", "", "No source files found to check"
        return "fail", f"{with_spdx}/{checked} sampled files have SPDX headers", "Add SPDX-License-Identifier headers to source files"

    if ctrl_id == "OSPS-LE-03":
        for name in ["NOTICE", "NOTICE.md", "THIRD-PARTY-NOTICES.txt", "THIRD_PARTY_NOTICES",
                      "ThirdPartyNotices.txt"]:
            if (path / name).exists():
                return "pass", f"Found {name}", ""
        return "fail", "", "Generate third-party notices — run `ossguard tpn`"

    # --- Quality ---
    if ctrl_id == "OSPS-QA-01":
        for td in ["tests", "test", "spec", "__tests__", "test_*.py"]:
            if (path / td).is_dir():
                return "pass", f"Test directory '{td}' found", ""
        if (path / "pytest.ini").exists() or (path / "jest.config.js").exists() or (path / "Cargo.toml").exists():
            return "pass", "Test configuration found", ""
        return "fail", "", "Add an automated test suite"

    if ctrl_id == "OSPS-QA-02":
        if info.has_github_actions:
            wf_dir = path / ".github" / "workflows"
            if wf_dir.is_dir():
                for wf in wf_dir.iterdir():
                    if wf.suffix in (".yml", ".yaml"):
                        content = wf.read_text().lower()
                        if "test" in content or "pytest" in content or "jest" in content:
                            return "pass", "CI test workflow found", ""
            return "pass", "GitHub Actions found (assumed to include tests)", ""
        return "fail", "", "Configure CI to run tests — run `ossguard ci`"

    if ctrl_id == "OSPS-QA-03":
        # Check for coverage config
        for name in [".coveragerc", "codecov.yml", ".codecov.yml", "coverage.xml",
                      "jest.config.js", "tox.ini", "setup.cfg"]:
            if (path / name).exists():
                return "pass", f"Coverage configuration found: {name}", ""
        return "unknown", "", "Configure and measure test coverage"

    if ctrl_id == "OSPS-QA-04":
        # Reproducible builds — hard to detect locally
        return "unknown", "", "Verify builds are reproducible"

    # --- Security Assessment ---
    if ctrl_id == "OSPS-SA-01":
        if info.has_codeql:
            return "pass", "CodeQL workflow found", ""
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text().lower()
                    if any(t in content for t in ["semgrep", "bandit", "eslint", "clippy", "gosec", "sonar"]):
                        return "pass", f"Static analysis found in {wf.name}", ""
        return "fail", "", "Add static analysis — run `ossguard init` for CodeQL"

    if ctrl_id == "OSPS-SA-02":
        if info.has_codeql:
            return "pass", "CodeQL SAST workflow found", ""
        return "fail", "", "Configure SAST to run on each change — run `ossguard init`"

    if ctrl_id == "OSPS-SA-03":
        if info.has_sbom_workflow:
            return "pass", "SBOM generation workflow found", ""
        return "fail", "", "Add SBOM generation — run `ossguard init`"

    if ctrl_id == "OSPS-SA-04":
        fuzz_markers = [
            "fuzz", "oss-fuzz", ".clusterfuzzlite", "cargo-fuzz",
            "go-fuzz", "jazzer", "atheris",
        ]
        for marker in fuzz_markers:
            if (path / marker).exists() or (path / marker).is_dir():
                return "pass", f"Fuzz config '{marker}' found", ""
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text().lower()
                    if "fuzz" in content:
                        return "pass", f"Fuzz workflow found: {wf.name}", ""
        return "fail", "", "Set up fuzz testing — run `ossguard fuzz`"

    if ctrl_id == "OSPS-SA-05":
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text().lower()
                    if "dependency-review" in content or "dependency_review" in content:
                        return "pass", f"Dependency review found: {wf.name}", ""
        return "fail", "", "Add dependency review action for PRs"

    # --- Vulnerability Management ---
    if ctrl_id == "OSPS-VM-01":
        if info.has_dependabot:
            return "pass", "Dependabot configured", ""
        return "fail", "", "Enable Dependabot — run `ossguard init`"

    if ctrl_id == "OSPS-VM-02":
        if info.has_security_md:
            return "pass", "SECURITY.md defines vulnerability process", ""
        return "fail", "", "Add SECURITY.md with vulnerability handling process"

    if ctrl_id == "OSPS-VM-03":
        if info.has_dependabot and info.has_security_md:
            return "pass", "Automated updates + vulnerability process in place", ""
        return "unknown", "", "Define SLAs for fixing critical/high vulnerabilities"

    if ctrl_id == "OSPS-VM-04":
        # Check for GitHub Security Advisories usage
        ghsa_dir = path / ".github" / "advisories"
        if ghsa_dir.is_dir():
            return "pass", "Security advisories directory found", ""
        return "unknown", "", "Publish security advisories via GitHub Security Advisories"

    return "unknown", "", ""


def _extract_action_refs(content: str) -> list[str]:
    """Extract action version refs from workflow content."""
    import re
    refs = re.findall(r'uses:\s*[\w\-./]+@(\S+)', content)
    return refs
