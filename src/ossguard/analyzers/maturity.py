"""S2C2F maturity assessment — Secure Supply Chain Consumption Framework levels."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ossguard.detector import ProjectInfo, detect_project


@dataclass
class S2C2FPractice:
    """A single S2C2F practice."""

    id: str
    level: int  # 1-4
    category: str
    description: str
    status: str = "unknown"  # "met", "unmet", "unknown"
    evidence: str = ""
    recommendation: str = ""


@dataclass
class MaturityReport:
    """S2C2F maturity assessment report."""

    practices: list[S2C2FPractice] = field(default_factory=list)
    achieved_level: int = 0
    level1_pct: float = 0
    level2_pct: float = 0
    level3_pct: float = 0
    level4_pct: float = 0


# S2C2F Practices (aligned with the Secure Supply Chain Consumption Framework)
_PRACTICES: list[tuple[str, int, str, str]] = [
    # Level 1 — Ingest
    ("S2C2F-ING-1", 1, "Ingest", "Use package managers to consume OSS (not copy-paste)"),
    ("S2C2F-ING-2", 1, "Ingest", "Track all OSS dependencies in a manifest file"),
    ("S2C2F-ING-3", 1, "Ingest", "Use an automated dependency update tool"),

    # Level 1 — Scan
    ("S2C2F-SCN-1", 1, "Scan", "Scan OSS for known vulnerabilities"),
    ("S2C2F-SCN-2", 1, "Scan", "Scan OSS for license compliance"),

    # Level 2 — Inventory
    ("S2C2F-INV-1", 2, "Inventory", "Maintain an inventory (SBOM) of all OSS consumed"),
    ("S2C2F-INV-2", 2, "Inventory", "Track transitive dependencies"),

    # Level 2 — Update
    ("S2C2F-UPD-1", 2, "Update", "Apply security patches within defined SLAs"),
    ("S2C2F-UPD-2", 2, "Update", "Automate dependency updates for security fixes"),

    # Level 2 — Enforce
    ("S2C2F-ENF-1", 2, "Enforce", "Block known-vulnerable components from being used"),
    ("S2C2F-ENF-2", 2, "Enforce", "Enforce license compliance policies"),

    # Level 3 — Audit
    ("S2C2F-AUD-1", 3, "Audit", "Perform security audit of critical OSS dependencies"),
    ("S2C2F-AUD-2", 3, "Audit", "Verify provenance of OSS packages"),

    # Level 3 — Fix
    ("S2C2F-FIX-1", 3, "Fix", "Ability to privately patch critical OSS vulnerabilities"),
    ("S2C2F-FIX-2", 3, "Fix", "Contribute security fixes upstream"),

    # Level 3 — Verify
    ("S2C2F-VER-1", 3, "Verify", "Verify signatures on consumed OSS packages"),
    ("S2C2F-VER-2", 3, "Verify", "Validate SBOM accuracy"),

    # Level 4 — Rebuild
    ("S2C2F-REB-1", 4, "Rebuild", "Rebuild OSS from source in a controlled environment"),
    ("S2C2F-REB-2", 4, "Rebuild", "Verify reproducibility of builds"),

    # Level 4 — Secure
    ("S2C2F-SEC-1", 4, "Secure", "Run OSS in sandboxed environments"),
    ("S2C2F-SEC-2", 4, "Secure", "Apply runtime protection and monitoring"),
]


def assess_maturity(project_path: str | Path) -> MaturityReport:
    """Assess a project's S2C2F maturity level.

    Args:
        project_path: Path to the project.

    Returns:
        MaturityReport with practice-level assessments.
    """
    path = Path(project_path).resolve()
    info = detect_project(path)

    practices: list[S2C2FPractice] = []

    for prac_id, level, category, description in _PRACTICES:
        status, evidence, rec = _check_practice(prac_id, info, path)
        practices.append(S2C2FPractice(
            id=prac_id, level=level, category=category,
            description=description, status=status,
            evidence=evidence, recommendation=rec,
        ))

    # Calculate level percentages
    for lvl in range(1, 5):
        lvl_pracs = [p for p in practices if p.level == lvl]
        met = sum(1 for p in lvl_pracs if p.status == "met")
        total = len(lvl_pracs)
        pct = round(met / total * 100, 1) if total else 0

        if lvl == 1:
            report_l1 = pct
        elif lvl == 2:
            report_l2 = pct
        elif lvl == 3:
            report_l3 = pct
        else:
            report_l4 = pct

    # Achieved level
    achieved = 0
    for lvl in range(1, 5):
        lvl_pracs = [p for p in practices if p.level == lvl]
        if lvl_pracs and all(p.status == "met" for p in lvl_pracs):
            achieved = lvl
        else:
            break

    return MaturityReport(
        practices=practices,
        achieved_level=achieved,
        level1_pct=report_l1,
        level2_pct=report_l2,
        level3_pct=report_l3,
        level4_pct=report_l4,
    )


def _check_practice(prac_id: str, info: ProjectInfo, path: Path) -> tuple[str, str, str]:
    """Check a single S2C2F practice."""

    # Level 1 — Ingest
    if prac_id == "S2C2F-ING-1":
        manifests = ["package.json", "requirements.txt", "pyproject.toml", "go.mod",
                      "Cargo.toml", "pom.xml", "composer.json", "Gemfile"]
        for m in manifests:
            if (path / m).exists():
                return "met", f"Package manifest found: {m}", ""
        return "unmet", "", "Use a package manager with a manifest file"

    if prac_id == "S2C2F-ING-2":
        manifests = ["package.json", "requirements.txt", "pyproject.toml", "go.mod",
                      "Cargo.toml", "pom.xml", "composer.json"]
        found = [m for m in manifests if (path / m).exists()]
        if found:
            return "met", f"Dependency manifests: {', '.join(found)}", ""
        return "unmet", "", "Track dependencies in a manifest file"

    if prac_id == "S2C2F-ING-3":
        if info.has_dependabot:
            return "met", "Dependabot configured", ""
        for f in ["renovate.json", ".renovaterc", ".renovaterc.json"]:
            if (path / f).exists():
                return "met", f"Renovate configured: {f}", ""
        return "unmet", "", "Enable Dependabot or Renovate — run `ossguard init`"

    # Level 1 — Scan
    if prac_id == "S2C2F-SCN-1":
        if info.has_dependabot or info.has_codeql:
            return "met", "Vulnerability scanning configured", ""
        return "unmet", "", "Enable vulnerability scanning — run `ossguard deps`"

    if prac_id == "S2C2F-SCN-2":
        # Check for license scanning config
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text().lower()
                    if "license" in content:
                        return "met", f"License scanning found in {wf.name}", ""
        return "unknown", "", "Add license compliance scanning — run `ossguard license`"

    # Level 2 — Inventory
    if prac_id == "S2C2F-INV-1":
        if info.has_sbom_workflow:
            return "met", "SBOM generation workflow found", ""
        for f in ["sbom.json", "sbom.spdx.json", "bom.json"]:
            if (path / f).exists():
                return "met", f"SBOM found: {f}", ""
        return "unmet", "", "Generate SBOMs — run `ossguard sbom`"

    if prac_id == "S2C2F-INV-2":
        lock_files = ["package-lock.json", "yarn.lock", "poetry.lock",
                       "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock"]
        for lf in lock_files:
            if (path / lf).exists():
                return "met", f"Lock file tracks transitive deps: {lf}", ""
        return "unmet", "", "Use lock files to track transitive dependencies"

    # Level 2 — Update
    if prac_id == "S2C2F-UPD-1":
        if info.has_dependabot:
            return "met", "Automated dependency updates configured", ""
        return "unknown", "", "Define and enforce SLAs for security patches"

    if prac_id == "S2C2F-UPD-2":
        if info.has_dependabot:
            return "met", "Dependabot automates security updates", ""
        return "unmet", "", "Enable automated security updates"

    # Level 2 — Enforce
    if prac_id == "S2C2F-ENF-1":
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text().lower()
                    if "dependency-review" in content or "audit" in content:
                        return "met", f"Dependency enforcement found in {wf.name}", ""
        return "unmet", "", "Add dependency review to CI — run `ossguard ci`"

    if prac_id == "S2C2F-ENF-2":
        return "unknown", "", "Implement license compliance enforcement"

    # Level 3 — Audit
    if prac_id == "S2C2F-AUD-1":
        return "unknown", "", "Perform security audits of critical dependencies"

    if prac_id == "S2C2F-AUD-2":
        if info.has_sigstore:
            return "met", "Sigstore verification available", ""
        return "unmet", "", "Verify provenance of consumed packages"

    # Level 3 — Fix
    if prac_id == "S2C2F-FIX-1":
        return "unknown", "", "Establish process for privately patching critical vulnerabilities"

    if prac_id == "S2C2F-FIX-2":
        if info.has_security_md:
            return "met", "Security policy encourages upstream contributions", ""
        return "unknown", "", "Document process for contributing security fixes upstream"

    # Level 3 — Verify
    if prac_id == "S2C2F-VER-1":
        wf_dir = path / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in wf_dir.iterdir():
                if wf.suffix in (".yml", ".yaml"):
                    content = wf.read_text().lower()
                    if "cosign verify" in content or "sigstore" in content:
                        return "met", "Signature verification configured", ""
        return "unmet", "", "Add package signature verification"

    if prac_id == "S2C2F-VER-2":
        return "unknown", "", "Implement SBOM validation processes"

    # Level 4
    if prac_id in ("S2C2F-REB-1", "S2C2F-REB-2", "S2C2F-SEC-1", "S2C2F-SEC-2"):
        return "unknown", "", "Advanced practice — requires organizational process"

    return "unknown", "", ""
