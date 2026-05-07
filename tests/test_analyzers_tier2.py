"""Tests for Tier 1-3 analyzers: baseline, insights, pin, secrets, slsa, sbom_gen,
supply_chain, container, compare, update, maturity, fuzz."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------
class TestBaseline:
    def test_empty_project(self, tmp_path):
        from ossguard.analyzers.baseline import check_baseline

        report = check_baseline(tmp_path, target_level=1)
        assert report.level1_total > 0
        assert report.achieved_level == 0  # nothing passes

    def test_level1_partial(self, tmp_path):
        from ossguard.analyzers.baseline import check_baseline

        (tmp_path / "README.md").write_text("# My Project\n\n## Install\npip install myproject\n")
        (tmp_path / "LICENSE").write_text("MIT License")
        (tmp_path / "SECURITY.md").write_text("Report vulns to ...")

        report = check_baseline(tmp_path, target_level=1)
        passing = [c for c in report.controls if c.status == "pass"]
        assert len(passing) >= 3  # README, LICENSE, SECURITY.md

    def test_level2_checks(self, tmp_path):
        from ossguard.analyzers.baseline import check_baseline

        (tmp_path / "CHANGELOG.md").write_text("## 1.0.0\n- Initial release")
        report = check_baseline(tmp_path, target_level=2)
        changelog_ctrl = [c for c in report.controls if c.id == "OSPS-DO-04"]
        assert len(changelog_ctrl) == 1
        assert changelog_ctrl[0].status == "pass"

    def test_level3_filter(self, tmp_path):
        from ossguard.analyzers.baseline import check_baseline

        report = check_baseline(tmp_path, target_level=1)
        l3 = [c for c in report.controls if c.level == 3]
        assert len(l3) == 0  # Level 3 controls excluded


# ---------------------------------------------------------------------------
# Insights
# ---------------------------------------------------------------------------
class TestInsights:
    def test_generate_insights(self, tmp_path):
        from ossguard.analyzers.insights import generate_insights

        (tmp_path / "README.md").write_text("# Hello")
        (tmp_path / "SECURITY.md").write_text("Report issues")
        (tmp_path / "package.json").write_text('{"name": "test"}')

        content = generate_insights(tmp_path)
        assert "schema-version" in content
        assert "vulnerability-reporting" in content

    def test_validate_missing(self, tmp_path):
        from ossguard.analyzers.insights import validate_insights

        report = validate_insights(tmp_path)
        assert not report.valid
        assert any("No SECURITY-INSIGHTS.yml" in e for e in report.errors)

    def test_validate_valid(self, tmp_path):
        import yaml
        from ossguard.analyzers.insights import validate_insights

        data = {
            "header": {"schema-version": "1.0.0", "expiry-date": "2027-01-01", "last-updated": "2026-01-01"},
            "project-lifecycle": {"status": "active"},
            "vulnerability-reporting": {"accepts-vulnerability-reports": True},
        }
        (tmp_path / "SECURITY-INSIGHTS.yml").write_text(yaml.dump(data))
        report = validate_insights(tmp_path)
        assert report.valid

    def test_validate_invalid_yaml(self, tmp_path):
        from ossguard.analyzers.insights import validate_insights

        (tmp_path / "SECURITY-INSIGHTS.yml").write_text("not: [valid: yaml: !!!")
        report = validate_insights(tmp_path)
        assert not report.valid


# ---------------------------------------------------------------------------
# Pin
# ---------------------------------------------------------------------------
class TestPin:
    def test_no_workflows(self, tmp_path):
        from ossguard.analyzers.pin import scan_actions

        report = scan_actions(tmp_path)
        assert report.total_refs == 0

    def test_scan_finds_refs(self, tmp_path):
        from ossguard.analyzers.pin import scan_actions

        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "jobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/setup-python@v5\n"
        )

        report = scan_actions(tmp_path)
        assert report.total_refs == 2
        assert report.already_pinned_count == 0
        assert all(not a.already_pinned for a in report.actions)

    def test_scan_detects_pinned(self, tmp_path):
        from ossguard.analyzers.pin import scan_actions

        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        sha = "a" * 40
        (wf_dir / "ci.yml").write_text(
            f"jobs:\n  build:\n    steps:\n"
            f"      - uses: actions/checkout@{sha}\n"
        )

        report = scan_actions(tmp_path)
        assert report.total_refs == 1
        assert report.already_pinned_count == 1


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
class TestSecrets:
    def test_clean_project(self, tmp_path):
        from ossguard.analyzers.secrets import scan_secrets

        (tmp_path / "main.py").write_text("print('hello world')\n")
        report = scan_secrets(tmp_path)
        assert report.clean

    def test_detect_github_token(self, tmp_path):
        from ossguard.analyzers.secrets import scan_secrets

        (tmp_path / "config.py").write_text("TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'\n")
        report = scan_secrets(tmp_path)
        assert not report.clean
        assert any(f.rule_id == "github-token" for f in report.findings)

    def test_detect_aws_key(self, tmp_path):
        from ossguard.analyzers.secrets import scan_secrets

        (tmp_path / "env.sh").write_text("export AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        report = scan_secrets(tmp_path)
        assert any(f.rule_id == "aws-access-key" for f in report.findings)

    def test_detect_private_key(self, tmp_path):
        from ossguard.analyzers.secrets import scan_secrets

        (tmp_path / "key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nblah\n-----END RSA PRIVATE KEY-----\n")
        report = scan_secrets(tmp_path)
        assert any(f.rule_id == "private-key-rsa" for f in report.findings)

    def test_ignore_file(self, tmp_path):
        from ossguard.analyzers.secrets import scan_secrets

        (tmp_path / "config.py").write_text("TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'\n")
        (tmp_path / ".ossguard-secrets-ignore").write_text("config.py\n")
        report = scan_secrets(tmp_path)
        assert report.clean

    def test_skip_lock_files(self, tmp_path):
        from ossguard.analyzers.secrets import scan_secrets

        (tmp_path / "package-lock.json").write_text('{"resolved": "sha512-AKIAIOSFODNN7EXAMPLE"}')
        report = scan_secrets(tmp_path)
        assert report.clean


# ---------------------------------------------------------------------------
# SLSA
# ---------------------------------------------------------------------------
class TestSLSA:
    def test_empty_project(self, tmp_path):
        from ossguard.analyzers.slsa import check_slsa

        report = check_slsa(tmp_path)
        assert report.achieved_level == 0
        assert report.total_count > 0

    def test_with_ci(self, tmp_path):
        from ossguard.analyzers.slsa import check_slsa

        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
        report = check_slsa(tmp_path)
        # Should at least meet CI requirement
        ci_req = [r for r in report.requirements if r.id == "slsa-l1-ci"]
        assert ci_req[0].status == "met"

    def test_with_slsa_generator(self, tmp_path):
        from ossguard.analyzers.slsa import check_slsa

        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "release.yml").write_text(
            "name: Release\njobs:\n  provenance:\n"
            "    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1\n"
        )
        report = check_slsa(tmp_path)
        prov = [r for r in report.requirements if r.id == "slsa-l1-provenance"]
        assert prov[0].status == "met"


# ---------------------------------------------------------------------------
# SBOM Gen
# ---------------------------------------------------------------------------
class TestSBOMGen:
    def test_spdx_generation(self, tmp_path):
        from ossguard.analyzers.sbom_gen import generate_sbom

        (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests==2.31.0\n")
        content = generate_sbom(tmp_path, sbom_format="spdx")
        data = json.loads(content)
        assert data["spdxVersion"] == "SPDX-2.3"
        assert len(data["packages"]) >= 3  # root + 2 deps

    def test_cyclonedx_generation(self, tmp_path):
        from ossguard.analyzers.sbom_gen import generate_sbom

        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"express": "4.18.0", "lodash": "4.17.21"}
        }))
        content = generate_sbom(tmp_path, sbom_format="cyclonedx")
        data = json.loads(content)
        assert data["bomFormat"] == "CycloneDX"
        assert len(data["components"]) >= 2

    def test_empty_project(self, tmp_path):
        from ossguard.analyzers.sbom_gen import generate_sbom

        content = generate_sbom(tmp_path)
        data = json.loads(content)
        assert data["spdxVersion"] == "SPDX-2.3"
        assert len(data["packages"]) == 1  # root only


# ---------------------------------------------------------------------------
# Supply Chain
# ---------------------------------------------------------------------------
class TestSupplyChain:
    def test_empty_project(self, tmp_path):
        from ossguard.analyzers.supply_chain import check_supply_chain

        report = check_supply_chain(tmp_path)
        assert report.clean
        assert report.total_deps == 0

    @patch("ossguard.analyzers.supply_chain.OSVClient")
    def test_typosquat_detection(self, mock_osv_cls, tmp_path):
        from ossguard.analyzers.supply_chain import check_supply_chain

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.query.return_value = []
        mock_osv_cls.return_value = mock_client

        # "reqests" is a typosquat of "requests" (edit distance 1)
        (tmp_path / "requirements.txt").write_text("reqests==2.31.0\n")
        report = check_supply_chain(tmp_path, check_malicious=False)
        typos = [f for f in report.findings if f.finding_type == "typosquat"]
        assert len(typos) >= 1

    def test_no_typosquat_clean(self, tmp_path):
        from ossguard.analyzers.supply_chain import check_supply_chain

        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
        report = check_supply_chain(tmp_path, check_malicious=False, check_typosquats=True)
        typos = [f for f in report.findings if f.finding_type == "typosquat"]
        assert len(typos) == 0

    def test_levenshtein(self):
        from ossguard.analyzers.supply_chain import _levenshtein_distance

        assert _levenshtein_distance("requests", "requests") == 0
        assert _levenshtein_distance("reqeusts", "requests") == 2
        assert _levenshtein_distance("", "abc") == 3
        assert _levenshtein_distance("kitten", "sitting") == 3


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------
class TestContainer:
    def test_no_dockerfile(self, tmp_path):
        from ossguard.analyzers.container import scan_containers

        report = scan_containers(tmp_path)
        assert report.files_scanned == 0

    def test_detect_latest_tag(self, tmp_path):
        from ossguard.analyzers.container import scan_containers

        (tmp_path / "Dockerfile").write_text("FROM python:latest\nRUN pip install flask\n")
        report = scan_containers(tmp_path)
        assert any(f.rule_id == "DL-001" for f in report.findings)

    def test_detect_no_user(self, tmp_path):
        from ossguard.analyzers.container import scan_containers

        (tmp_path / "Dockerfile").write_text("FROM python:3.12\nCOPY . /app\nCMD ['python', 'app.py']\n")
        report = scan_containers(tmp_path)
        user_findings = [f for f in report.findings if f.rule_id == "DL-010"]
        assert len(user_findings) >= 1

    def test_detect_secrets_in_build(self, tmp_path):
        from ossguard.analyzers.container import scan_containers

        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "ARG SECRET_KEY=mysupersecret123\n"
            "USER nobody\n"
        )
        report = scan_containers(tmp_path)
        assert any(f.rule_id == "DL-020" for f in report.findings)

    def test_detect_curl_pipe(self, tmp_path):
        from ossguard.analyzers.container import scan_containers

        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:22.04\n"
            "RUN curl -s https://example.com/script.sh | bash\n"
            "USER app\n"
        )
        report = scan_containers(tmp_path)
        assert any(f.rule_id == "DL-032" for f in report.findings)

    def test_missing_dockerignore(self, tmp_path):
        from ossguard.analyzers.container import scan_containers

        (tmp_path / "Dockerfile").write_text("FROM python:3.12\nUSER app\n")
        report = scan_containers(tmp_path)
        assert any(f.rule_id == "DL-060" for f in report.findings)


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------
class TestCompare:
    @patch("ossguard.analyzers.compare.run_audit")
    def test_compare_two_projects(self, mock_audit, tmp_path):
        from ossguard.analyzers.audit import AuditReport
        from ossguard.analyzers.compare import compare_projects
        from ossguard.detector import ProjectInfo

        proj_a = tmp_path / "a"
        proj_b = tmp_path / "b"
        proj_a.mkdir()
        proj_b.mkdir()

        report_a = AuditReport()
        report_a.overall_grade = "B"
        report_a.config_score = 5
        report_a.config_total = 7
        report_a.findings = ["f1"]
        report_a.project_info = ProjectInfo(path=proj_a, repo_name="project-a")

        report_b = AuditReport()
        report_b.overall_grade = "C"
        report_b.config_score = 3
        report_b.config_total = 7
        report_b.findings = ["f1", "f2", "f3"]
        report_b.project_info = ProjectInfo(path=proj_b, repo_name="project-b")

        mock_audit.side_effect = [report_a, report_b]

        result = compare_projects(proj_a, proj_b)
        assert result.project_a_name == "project-a"
        assert result.project_b_name == "project-b"
        assert result.winner == "a"  # A is better


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------
class TestUpdate:
    def test_empty_project(self, tmp_path):
        from ossguard.analyzers.update import check_updates

        report = check_updates(tmp_path)
        assert report.total_updates == 0

    @patch("ossguard.analyzers.update.DepsDevClient")
    @patch("ossguard.analyzers.update.analyze_dependencies")
    @patch("ossguard.analyzers.update.parse_dependencies")
    def test_finds_updates(self, mock_parse, mock_analyze, mock_ddc, tmp_path):
        from ossguard.analyzers.dep_health import DepHealthReport
        from ossguard.analyzers.update import check_updates
        from ossguard.parsers.dependencies import Dependency

        deps = [Dependency(name="flask", version="2.0.0", ecosystem="pypi")]
        mock_parse.return_value = deps
        mock_analyze.return_value = DepHealthReport(results=[], total_deps=1)

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        pkg_info = MagicMock()
        pkg_info.latest_version = "3.0.0"
        mock_client.get_package.return_value = pkg_info
        mock_ddc.return_value = mock_client

        report = check_updates(tmp_path)
        assert report.total_updates == 1
        assert report.candidates[0].latest_version == "3.0.0"


# ---------------------------------------------------------------------------
# Maturity (S2C2F)
# ---------------------------------------------------------------------------
class TestMaturity:
    def test_empty_project(self, tmp_path):
        from ossguard.analyzers.maturity import assess_maturity

        report = assess_maturity(tmp_path)
        assert report.achieved_level == 0
        assert len(report.practices) > 0

    def test_with_deps_and_dependabot(self, tmp_path):
        from ossguard.analyzers.maturity import assess_maturity

        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
        ghdir = tmp_path / ".github"
        ghdir.mkdir()
        (ghdir / "dependabot.yml").write_text("version: 2\n")

        report = assess_maturity(tmp_path)
        # Should have met some Level 1 practices
        met = [p for p in report.practices if p.level == 1 and p.status == "met"]
        assert len(met) >= 3  # ING-1, ING-2, ING-3, SCN-1


# ---------------------------------------------------------------------------
# Fuzz
# ---------------------------------------------------------------------------
class TestFuzz:
    def test_empty_project(self, tmp_path):
        from ossguard.analyzers.fuzz import check_fuzz_readiness

        report = check_fuzz_readiness(tmp_path)
        assert not report.has_fuzzing
        assert report.readiness_score == 0

    def test_python_atheris(self, tmp_path):
        from ossguard.analyzers.fuzz import check_fuzz_readiness

        (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
        (tmp_path / "fuzz_test.py").write_text(
            "import atheris\nimport sys\n\n"
            "@atheris.instrument_func\n"
            "def fuzz(data):\n    pass\n"
        )

        report = check_fuzz_readiness(tmp_path)
        assert report.has_fuzzing
        assert report.framework == "Atheris"
        assert report.readiness_score >= 50

    def test_go_native_fuzz(self, tmp_path):
        from ossguard.analyzers.fuzz import check_fuzz_readiness

        (tmp_path / "go.mod").write_text("module example.com/mymod\ngo 1.21\n")
        (tmp_path / "fuzz_test.go").write_text(
            "package mymod\n\nimport \"testing\"\n\n"
            "func FuzzParse(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, data []byte) {})\n}\n"
        )

        report = check_fuzz_readiness(tmp_path)
        assert report.has_fuzzing
        assert report.framework == "Go native fuzzing"

    def test_rust_cargo_fuzz(self, tmp_path):
        from ossguard.analyzers.fuzz import check_fuzz_readiness

        (tmp_path / "Cargo.toml").write_text('[package]\nname = "test"\nversion = "0.1.0"\n')
        fuzz_dir = tmp_path / "fuzz"
        fuzz_dir.mkdir()
        (fuzz_dir / "Cargo.toml").write_text('[package]\nname = "test-fuzz"\n')

        report = check_fuzz_readiness(tmp_path)
        assert report.has_fuzzing
        assert "cargo-fuzz" in report.framework

    def test_starter_harness_python(self, tmp_path):
        from ossguard.analyzers.fuzz import check_fuzz_readiness

        (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
        report = check_fuzz_readiness(tmp_path)
        assert "atheris" in report.starter_harness

    def test_clusterfuzzlite_detection(self, tmp_path):
        from ossguard.analyzers.fuzz import check_fuzz_readiness

        cfl_dir = tmp_path / ".clusterfuzzlite"
        cfl_dir.mkdir()
        (cfl_dir / "project.yaml").write_text("language: python\n")

        report = check_fuzz_readiness(tmp_path)
        existing = [f for f in report.findings if f.category == "existing"]
        assert len(existing) >= 1
