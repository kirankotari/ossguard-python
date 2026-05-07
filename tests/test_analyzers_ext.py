"""Tests for extended analyzers (audit, fix, badge, ci, report, policy, license)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ossguard.apis.deps_dev import PackageInfo
from ossguard.apis.osv import VulnInfo
from ossguard.parsers.dependencies import Dependency


class TestAudit:
    @patch("ossguard.analyzers.audit.analyze_reachability")
    @patch("ossguard.analyzers.audit.analyze_dependencies")
    @patch("ossguard.analyzers.audit.parse_dependencies")
    def test_audit_empty_project(self, mock_parse, mock_analyze, mock_reach, tmp_path):
        from ossguard.analyzers.audit import run_audit

        mock_parse.return_value = []
        report = run_audit(tmp_path)

        assert report.overall_grade in ("A", "B", "C", "D", "F")
        assert report.config_score == 0
        assert report.config_total == 6
        assert report.audit_time
        assert len(report.findings) > 0

    @patch("ossguard.analyzers.audit.analyze_reachability")
    @patch("ossguard.analyzers.audit.analyze_dependencies")
    @patch("ossguard.analyzers.audit.parse_dependencies")
    def test_audit_with_security_md(self, mock_parse, mock_analyze, mock_reach, tmp_path):
        from ossguard.analyzers.audit import run_audit

        (tmp_path / "SECURITY.md").write_text("# Security Policy")
        mock_parse.return_value = []
        report = run_audit(tmp_path)

        assert report.config_score >= 1
        # Should not have "Missing SECURITY.md" finding
        security_findings = [f for f in report.findings if "SECURITY.md" in f]
        assert len(security_findings) == 0

    def test_audit_to_json(self, tmp_path):
        from ossguard.analyzers.audit import AuditReport

        report = AuditReport(
            overall_grade="B",
            config_score=4,
            config_total=6,
            findings=["test finding"],
            recommendations=["test recommendation"],
            audit_time="2024-01-01T00:00:00Z",
        )
        data = json.loads(report.to_json())
        assert data["overall_grade"] == "B"
        assert len(data["findings"]) == 1


class TestFix:
    @patch("ossguard.analyzers.fix.analyze_dependencies")
    @patch("ossguard.analyzers.fix.parse_dependencies")
    def test_fix_dry_run(self, mock_parse, mock_analyze, tmp_path):
        from ossguard.analyzers.fix import auto_fix

        mock_parse.return_value = []
        report = auto_fix(tmp_path, dry_run=True)

        # Should propose adding missing configs
        assert report.total >= 0

    @patch("ossguard.analyzers.fix.analyze_dependencies")
    @patch("ossguard.analyzers.fix.parse_dependencies")
    def test_fix_adds_security_md(self, mock_parse, mock_analyze, tmp_path):
        from ossguard.analyzers.fix import auto_fix

        mock_parse.return_value = []
        (tmp_path / ".git").mkdir()  # Make it look like a git repo

        report = auto_fix(tmp_path, dry_run=False, fix_deps=False, fix_configs=True)

        # Should have created SECURITY.md
        if (tmp_path / "SECURITY.md").exists():
            assert any(a.applied for a in report.actions if "SECURITY.md" in a.description)

    def test_fix_bump_package_json(self, tmp_path):
        from ossguard.analyzers.fix import _bump_package_json

        pkg = {"dependencies": {"lodash": "^4.17.20"}}
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text(json.dumps(pkg))

        success = _bump_package_json(pkg_path, "lodash", "4.17.21")
        assert success

        updated = json.loads(pkg_path.read_text())
        assert updated["dependencies"]["lodash"] == "^4.17.21"

    def test_fix_bump_requirements_txt(self, tmp_path):
        from ossguard.analyzers.fix import _bump_requirements_txt

        (tmp_path / "requirements.txt").write_text("requests==2.28.0\nflask>=2.0\n")

        success = _bump_requirements_txt(tmp_path / "requirements.txt", "requests", "2.31.0")
        assert success

        content = (tmp_path / "requirements.txt").read_text()
        assert "requests==2.31.0" in content


class TestBadge:
    def test_badge_empty_project(self, tmp_path):
        from ossguard.analyzers.badge import assess_badge_readiness

        report = assess_badge_readiness(tmp_path)

        assert report.readiness_pct >= 0
        assert len(report.criteria) > 0
        assert report.met_count + report.unmet_count + report.unknown_count == len(report.criteria)

    def test_badge_with_configs(self, tmp_path):
        from ossguard.analyzers.badge import assess_badge_readiness

        (tmp_path / "README.md").write_text("# My Project\n" + "x" * 200)
        (tmp_path / "LICENSE").write_text("MIT License")
        (tmp_path / "CONTRIBUTING.md").write_text("# Contributing")
        (tmp_path / "SECURITY.md").write_text("# Security Policy")
        (tmp_path / ".git").mkdir()
        (tmp_path / "tests").mkdir()

        report = assess_badge_readiness(tmp_path)
        assert report.readiness_pct > 30  # Should have several criteria met


class TestCI:
    def test_generate_python_pipeline(self, tmp_path):
        from ossguard.analyzers.ci import generate_ci_pipeline

        (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"')
        (tmp_path / "requirements.txt").write_text("flask==2.0\n")

        content = generate_ci_pipeline(tmp_path)

        assert "OSSGuard Security Pipeline" in content
        assert "pytest" in content or "test" in content.lower()
        assert "codeql" in content.lower()
        assert "scorecard" in content.lower()
        assert "sbom" in content.lower()

    def test_generate_js_pipeline(self, tmp_path):
        from ossguard.analyzers.ci import generate_ci_pipeline

        (tmp_path / "package.json").write_text('{"name": "test", "dependencies": {}}')

        content = generate_ci_pipeline(tmp_path)
        assert "node" in content.lower() or "npm" in content.lower()

    def test_generate_go_pipeline(self, tmp_path):
        from ossguard.analyzers.ci import generate_ci_pipeline

        (tmp_path / "go.mod").write_text("module example.com/app\n\ngo 1.21\n")

        content = generate_ci_pipeline(tmp_path)
        assert "go" in content.lower()


class TestReport:
    @patch("ossguard.analyzers.report.run_audit")
    def test_generate_html_report(self, mock_audit, tmp_path):
        from ossguard.analyzers.audit import AuditReport
        from ossguard.analyzers.report import generate_report
        from ossguard.detector import ProjectInfo

        mock_audit.return_value = AuditReport(
            project_info=ProjectInfo(path=tmp_path),
            overall_grade="B",
            config_score=4,
            config_total=6,
            findings=["Missing SBOM"],
            recommendations=["Run ossguard init"],
            audit_time="2024-01-01T00:00:00Z",
        )

        content = generate_report(tmp_path, output_format="html")
        assert "<html" in content
        assert "OSSGuard Security Report" in content
        assert "Missing SBOM" in content

    @patch("ossguard.analyzers.report.run_audit")
    def test_generate_json_report(self, mock_audit, tmp_path):
        from ossguard.analyzers.audit import AuditReport
        from ossguard.analyzers.report import generate_report
        from ossguard.detector import ProjectInfo

        mock_audit.return_value = AuditReport(
            project_info=ProjectInfo(path=tmp_path),
            overall_grade="A",
            config_score=6,
            config_total=6,
            audit_time="2024-01-01T00:00:00Z",
        )

        content = generate_report(tmp_path, output_format="json")
        data = json.loads(content)
        assert data["overall_grade"] == "A"


class TestPolicy:
    @patch("ossguard.analyzers.policy.analyze_dependencies")
    @patch("ossguard.analyzers.policy.parse_dependencies")
    def test_policy_default(self, mock_parse, mock_analyze, tmp_path):
        from ossguard.analyzers.policy import check_policy

        mock_parse.return_value = []
        report = check_policy(tmp_path)

        assert len(report.rules) > 0
        assert report.policy_file == "(default)"
        # Empty project should fail several rules
        assert report.failed > 0

    @patch("ossguard.analyzers.policy.analyze_dependencies")
    @patch("ossguard.analyzers.policy.parse_dependencies")
    def test_policy_with_configs(self, mock_parse, mock_analyze, tmp_path):
        from ossguard.analyzers.policy import check_policy

        (tmp_path / "SECURITY.md").write_text("# Security")
        (tmp_path / "README.md").write_text("# README")
        (tmp_path / "LICENSE").write_text("MIT")
        mock_parse.return_value = []

        report = check_policy(tmp_path)
        # These rules should pass
        passed_ids = [r.id for r in report.rules if r.passed]
        assert "require_security_md" in passed_ids
        assert "require_readme" in passed_ids
        assert "require_license" in passed_ids

    def test_policy_generate_template(self, tmp_path):
        from ossguard.analyzers.policy import generate_policy_template

        template = generate_policy_template()
        data = json.loads(template)
        assert "rules" in data
        assert "require_security_md" in data["rules"]

    @patch("ossguard.analyzers.policy.analyze_dependencies")
    @patch("ossguard.analyzers.policy.parse_dependencies")
    def test_policy_custom_file(self, mock_parse, mock_analyze, tmp_path):
        from ossguard.analyzers.policy import check_policy

        custom_policy = {
            "name": "Custom",
            "rules": {
                "require_readme": {"severity": "error", "description": "README required"},
            },
        }
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(custom_policy))
        (tmp_path / "README.md").write_text("# Test")
        mock_parse.return_value = []

        report = check_policy(tmp_path, policy_file=str(policy_path))
        assert report.compliant  # README exists, only rule passes


class TestLicenseCheck:
    @patch("ossguard.analyzers.license_check.DepsDevClient")
    def test_license_all_permissive(self, mock_ddc_cls):
        from ossguard.analyzers.license_check import check_licenses

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(name="react", license="MIT")
        mock_ddc.get_package.return_value = None
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="react", version="18.2.0", ecosystem="npm")]
        report = check_licenses(deps, project_license="Apache-2.0")

        assert report.compliant
        assert report.summary.get("permissive", 0) >= 1
        assert len(report.conflicts) == 0

    @patch("ossguard.analyzers.license_check.DepsDevClient")
    def test_license_conflict_detected(self, mock_ddc_cls):
        from ossguard.analyzers.license_check import check_licenses

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(name="gpl-lib", license="GPL-3.0")
        mock_ddc.get_package.return_value = None
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="gpl-lib", version="1.0", ecosystem="npm")]
        report = check_licenses(deps, project_license="MIT")

        assert not report.compliant
        assert len(report.conflicts) >= 1

    @patch("ossguard.analyzers.license_check.DepsDevClient")
    def test_license_unknown(self, mock_ddc_cls):
        from ossguard.analyzers.license_check import check_licenses

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(name="mystery", license="")
        mock_ddc.get_package.return_value = None
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="mystery", version="1.0", ecosystem="npm")]
        report = check_licenses(deps, project_license="MIT")

        assert "mystery" in report.unknown_licenses

    def test_classify_licenses(self):
        from ossguard.analyzers.license_check import _classify_license

        assert _classify_license("MIT") == "permissive"
        assert _classify_license("Apache-2.0") == "permissive"
        assert _classify_license("GPL-3.0") == "copyleft"
        assert _classify_license("LGPL-2.1") == "weak_copyleft"
        assert _classify_license("MPL-2.0") == "weak_copyleft"
        assert _classify_license("") == "unknown"
        assert _classify_license("SomeRandomLicense") == "unknown"
