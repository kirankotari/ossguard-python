"""Tests for the file generators."""

from ossguard.generators.security_md import generate_security_md
from ossguard.generators.scorecard import generate_scorecard_workflow
from ossguard.generators.dependabot import generate_dependabot_config
from ossguard.generators.codeql import generate_codeql_workflow
from ossguard.generators.sbom import generate_sbom_workflow
from ossguard.generators.sigstore import generate_sigstore_workflow
from ossguard.generators.branch_protection import generate_branch_protection_guide


class TestSecurityMd:
    def test_generates_content(self):
        content = generate_security_md("my-project")
        assert "# Security Policy" in content
        assert "my-project" in content
        assert "OpenSSF" in content

    def test_includes_email_when_provided(self):
        content = generate_security_md("test", contact_email="security@example.com")
        assert "security@example.com" in content

    def test_placeholder_when_no_email(self):
        content = generate_security_md("test")
        assert "REPLACE_WITH_SECURITY_EMAIL" in content

    def test_references_cvd_guide(self):
        content = generate_security_md("test")
        assert "ossf/oss-vulnerability-guide" in content


class TestScorecardWorkflow:
    def test_generates_valid_yaml(self):
        content = generate_scorecard_workflow()
        assert "ossf/scorecard-action@v2" in content
        assert "permissions:" in content
        assert "security-events: write" in content

    def test_weekly_schedule(self):
        content = generate_scorecard_workflow()
        assert "cron:" in content


class TestDependabotConfig:
    def test_npm_ecosystem(self):
        content = generate_dependabot_config(["npm"])
        assert 'package-ecosystem: "npm"' in content
        assert 'package-ecosystem: "github-actions"' in content

    def test_pip_ecosystem(self):
        content = generate_dependabot_config(["pip"])
        assert 'package-ecosystem: "pip"' in content

    def test_multiple_ecosystems(self):
        content = generate_dependabot_config(["npm", "pip", "go-modules"])
        assert 'package-ecosystem: "npm"' in content
        assert 'package-ecosystem: "pip"' in content
        assert 'package-ecosystem: "gomod"' in content

    def test_always_includes_github_actions(self):
        content = generate_dependabot_config([])
        assert 'package-ecosystem: "github-actions"' in content

    def test_yarn_maps_to_npm(self):
        content = generate_dependabot_config(["yarn"])
        assert 'package-ecosystem: "npm"' in content


class TestCodeqlWorkflow:
    def test_python_language(self):
        content = generate_codeql_workflow(["python"])
        assert content is not None
        assert "'python'" in content

    def test_javascript_language(self):
        content = generate_codeql_workflow(["javascript"])
        assert content is not None
        assert "'javascript-typescript'" in content

    def test_go_language(self):
        content = generate_codeql_workflow(["go"])
        assert content is not None
        assert "'go'" in content

    def test_unsupported_language_returns_none(self):
        content = generate_codeql_workflow(["dart"])
        assert content is None

    def test_mixed_supported_unsupported(self):
        content = generate_codeql_workflow(["python", "dart"])
        assert content is not None
        assert "'python'" in content

    def test_security_extended_queries(self):
        content = generate_codeql_workflow(["python"])
        assert "security-extended" in content


class TestSbomWorkflow:
    def test_generates_valid_content(self):
        content = generate_sbom_workflow()
        assert "anchore/sbom-action" in content
        assert "spdx-json" in content
        assert "cyclonedx-json" in content

    def test_release_trigger(self):
        content = generate_sbom_workflow()
        assert "release:" in content


class TestSigstoreWorkflow:
    def test_python_sigstore(self):
        content = generate_sigstore_workflow("python")
        assert "sigstore/gh-action-sigstore-python" in content

    def test_generic_cosign(self):
        content = generate_sigstore_workflow("go")
        assert "cosign" in content

    def test_default_generic(self):
        content = generate_sigstore_workflow()
        assert "cosign" in content


class TestBranchProtection:
    def test_generates_guide(self):
        content = generate_branch_protection_guide()
        assert "Branch Protection" in content
        assert "OpenSSF SCM Best Practices" in content
        assert "scorecard" in content.lower()
