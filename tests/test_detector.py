"""Tests for the project detector."""

import json

import pytest

from ossguard.detector import detect_project


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project directory."""
    return tmp_path


class TestDetectProject:
    def test_empty_directory(self, temp_project):
        info = detect_project(temp_project)
        assert info.path == temp_project
        assert info.languages == []
        assert info.package_managers == []
        assert info.frameworks == []
        assert not info.has_git
        assert not info.has_security_md

    def test_python_project(self, temp_project):
        (temp_project / "pyproject.toml").write_text("[project]\nname = 'test'")
        (temp_project / "setup.py").write_text("")
        info = detect_project(temp_project)
        assert "python" in info.languages
        assert "pip" in info.package_managers
        assert info.primary_language == "python"

    def test_javascript_project(self, temp_project):
        pkg = {"name": "test", "dependencies": {"react": "^18.0.0"}}
        (temp_project / "package.json").write_text(json.dumps(pkg))
        info = detect_project(temp_project)
        assert "javascript" in info.languages
        assert "npm" in info.package_managers
        assert "React" in info.frameworks

    def test_go_project(self, temp_project):
        (temp_project / "go.mod").write_text("module example.com/test\n\ngo 1.21")
        info = detect_project(temp_project)
        assert "go" in info.languages
        assert "go-modules" in info.package_managers

    def test_rust_project(self, temp_project):
        (temp_project / "Cargo.toml").write_text('[package]\nname = "test"')
        info = detect_project(temp_project)
        assert "rust" in info.languages
        assert "cargo" in info.package_managers

    def test_detects_git(self, temp_project):
        (temp_project / ".git").mkdir()
        info = detect_project(temp_project)
        assert info.has_git

    def test_detects_security_md_in_root(self, temp_project):
        (temp_project / "SECURITY.md").write_text("# Security")
        info = detect_project(temp_project)
        assert info.has_security_md

    def test_detects_security_md_in_github(self, temp_project):
        github_dir = temp_project / ".github"
        github_dir.mkdir()
        (github_dir / "SECURITY.md").write_text("# Security")
        info = detect_project(temp_project)
        assert info.has_security_md

    def test_detects_dependabot(self, temp_project):
        github_dir = temp_project / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text("version: 2")
        info = detect_project(temp_project)
        assert info.has_dependabot

    def test_detects_scorecard_workflow(self, temp_project):
        wf_dir = temp_project / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "scorecard.yml").write_text("uses: ossf/scorecard-action@v2")
        info = detect_project(temp_project)
        assert info.has_scorecard

    def test_detects_codeql_workflow(self, temp_project):
        wf_dir = temp_project / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "codeql.yml").write_text("uses: github/codeql-action/init@v3")
        info = detect_project(temp_project)
        assert info.has_codeql

    def test_detects_sbom_workflow(self, temp_project):
        wf_dir = temp_project / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "sbom.yml").write_text("Generate SBOM with CycloneDX")
        info = detect_project(temp_project)
        assert info.has_sbom_workflow

    def test_detects_sigstore_workflow(self, temp_project):
        wf_dir = temp_project / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "sign.yml").write_text("uses: sigstore/cosign-installer@v3")
        info = detect_project(temp_project)
        assert info.has_sigstore

    def test_repo_name(self, temp_project):
        info = detect_project(temp_project)
        assert info.repo_name == temp_project.name

    def test_nonexistent_path(self):
        info = detect_project("/nonexistent/path")
        assert info.languages == []

    def test_summary(self, temp_project):
        (temp_project / "pyproject.toml").write_text("[project]")
        info = detect_project(temp_project)
        summary = info.summary()
        assert "languages" in summary
        assert "existing" in summary
        assert "security_md" in summary["existing"]
