"""Tests for the CLI commands."""


from typer.testing import CliRunner

from ossguard.cli import app

runner = CliRunner()


class TestInitCommand:
    def test_init_empty_project(self, tmp_path):
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert "Phase 1" in result.output
        assert "Phase 2" in result.output
        assert "Phase 3" in result.output
        # Check files were created
        assert (tmp_path / "SECURITY.md").exists()
        assert (tmp_path / ".github" / "workflows" / "scorecard.yml").exists()
        assert (tmp_path / ".github" / "dependabot.yml").exists()
        assert (tmp_path / ".github" / "workflows" / "sbom.yml").exists()
        assert (tmp_path / ".github" / "workflows" / "sigstore.yml").exists()
        assert (tmp_path / ".github" / "BRANCH_PROTECTION.md").exists()

    def test_init_dry_run(self, tmp_path):
        result = runner.invoke(app, ["init", str(tmp_path), "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.output
        # No files should be created
        assert not (tmp_path / "SECURITY.md").exists()

    def test_init_with_email(self, tmp_path):
        result = runner.invoke(app, ["init", str(tmp_path), "--email", "sec@example.com"])
        assert result.exit_code == 0
        security_md = (tmp_path / "SECURITY.md").read_text()
        assert "sec@example.com" in security_md

    def test_init_skip_scorecard(self, tmp_path):
        result = runner.invoke(app, ["init", str(tmp_path), "--skip-scorecard"])
        assert result.exit_code == 0
        assert not (tmp_path / ".github" / "workflows" / "scorecard.yml").exists()

    def test_init_skips_existing(self, tmp_path):
        # Create existing SECURITY.md
        (tmp_path / "SECURITY.md").write_text("existing")
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        # Should not overwrite
        assert (tmp_path / "SECURITY.md").read_text() == "existing"

    def test_init_force_overwrites(self, tmp_path):
        (tmp_path / "SECURITY.md").write_text("old content")
        result = runner.invoke(app, ["init", str(tmp_path), "--force"])
        assert result.exit_code == 0
        content = (tmp_path / "SECURITY.md").read_text()
        assert "Security Policy" in content

    def test_init_python_project(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='test'")
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        # Should detect Python and create CodeQL with Python
        codeql = tmp_path / ".github" / "workflows" / "codeql.yml"
        if codeql.exists():
            assert "python" in codeql.read_text().lower()

    def test_init_invalid_path(self):
        result = runner.invoke(app, ["init", "/nonexistent/path"])
        assert result.exit_code == 1


class TestScanCommand:
    def test_scan_empty_project(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "Security Posture Score" in result.output
        assert "0/6" in result.output

    def test_scan_with_security_md(self, tmp_path):
        (tmp_path / "SECURITY.md").write_text("# Security")
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "1/6" in result.output

    def test_scan_suggests_init(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "ossguard init" in result.output


class TestVersionCommand:
    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
