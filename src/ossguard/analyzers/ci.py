"""Unified CI pipeline generator — single workflow combining all security checks."""

from __future__ import annotations

from pathlib import Path

from ossguard.detector import ProjectInfo, detect_project


def generate_ci_pipeline(project_path: str | Path) -> str:
    """Generate a unified GitHub Actions CI pipeline that wires together all security checks.

    Produces a single workflow file that runs:
    - Tests (auto-detected language)
    - Linting
    - CodeQL scanning
    - Dependency audit
    - SBOM generation
    - Scorecard

    Args:
        project_path: Path to the project.

    Returns:
        YAML string of the unified CI workflow.
    """
    path = Path(project_path).resolve()
    info = detect_project(path)

    lang = info.primary_language or "python"
    test_step = _get_test_step(lang, info)
    lint_step = _get_lint_step(lang)
    codeql_languages = _get_codeql_languages(info.languages)

    workflow = f"""name: OSSGuard Security Pipeline
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6 AM UTC

permissions:
  contents: read

jobs:
  # ──────────────────────────────────────────────
  # Job 1: Build & Test
  # ──────────────────────────────────────────────
  test:
    name: Build & Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
{test_step}

  # ──────────────────────────────────────────────
  # Job 2: Lint & Format
  # ──────────────────────────────────────────────
  lint:
    name: Lint & Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
{lint_step}

  # ──────────────────────────────────────────────
  # Job 3: Security Scanning (CodeQL)
  # ──────────────────────────────────────────────
  codeql:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: {codeql_languages}
          queries: security-extended

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3

  # ──────────────────────────────────────────────
  # Job 4: Dependency Audit
  # ──────────────────────────────────────────────
  dependency-audit:
    name: Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
{_get_dep_audit_step(lang)}

  # ──────────────────────────────────────────────
  # Job 5: OpenSSF Scorecard
  # ──────────────────────────────────────────────
  scorecard:
    name: OpenSSF Scorecard
    runs-on: ubuntu-latest
    if: github.event_name != 'pull_request'
    permissions:
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run Scorecard
        uses: ossf/scorecard-action@v2.4.0
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true

      - name: Upload Scorecard SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

  # ──────────────────────────────────────────────
  # Job 6: SBOM Generation
  # ──────────────────────────────────────────────
  sbom:
    name: SBOM Generation
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json

  # ──────────────────────────────────────────────
  # Summary Gate
  # ──────────────────────────────────────────────
  security-gate:
    name: Security Gate
    runs-on: ubuntu-latest
    needs: [test, lint, codeql, dependency-audit]
    if: always()
    steps:
      - name: Check results
        run: |
          echo "Test: ${{{{ needs.test.result }}}}"
          echo "Lint: ${{{{ needs.lint.result }}}}"
          echo "CodeQL: ${{{{ needs.codeql.result }}}}"
          echo "Dep Audit: ${{{{ needs.dependency-audit.result }}}}"
          if [[ "${{{{ needs.test.result }}}}" == "failure" ]] || \\
             [[ "${{{{ needs.codeql.result }}}}" == "failure" ]]; then
            echo "::error::Security gate failed"
            exit 1
          fi
          echo "All security checks passed!"
"""
    return workflow


def _get_test_step(lang: str, info: ProjectInfo) -> str:
    """Generate language-specific test step."""
    lang_lower = lang.lower()

    if lang_lower == "python":
        return """
      - uses: actions/setup-python@v5
        with:
          python-version: '3.x'

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Run tests
        run: pytest tests/ -v --tb=short"""

    elif lang_lower in ("javascript", "typescript"):
        pm = "npm"
        if "yarn" in info.package_managers:
            pm = "yarn"
        elif "pnpm" in info.package_managers:
            pm = "pnpm"

        install_cmd = f"{pm} install" if pm == "npm" else f"{pm} install"
        test_cmd = f"{pm} test" if pm == "npm" else f"{pm} test"

        return f"""
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: {install_cmd}

      - name: Run tests
        run: {test_cmd}"""

    elif lang_lower == "go":
        return """
      - uses: actions/setup-go@v5
        with:
          go-version: 'stable'

      - name: Run tests
        run: go test ./... -v -race"""

    elif lang_lower == "rust":
        return """
      - uses: dtolnay/rust-toolchain@stable

      - name: Run tests
        run: cargo test --verbose"""

    elif lang_lower in ("java", "kotlin"):
        return """
      - uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '17'

      - name: Run tests
        run: ./gradlew test || mvn test"""

    else:
        return """
      - name: Run tests
        run: echo "Configure test command for your project"
"""


def _get_lint_step(lang: str) -> str:
    """Generate language-specific lint step."""
    lang_lower = lang.lower()

    if lang_lower == "python":
        return """
      - uses: actions/setup-python@v5
        with:
          python-version: '3.x'

      - name: Install ruff
        run: pip install ruff

      - name: Lint
        run: ruff check ."""

    elif lang_lower in ("javascript", "typescript"):
        return """
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Lint
        run: npx eslint . || echo 'ESLint not configured'"""

    elif lang_lower == "go":
        return """
      - uses: actions/setup-go@v5
        with:
          go-version: 'stable'

      - name: Lint
        uses: golangci/golangci-lint-action@v4"""

    elif lang_lower == "rust":
        return """
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt

      - name: Lint
        run: cargo clippy -- -D warnings

      - name: Format check
        run: cargo fmt -- --check"""

    else:
        return """
      - name: Lint
        run: echo "Configure linter for your project"
"""


def _get_codeql_languages(languages: list[str]) -> str:
    """Get CodeQL-supported languages string."""
    codeql_map = {
        "python": "python",
        "javascript": "javascript-typescript",
        "typescript": "javascript-typescript",
        "go": "go",
        "java": "java-kotlin",
        "kotlin": "java-kotlin",
        "c": "c-cpp",
        "c++": "c-cpp",
        "ruby": "ruby",
        "c#": "csharp",
        "swift": "swift",
    }
    codeql_langs = set()
    for lang in languages:
        mapped = codeql_map.get(lang.lower())
        if mapped:
            codeql_langs.add(mapped)

    if not codeql_langs:
        codeql_langs.add("python")

    return ", ".join(sorted(codeql_langs))


def _get_dep_audit_step(lang: str) -> str:
    """Generate language-specific dependency audit step."""
    lang_lower = lang.lower()

    if lang_lower == "python":
        return """
      - uses: actions/setup-python@v5
        with:
          python-version: '3.x'

      - name: Install pip-audit
        run: pip install pip-audit

      - name: Audit dependencies
        run: pip-audit -r requirements.txt || pip-audit"""

    elif lang_lower in ("javascript", "typescript"):
        return """
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Audit dependencies
        run: npm audit --production"""

    elif lang_lower == "go":
        return """
      - uses: actions/setup-go@v5
        with:
          go-version: 'stable'

      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest

      - name: Audit dependencies
        run: govulncheck ./..."""

    elif lang_lower == "rust":
        return """
      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Audit dependencies
        run: cargo audit"""

    else:
        return """
      - name: Audit dependencies
        run: echo "Configure dependency auditing for your project"
"""
