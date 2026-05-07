"""Generate CodeQL security scanning workflow."""

from __future__ import annotations

# Languages supported by CodeQL
_CODEQL_LANGUAGES: dict[str, str] = {
    "javascript": "javascript-typescript",
    "typescript": "javascript-typescript",
    "python": "python",
    "java": "java-kotlin",
    "kotlin": "java-kotlin",
    "csharp": "csharp",
    "c/c++": "c-cpp",
    "go": "go",
    "ruby": "ruby",
}


def generate_codeql_workflow(languages: list[str]) -> str | None:
    """Generate a GitHub Actions workflow for CodeQL code scanning.

    Reference: https://docs.github.com/en/code-security/code-scanning
    Returns None if no supported languages are detected.
    """
    codeql_langs = set()
    for lang in languages:
        cql = _CODEQL_LANGUAGES.get(lang.lower())
        if cql:
            codeql_langs.add(cql)

    if not codeql_langs:
        return None

    language_list = ", ".join(f"'{lang}'" for lang in sorted(codeql_langs))

    return f"""# CodeQL Analysis - Automated code scanning for security vulnerabilities
# https://docs.github.com/en/code-security/code-scanning
# Finds security vulnerabilities and coding errors in your codebase.

name: "CodeQL"

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]
  schedule:
    # Run weekly on Wednesday at 00:00 UTC
    - cron: '0 0 * * 3'

permissions:
  contents: read

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read

    strategy:
      fail-fast: false
      matrix:
        language: [{language_list}]

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{{{ matrix.language }}}}
          # Use extended queries for more thorough analysis
          queries: security-extended

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{{{ matrix.language }}}}"
"""
