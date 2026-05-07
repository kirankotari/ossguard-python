"""Generate Sigstore signing workflow for release artifacts."""

from __future__ import annotations


def generate_sigstore_workflow(primary_language: str = "") -> str:
    """Generate a GitHub Actions workflow for Sigstore signing.

    Uses sigstore/gh-action-sigstore-python for Python projects,
    and cosign for other projects.
    Reference: https://docs.sigstore.dev/
    """
    if primary_language == "python":
        return _generate_python_sigstore()
    return _generate_generic_sigstore()


def _generate_python_sigstore() -> str:
    """Generate Sigstore workflow for Python packages."""
    return """# Sigstore Signing - Cryptographic signing for Python releases
# https://docs.sigstore.dev/
# Signs your Python package distributions using Sigstore's keyless signing,
# providing verifiable provenance for your releases.

name: Sign Release (Sigstore)

on:
  release:
    types: [published]

permissions:
  contents: read
  id-token: write  # Required for Sigstore OIDC

jobs:
  sign:
    name: Sign Python Distribution
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Install build dependencies
        run: pip install build

      - name: Build distribution
        run: python -m build

      - name: Sign with Sigstore
        uses: sigstore/gh-action-sigstore-python@v3
        with:
          inputs: ./dist/*.tar.gz ./dist/*.whl

      - name: Upload signed artifacts
        uses: actions/upload-artifact@v4
        with:
          name: signed-dist
          path: |
            dist/*.tar.gz
            dist/*.whl
            dist/*.sigstore.json
"""


def _generate_generic_sigstore() -> str:
    """Generate generic Sigstore workflow using cosign."""
    return """# Sigstore Signing - Cryptographic signing for release artifacts
# https://docs.sigstore.dev/
# Signs your release artifacts using cosign (Sigstore), providing
# verifiable provenance and tamper-evidence for your releases.

name: Sign Release (Sigstore)

on:
  release:
    types: [published]

permissions:
  contents: write
  id-token: write  # Required for Sigstore OIDC

jobs:
  sign:
    name: Sign Release Artifacts
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Download release assets
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          mkdir -p release-assets
          gh release download "${{ github.event.release.tag_name }}" -D release-assets

      - name: Sign each asset with cosign
        run: |
          for file in release-assets/*; do
            cosign sign-blob --yes "$file" \\
              --output-signature "${file}.sig" \\
              --output-certificate "${file}.pem"
          done

      - name: Upload signatures to release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release upload "${{ github.event.release.tag_name }}" \\
            release-assets/*.sig release-assets/*.pem
"""
