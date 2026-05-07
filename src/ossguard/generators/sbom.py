"""Generate SBOM (Software Bill of Materials) generation workflow."""

from __future__ import annotations


def generate_sbom_workflow() -> str:
    """Generate a GitHub Actions workflow for SBOM generation.

    Uses anchore/sbom-action which supports CycloneDX and SPDX formats.
    Reference: https://github.com/anchore/sbom-action
    """
    return """# SBOM Generation - Software Bill of Materials
# https://github.com/anchore/sbom-action
# Generates an SBOM for every release, providing transparency into
# your project's dependencies as recommended by OpenSSF.

name: Generate SBOM

on:
  release:
    types: [published]
  push:
    branches: [ "main", "master" ]

permissions:
  contents: write

jobs:
  sbom:
    name: Generate SBOM
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Generate SBOM (SPDX)
        uses: anchore/sbom-action@v0
        with:
          format: spdx-json
          output-file: sbom-spdx.json

      - name: Generate SBOM (CycloneDX)
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom-cyclonedx.json

      - name: Upload SBOMs as artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom-spdx.json
            sbom-cyclonedx.json

      - name: Attach SBOMs to release
        if: github.event_name == 'release'
        uses: softprops/action-gh-release@v2
        with:
          files: |
            sbom-spdx.json
            sbom-cyclonedx.json
"""
