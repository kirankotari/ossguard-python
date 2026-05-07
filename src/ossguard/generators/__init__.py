"""Generators for OpenSSF security configurations and files."""

from ossguard.generators.security_md import generate_security_md
from ossguard.generators.scorecard import generate_scorecard_workflow
from ossguard.generators.dependabot import generate_dependabot_config
from ossguard.generators.codeql import generate_codeql_workflow
from ossguard.generators.sbom import generate_sbom_workflow
from ossguard.generators.sigstore import generate_sigstore_workflow
from ossguard.generators.branch_protection import generate_branch_protection_guide

__all__ = [
    "generate_security_md",
    "generate_scorecard_workflow",
    "generate_dependabot_config",
    "generate_codeql_workflow",
    "generate_sbom_workflow",
    "generate_sigstore_workflow",
    "generate_branch_protection_guide",
]
