"""Parsers for dependency files and SBOMs."""

from ossguard.parsers.dependencies import Dependency, parse_dependencies
from ossguard.parsers.sbom import SBOMInfo, parse_sbom

__all__ = ["Dependency", "parse_dependencies", "SBOMInfo", "parse_sbom"]
