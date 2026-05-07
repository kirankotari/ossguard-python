"""Generate Dependabot configuration for automated dependency updates."""

from __future__ import annotations

# Mapping from our detected package managers to Dependabot ecosystem names
_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "pip": "pip",
    "pipenv": "pip",
    "poetry": "pip",
    "go-modules": "gomod",
    "cargo": "cargo",
    "bundler": "bundler",
    "maven": "maven",
    "gradle": "gradle",
    "composer": "composer",
    "pub": "pub",
}


def generate_dependabot_config(package_managers: list[str]) -> str:
    """Generate a dependabot.yml configuration file.

    Reference: https://docs.github.com/en/code-security/dependabot
    """
    ecosystems = set()
    for pm in package_managers:
        eco = _ECOSYSTEM_MAP.get(pm)
        if eco:
            ecosystems.add(eco)

    # Always include github-actions
    ecosystems.add("github-actions")

    # Build the YAML
    entries = []
    for eco in sorted(ecosystems):
        directory = "/"
        entries.append(
            f"""  - package-ecosystem: "{eco}"
    directory: "{directory}"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "security\""""
        )

    updates_block = "\n\n".join(entries)

    return f"""# Dependabot configuration
# https://docs.github.com/en/code-security/dependabot/dependabot-version-updates
# Keeps your dependencies up to date and patches known vulnerabilities.

version: 2

updates:
{updates_block}
"""
