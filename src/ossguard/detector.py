"""Auto-detect project language, framework, and package manager."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProjectInfo:
    """Detected project metadata."""

    path: Path
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    has_github_actions: bool = False
    has_git: bool = False
    has_security_md: bool = False
    has_scorecard: bool = False
    has_dependabot: bool = False
    has_codeql: bool = False
    has_sbom_workflow: bool = False
    has_sigstore: bool = False
    repo_name: str = ""
    primary_language: str = ""

    def summary(self) -> dict[str, any]:
        """Return a summary dict of what's detected and what's missing."""
        return {
            "languages": self.languages,
            "primary_language": self.primary_language,
            "frameworks": self.frameworks,
            "package_managers": self.package_managers,
            "existing": {
                "git": self.has_git,
                "github_actions": self.has_github_actions,
                "security_md": self.has_security_md,
                "scorecard": self.has_scorecard,
                "dependabot": self.has_dependabot,
                "codeql": self.has_codeql,
                "sbom_workflow": self.has_sbom_workflow,
                "sigstore": self.has_sigstore,
            },
        }


# Mapping of files to language/framework/package manager
_LANGUAGE_MARKERS: dict[str, str] = {
    "package.json": "javascript",
    "tsconfig.json": "typescript",
    "pyproject.toml": "python",
    "setup.py": "python",
    "setup.cfg": "python",
    "requirements.txt": "python",
    "Pipfile": "python",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "rust",
    "Gemfile": "ruby",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "kotlin",
    "*.csproj": "csharp",
    "*.sln": "csharp",
    "composer.json": "php",
    "mix.exs": "elixir",
    "pubspec.yaml": "dart",
    "CMakeLists.txt": "c/c++",
    "Makefile": "c/c++",
    "meson.build": "c/c++",
}

_PACKAGE_MANAGER_MARKERS: dict[str, str] = {
    "package.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "pyproject.toml": "pip",
    "Pipfile": "pipenv",
    "poetry.lock": "poetry",
    "requirements.txt": "pip",
    "go.mod": "go-modules",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "composer.json": "composer",
    "pubspec.yaml": "pub",
}

_FRAMEWORK_MARKERS: dict[str, str] = {
    "next.config.js": "Next.js",
    "next.config.mjs": "Next.js",
    "next.config.ts": "Next.js",
    "nuxt.config.ts": "Nuxt",
    "angular.json": "Angular",
    "svelte.config.js": "Svelte",
    "astro.config.mjs": "Astro",
    "vite.config.ts": "Vite",
    "vite.config.js": "Vite",
    "webpack.config.js": "Webpack",
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "manage.py": "Django",
}


def detect_project(project_path: str | Path) -> ProjectInfo:
    """Scan a directory and detect project characteristics."""
    path = Path(project_path).resolve()
    info = ProjectInfo(path=path)

    if not path.is_dir():
        return info

    info.repo_name = path.name
    info.has_git = (path / ".git").is_dir()

    # Scan top-level and one level deep
    files_in_root = set()
    for item in path.iterdir():
        files_in_root.add(item.name)

    # Detect languages and package managers
    for marker, lang in _LANGUAGE_MARKERS.items():
        if marker.startswith("*"):
            ext = marker[1:]
            if any(f.endswith(ext) for f in files_in_root):
                if lang not in info.languages:
                    info.languages.append(lang)
        elif marker in files_in_root:
            if lang not in info.languages:
                info.languages.append(lang)

    for marker, pm in _PACKAGE_MANAGER_MARKERS.items():
        if marker in files_in_root and pm not in info.package_managers:
            info.package_managers.append(pm)

    for marker, fw in _FRAMEWORK_MARKERS.items():
        if marker in files_in_root and fw not in info.frameworks:
            info.frameworks.append(fw)

    # Check for framework references inside package.json
    package_json = path / "package.json"
    if package_json.exists():
        try:
            import json

            with open(package_json) as f:
                pkg = json.load(f)
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            for dep_name in deps:
                if dep_name == "react":
                    _add_unique(info.frameworks, "React")
                elif dep_name == "vue":
                    _add_unique(info.frameworks, "Vue")
                elif dep_name == "@angular/core":
                    _add_unique(info.frameworks, "Angular")
                elif dep_name == "express":
                    _add_unique(info.frameworks, "Express")
                elif dep_name == "fastify":
                    _add_unique(info.frameworks, "Fastify")
        except Exception:
            pass

    # Set primary language
    if info.languages:
        info.primary_language = info.languages[0]

    # Check existing security setup
    github_dir = path / ".github"
    if github_dir.is_dir():
        info.has_github_actions = (github_dir / "workflows").is_dir()

        # Check for SECURITY.md in .github or root
        info.has_security_md = (github_dir / "SECURITY.md").exists()

        # Check for dependabot
        info.has_dependabot = (github_dir / "dependabot.yml").exists() or (
            github_dir / "dependabot.yaml"
        ).exists()

        # Scan workflows for scorecard, codeql, sbom, sigstore
        workflows_dir = github_dir / "workflows"
        if workflows_dir.is_dir():
            for wf_file in workflows_dir.iterdir():
                if wf_file.suffix in (".yml", ".yaml"):
                    try:
                        content = wf_file.read_text().lower()
                        if "scorecard" in content or "ossf/scorecard" in content:
                            info.has_scorecard = True
                        if "codeql" in content:
                            info.has_codeql = True
                        if "sbom" in content or "cyclonedx" in content or "spdx" in content:
                            info.has_sbom_workflow = True
                        if "sigstore" in content or "cosign" in content:
                            info.has_sigstore = True
                    except Exception:
                        pass

    # Also check root for SECURITY.md
    if not info.has_security_md:
        info.has_security_md = (path / "SECURITY.md").exists()

    return info


def _add_unique(lst: list[str], value: str) -> None:
    if value not in lst:
        lst.append(value)
