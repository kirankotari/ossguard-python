"""Client for the deps.dev API (dependency metadata, Scorecard, licenses)."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

DEPS_DEV_API_BASE = "https://api.deps.dev/v3alpha"

# Map our ecosystem names to deps.dev system names
_SYSTEM_MAP = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "go",
    "crates.io": "cargo",
    "maven": "maven",
    "rubygems": "rubygems",
    "nuget": "nuget",
    "packagist": "packagist",
}


@dataclass
class ScorecardResult:
    """OpenSSF Scorecard data from deps.dev."""

    overall_score: float = 0.0
    checks: dict[str, int] = field(default_factory=dict)
    date: str = ""
    repo_url: str = ""


@dataclass
class PackageInfo:
    """Package metadata from deps.dev."""

    name: str = ""
    ecosystem: str = ""
    latest_version: str = ""
    license: str = ""
    description: str = ""
    homepage: str = ""
    repo_url: str = ""
    scorecard: ScorecardResult | None = None
    is_deprecated: bool = False
    stars: int = 0


class DepsDevClient:
    """Client for the deps.dev API."""

    def __init__(self, timeout: float = 30.0):
        self._client = httpx.Client(
            base_url=DEPS_DEV_API_BASE,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> DepsDevClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def get_package(self, name: str, ecosystem: str) -> PackageInfo | None:
        """Get package metadata including Scorecard, license, and latest version."""
        system = _SYSTEM_MAP.get(ecosystem)
        if not system:
            return None

        encoded_name = quote(name, safe="")

        try:
            resp = self._client.get(f"/systems/{system}/packages/{encoded_name}")
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None

        # Extract version info
        versions = data.get("versions", [])
        latest_version = ""
        if versions:
            # Get the latest non-prerelease version
            for v in reversed(versions):
                vk = v.get("versionKey", {})
                if not _is_prerelease(vk.get("version", "")):
                    latest_version = vk.get("version", "")
                    break
            if not latest_version and versions:
                latest_version = versions[-1].get("versionKey", {}).get("version", "")

        info = PackageInfo(
            name=name,
            ecosystem=ecosystem,
            latest_version=latest_version,
        )

        return info

    def get_version(self, name: str, version: str, ecosystem: str) -> PackageInfo | None:
        """Get detailed info for a specific package version."""
        system = _SYSTEM_MAP.get(ecosystem)
        if not system:
            return None

        encoded_name = quote(name, safe="")
        encoded_version = quote(version, safe="")

        try:
            resp = self._client.get(
                f"/systems/{system}/packages/{encoded_name}/versions/{encoded_version}"
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None

        # Extract license
        licenses = data.get("licenses", [])
        license_str = ", ".join(licenses) if licenses else ""

        # Extract links
        links = {lnk.get("label", ""): lnk.get("url", "") for lnk in data.get("links", [])}

        info = PackageInfo(
            name=name,
            ecosystem=ecosystem,
            latest_version=version,
            license=license_str,
            homepage=links.get("HOMEPAGE", ""),
            repo_url=links.get("SOURCE_REPO", ""),
        )

        return info

    def get_scorecard(self, repo_url: str) -> ScorecardResult | None:
        """Get OpenSSF Scorecard for a repository via deps.dev project API."""
        if not repo_url:
            return None

        # Normalize repo URL to get project key
        # deps.dev expects: /projects/{type}:{id} e.g. /projects/github.com%2Fowner%2Frepo
        project_id = _normalize_repo_url(repo_url)
        if not project_id:
            return None

        try:
            encoded_id = quote(project_id, safe="")
            resp = self._client.get(f"/projects/{encoded_id}")
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None

        # Extract scorecard from project data
        scorecard_data = data.get("scorecardV2", data.get("scorecard", {}))
        if not scorecard_data:
            return None

        overall = scorecard_data.get("overallScore", 0.0)
        checks = {}
        for check in scorecard_data.get("checks", scorecard_data.get("check", [])):
            check_name = check.get("name", "")
            check_score = check.get("score", 0)
            if check_name:
                checks[check_name] = check_score

        return ScorecardResult(
            overall_score=overall,
            checks=checks,
            date=scorecard_data.get("date", ""),
            repo_url=repo_url,
        )

    def get_package_batch(
        self, packages: list[tuple[str, str, str]]
    ) -> dict[str, PackageInfo]:
        """Get metadata for multiple packages. Returns dict mapping name to PackageInfo."""
        results = {}
        for name, version, ecosystem in packages:
            if version:
                info = self.get_version(name, version, ecosystem)
            else:
                info = self.get_package(name, ecosystem)
            if info:
                results[name] = info
        return results


def _normalize_repo_url(url: str) -> str:
    """Normalize a repository URL to a deps.dev project ID."""
    url = url.rstrip("/")
    # Handle github.com URLs
    for prefix in ["https://", "http://", "git://", "ssh://git@"]:
        if url.startswith(prefix):
            url = url[len(prefix):]
            break

    # Remove .git suffix
    if url.endswith(".git"):
        url = url[:-4]

    # Should now be like: github.com/owner/repo
    parts = url.split("/")
    if len(parts) >= 3 and parts[0] in ("github.com", "gitlab.com", "bitbucket.org"):
        return f"{parts[0]}/{parts[1]}/{parts[2]}"

    return ""


def _is_prerelease(version: str) -> bool:
    """Check if a version string looks like a pre-release."""
    prerelease_markers = ["alpha", "beta", "rc", "dev", "pre", "snapshot", "canary", "nightly"]
    v_lower = version.lower()
    return any(m in v_lower for m in prerelease_markers)
