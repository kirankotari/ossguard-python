"""Pin GitHub Actions to commit SHAs — resolve tags to full SHAs for supply-chain safety."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx


@dataclass
class PinAction:
    """A single GitHub Action reference that can be pinned."""

    file: str
    line_number: int
    original: str  # e.g. "actions/checkout@v4"
    owner: str
    repo: str
    ref: str  # e.g. "v4"
    resolved_sha: str = ""
    pinned: str = ""  # e.g. "actions/checkout@abc123..."
    already_pinned: bool = False
    error: str = ""


@dataclass
class PinReport:
    """Report of all pinning actions."""

    actions: list[PinAction] = field(default_factory=list)
    pinned_count: int = 0
    already_pinned_count: int = 0
    failed_count: int = 0
    total_refs: int = 0


# Pattern to match GitHub Actions `uses:` references
_USES_PATTERN = re.compile(
    r"^(\s*-?\s*uses:\s*)([a-zA-Z0-9\-_.]+/[a-zA-Z0-9\-_.]+(?:/[a-zA-Z0-9\-_.]+)?)@(\S+)",
    re.MULTILINE,
)

# A SHA-like ref is 40 hex chars
_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def scan_actions(project_path: str | Path) -> PinReport:
    """Scan all GitHub Actions workflow files and identify unpinned action references.

    Args:
        project_path: Path to the project.

    Returns:
        PinReport with all action references found.
    """
    path = Path(project_path).resolve()
    wf_dir = path / ".github" / "workflows"

    if not wf_dir.is_dir():
        return PinReport()

    actions: list[PinAction] = []
    already = 0
    total = 0

    for wf_file in sorted(wf_dir.iterdir()):
        if wf_file.suffix not in (".yml", ".yaml"):
            continue

        content = wf_file.read_text()
        for match in _USES_PATTERN.finditer(content):
            action_ref = match.group(2)
            ref = match.group(3)
            total += 1

            parts = action_ref.split("/")
            owner = parts[0]
            repo = parts[1] if len(parts) > 1 else ""

            is_pinned = bool(_SHA_PATTERN.match(ref))
            if is_pinned:
                already += 1

            # Calculate line number
            line_num = content[: match.start()].count("\n") + 1

            actions.append(
                PinAction(
                    file=wf_file.name,
                    line_number=line_num,
                    original=f"{action_ref}@{ref}",
                    owner=owner,
                    repo=repo,
                    ref=ref,
                    already_pinned=is_pinned,
                )
            )

    return PinReport(
        actions=actions,
        already_pinned_count=already,
        total_refs=total,
    )


def pin_actions(
    project_path: str | Path,
    dry_run: bool = False,
) -> PinReport:
    """Resolve and pin all GitHub Actions to commit SHAs.

    Args:
        project_path: Path to the project.
        dry_run: If True, resolve SHAs but don't write files.

    Returns:
        PinReport with resolution results.
    """
    path = Path(project_path).resolve()
    report = scan_actions(path)

    if not report.actions:
        return report

    # Resolve SHAs for unpinned actions
    to_resolve = [a for a in report.actions if not a.already_pinned]

    if to_resolve:
        _resolve_shas(to_resolve)

    # Apply pins
    pinned = 0
    failed = 0

    if not dry_run:
        # Group by file
        files: dict[str, list[PinAction]] = {}
        for action in report.actions:
            if not action.already_pinned and action.resolved_sha:
                files.setdefault(action.file, []).append(action)

        wf_dir = path / ".github" / "workflows"
        for filename, file_actions in files.items():
            wf_path = wf_dir / filename
            content = wf_path.read_text()

            for action in file_actions:
                old = f"{action.owner}/{action.repo}@{action.ref}"
                # Add comment with original tag for readability
                new = f"{action.owner}/{action.repo}@{action.resolved_sha}  # {action.ref}"
                action.pinned = f"{action.owner}/{action.repo}@{action.resolved_sha}"
                content = content.replace(old, new, 1)
                pinned += 1

            wf_path.write_text(content)
    else:
        for action in to_resolve:
            if action.resolved_sha:
                action.pinned = f"{action.owner}/{action.repo}@{action.resolved_sha}"
                pinned += 1
            else:
                failed += 1

    report.pinned_count = pinned
    report.failed_count = sum(1 for a in to_resolve if not a.resolved_sha)

    return report


def _resolve_shas(actions: list[PinAction]) -> None:
    """Resolve tag/branch refs to commit SHAs via GitHub API."""
    try:
        with httpx.Client(timeout=10.0) as client:
            seen: dict[str, str] = {}

            for action in actions:
                key = f"{action.owner}/{action.repo}@{action.ref}"
                if key in seen:
                    action.resolved_sha = seen[key]
                    continue

                sha = _resolve_single(client, action.owner, action.repo, action.ref)
                action.resolved_sha = sha
                seen[key] = sha
                if not sha:
                    action.error = "Could not resolve SHA"
    except Exception:
        pass


def _resolve_single(client: httpx.Client, owner: str, repo: str, ref: str) -> str:
    """Resolve a single action ref to a commit SHA."""
    # Try tags first (most common), then branches
    for ref_type in ["tags", "heads"]:
        url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/{ref_type}/{ref}"
        try:
            resp = client.get(url, headers={"Accept": "application/vnd.github.v3+json"})
            if resp.status_code == 200:
                data = resp.json()
                obj = data.get("object", {})
                sha = obj.get("sha", "")

                # If it's an annotated tag, we need to dereference it
                if obj.get("type") == "tag" and sha:
                    tag_url = f"https://api.github.com/repos/{owner}/{repo}/git/tags/{sha}"
                    tag_resp = client.get(
                        tag_url, headers={"Accept": "application/vnd.github.v3+json"}
                    )
                    if tag_resp.status_code == 200:
                        tag_data = tag_resp.json()
                        sha = tag_data.get("object", {}).get("sha", sha)

                return sha
        except Exception:
            continue
    return ""
