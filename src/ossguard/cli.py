"""CLI entry point for ossguard."""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from ossguard import __version__
from ossguard.detector import ProjectInfo, detect_project
from ossguard.generators import (
    generate_branch_protection_guide,
    generate_codeql_workflow,
    generate_dependabot_config,
    generate_sbom_workflow,
    generate_scorecard_workflow,
    generate_security_md,
    generate_sigstore_workflow,
)

app = typer.Typer(
    name="ossguard",
    help="Guard any OSS project with OpenSSF security best practices — bootstrap, scan, and monitor.",
    no_args_is_help=True,
)
console = Console()

BANNER = r"""
   ___  ____ ____   ____                     _
  / _ \/ ___/ ___| / ___|_   _  __ _ _ __ __| |
 | | | \___ \___ \| |  _| | | |/ _` | '__/ _` |
 | |_| |___) |__) | |_| | |_| | (_| | | | (_| |
  \___/|____/____/ \____|\__,_|\__,_|_|  \__,_|
"""


@app.command()
def init(
    path: str = typer.Argument(".", help="Path to the project directory"),
    email: str = typer.Option("", "--email", "-e", help="Security contact email"),
    skip_scorecard: bool = typer.Option(False, "--skip-scorecard", help="Skip Scorecard setup"),
    skip_codeql: bool = typer.Option(False, "--skip-codeql", help="Skip CodeQL setup"),
    skip_dependabot: bool = typer.Option(False, "--skip-dependabot", help="Skip Dependabot setup"),
    skip_sbom: bool = typer.Option(False, "--skip-sbom", help="Skip SBOM workflow setup"),
    skip_sigstore: bool = typer.Option(False, "--skip-sigstore", help="Skip Sigstore setup"),
    skip_security_md: bool = typer.Option(False, "--skip-security-md", help="Skip SECURITY.md"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be created without writing files"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing files"),
) -> None:
    """Initialize OpenSSF security best practices for a project."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    # Phase 1: Detect project
    console.print("\n[bold cyan]Phase 1: Detecting project...[/]\n")
    info = detect_project(project_path)
    _print_detection_results(info)

    # Phase 2: Determine what to generate
    console.print("\n[bold cyan]Phase 2: Planning security setup...[/]\n")
    plan = _build_plan(info, skip_scorecard, skip_codeql, skip_dependabot, skip_sbom, skip_sigstore, skip_security_md, force)
    _print_plan(plan, info)

    if not plan:
        console.print("[green]Your project already has all OpenSSF security configurations![/]")
        raise typer.Exit(0)

    if dry_run:
        console.print("\n[yellow]Dry run mode — no files were written.[/]")
        raise typer.Exit(0)

    # Phase 3: Generate files
    console.print("\n[bold cyan]Phase 3: Generating files...[/]\n")
    created_files = _execute_plan(plan, info, project_path, email, force)

    # Phase 4: Summary
    _print_summary(created_files, info)


def _build_plan(
    info: ProjectInfo,
    skip_scorecard: bool,
    skip_codeql: bool,
    skip_dependabot: bool,
    skip_sbom: bool,
    skip_sigstore: bool,
    skip_security_md: bool,
    force: bool = False,
) -> list[dict]:
    """Build a list of actions to take."""
    plan = []

    if (force or not info.has_security_md) and not skip_security_md:
        plan.append({
            "id": "security_md",
            "name": "SECURITY.md",
            "description": "Vulnerability disclosure policy (OpenSSF CVD Guide)",
            "path": "SECURITY.md",
        })

    if (force or not info.has_scorecard) and not skip_scorecard:
        plan.append({
            "id": "scorecard",
            "name": "Scorecard Workflow",
            "description": "OpenSSF Scorecard automated security assessment",
            "path": ".github/workflows/scorecard.yml",
        })

    if (force or not info.has_dependabot) and not skip_dependabot:
        plan.append({
            "id": "dependabot",
            "name": "Dependabot Config",
            "description": "Automated dependency updates and security patches",
            "path": ".github/dependabot.yml",
        })

    if (force or not info.has_codeql) and not skip_codeql:
        codeql_content = generate_codeql_workflow(info.languages)
        if codeql_content is not None:
            plan.append({
                "id": "codeql",
                "name": "CodeQL Workflow",
                "description": "Automated code scanning for security vulnerabilities",
                "path": ".github/workflows/codeql.yml",
            })

    if (force or not info.has_sbom_workflow) and not skip_sbom:
        plan.append({
            "id": "sbom",
            "name": "SBOM Workflow",
            "description": "Software Bill of Materials generation for releases",
            "path": ".github/workflows/sbom.yml",
        })

    if (force or not info.has_sigstore) and not skip_sigstore:
        plan.append({
            "id": "sigstore",
            "name": "Sigstore Signing",
            "description": "Cryptographic signing of release artifacts",
            "path": ".github/workflows/sigstore.yml",
        })

    # Always offer branch protection guide
    plan.append({
        "id": "branch_protection",
        "name": "Branch Protection Guide",
        "description": "Guide for setting up branch protection (OpenSSF SCM Best Practices)",
        "path": ".github/BRANCH_PROTECTION.md",
    })

    return plan


def _execute_plan(
    plan: list[dict],
    info: ProjectInfo,
    project_path: Path,
    email: str,
    force: bool,
) -> list[str]:
    """Execute the plan and write files."""
    created_files = []

    for item in plan:
        file_path = project_path / item["path"]

        if file_path.exists() and not force:
            console.print(f"  [yellow]SKIP[/] {item['path']} (already exists, use --force to overwrite)")
            continue

        # Generate content
        content = _generate_content(item["id"], info, email)
        if content is None:
            console.print(f"  [yellow]SKIP[/] {item['path']} (not applicable)")
            continue

        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write file
        file_path.write_text(content)
        created_files.append(item["path"])
        console.print(f"  [green]CREATE[/] {item['path']} — {item['description']}")

    return created_files


def _generate_content(item_id: str, info: ProjectInfo, email: str) -> str | None:
    """Generate file content based on item ID."""
    if item_id == "security_md":
        return generate_security_md(repo_name=info.repo_name, contact_email=email)
    elif item_id == "scorecard":
        return generate_scorecard_workflow()
    elif item_id == "dependabot":
        return generate_dependabot_config(info.package_managers)
    elif item_id == "codeql":
        return generate_codeql_workflow(info.languages)
    elif item_id == "sbom":
        return generate_sbom_workflow()
    elif item_id == "sigstore":
        return generate_sigstore_workflow(info.primary_language)
    elif item_id == "branch_protection":
        return generate_branch_protection_guide()
    return None


def _print_detection_results(info: ProjectInfo) -> None:
    """Print what was detected about the project."""
    table = Table(title="Project Detection Results", show_header=True)
    table.add_column("Property", style="cyan", width=25)
    table.add_column("Value", style="white")

    table.add_row("Project Path", str(info.path))
    table.add_row("Repository Name", info.repo_name or "(unknown)")
    table.add_row("Git Initialized", _bool_icon(info.has_git))
    table.add_row("Languages", ", ".join(info.languages) if info.languages else "(none detected)")
    table.add_row("Primary Language", info.primary_language or "(none)")
    table.add_row("Package Managers", ", ".join(info.package_managers) if info.package_managers else "(none detected)")
    table.add_row("Frameworks", ", ".join(info.frameworks) if info.frameworks else "(none detected)")

    console.print(table)

    # Existing security setup
    sec_table = Table(title="Existing Security Setup", show_header=True)
    sec_table.add_column("Component", style="cyan", width=25)
    sec_table.add_column("Status", style="white", width=15)

    sec_table.add_row("GitHub Actions", _status(info.has_github_actions))
    sec_table.add_row("SECURITY.md", _status(info.has_security_md))
    sec_table.add_row("Scorecard", _status(info.has_scorecard))
    sec_table.add_row("Dependabot", _status(info.has_dependabot))
    sec_table.add_row("CodeQL", _status(info.has_codeql))
    sec_table.add_row("SBOM Workflow", _status(info.has_sbom_workflow))
    sec_table.add_row("Sigstore Signing", _status(info.has_sigstore))

    console.print(sec_table)


def _print_plan(plan: list[dict], info: ProjectInfo) -> None:
    """Print the planned actions."""
    if not plan:
        return

    tree = Tree("[bold]Files to be created[/]")
    for item in plan:
        icon = "[green]+[/]"
        tree.add(f"{icon} [bold]{item['path']}[/] — {item['description']}")

    console.print(tree)


def _print_summary(created_files: list[str], info: ProjectInfo) -> None:
    """Print final summary with next steps."""
    console.print(f"\n[bold green]Done![/] Created {len(created_files)} file(s).\n")

    # Next steps
    next_steps = Panel(
        "\n".join([
            "[bold]Next steps to complete your OpenSSF security setup:[/]\n",
            "1. [cyan]Review generated files[/] and customize for your project",
            "   - Update SECURITY.md with your actual security contact email",
            "   - Adjust workflow triggers if needed\n",
            "2. [cyan]Commit and push[/] the new files to your repository",
            "   git add . && git commit -m 'chore: add OpenSSF security configurations'\n",
            "3. [cyan]Set up branch protection[/] — see .github/BRANCH_PROTECTION.md\n",
            "4. [cyan]Get your OpenSSF Best Practices Badge[/]",
            "   https://www.bestpractices.dev/\n",
            "5. [cyan]Check your Scorecard[/] after the first workflow run",
            "   https://scorecard.dev/viewer/\n",
            "6. [cyan]Join the OpenSSF community[/]",
            "   https://slack.openssf.org/\n",
        ]),
        title="[bold blue]Next Steps[/]",
        border_style="blue",
    )
    console.print(next_steps)


def _bool_icon(value: bool) -> str:
    return "[green]Yes[/]" if value else "[red]No[/]"


def _status(value: bool) -> str:
    return "[green]Configured[/]" if value else "[yellow]Missing[/]"


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to the project directory"),
) -> None:
    """Scan a project and report its OpenSSF security posture (read-only)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Scan[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    info = detect_project(project_path)
    _print_detection_results(info)

    # Calculate score
    checks = [
        info.has_security_md,
        info.has_scorecard,
        info.has_dependabot,
        info.has_codeql,
        info.has_sbom_workflow,
        info.has_sigstore,
    ]
    score = sum(checks)
    total = len(checks)
    pct = int((score / total) * 100)

    if pct == 100:
        color = "green"
    elif pct >= 50:
        color = "yellow"
    else:
        color = "red"

    console.print(
        Panel(
            f"[{color} bold]{score}/{total} ({pct}%)[/] OpenSSF security components configured",
            title="[bold]Security Posture Score[/]",
        )
    )

    if score < total:
        console.print("\n[bold]Run [cyan]ossguard init[/] to add missing components.[/]")


@app.command()
def deps(
    path: str = typer.Argument(".", help="Path to the project directory"),
    include_dev: bool = typer.Option(False, "--include-dev", help="Include dev dependencies"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Analyze dependency health — vulns, outdated packages, and risk scores."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Deps[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.parsers.dependencies import parse_dependencies
    from ossguard.analyzers.dep_health import analyze_dependencies

    console.print("[bold cyan]Parsing dependencies...[/]")
    dep_list = parse_dependencies(project_path)

    if not dep_list:
        console.print("[yellow]No dependencies found.[/] Supported: package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml, and more.")
        raise typer.Exit(0)

    console.print(f"Found [bold]{len(dep_list)}[/] dependencies. Querying OSV & deps.dev APIs...\n")

    with console.status("[bold green]Analyzing dependency health..."):
        report = analyze_dependencies(dep_list, include_dev=include_dev)

    if json_output:
        import json as json_mod
        data = {
            "total_deps": report.total_deps,
            "total_vulns": report.total_vulns,
            "critical": report.critical_vulns,
            "high": report.high_vulns,
            "outdated": report.outdated_count,
            "aggregate_score": report.aggregate_score,
            "dependencies": [
                {
                    "name": r.dep.name,
                    "version": r.dep.version,
                    "ecosystem": r.dep.ecosystem,
                    "health_score": r.health_score,
                    "risk_level": r.risk_level,
                    "vuln_count": r.vuln_count,
                    "license": r.license,
                    "latest_version": r.latest_version,
                }
                for r in report.results
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    # Rich table output
    table = Table(title=f"Dependency Health Report — {report.total_deps} packages")
    table.add_column("Package", style="bold", max_width=35)
    table.add_column("Version", max_width=12)
    table.add_column("Latest", max_width=12)
    table.add_column("Vulns", justify="center", max_width=6)
    table.add_column("Risk", justify="center", max_width=10)
    table.add_column("Score", justify="center", max_width=6)
    table.add_column("License", max_width=15)

    risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "OK": "green"}

    for r in report.results:
        risk_style = risk_colors.get(r.risk_level, "white")
        version_display = r.dep.version or "?"
        latest_display = r.latest_version or "?"
        outdated_marker = " [yellow]*[/]" if r.is_outdated else ""
        score_color = "green" if r.health_score >= 8 else "yellow" if r.health_score >= 5 else "red"

        table.add_row(
            r.dep.name,
            version_display,
            f"{latest_display}{outdated_marker}",
            str(r.vuln_count) if r.vuln_count else "[green]0[/]",
            f"[{risk_style}]{r.risk_level}[/]",
            f"[{score_color}]{r.health_score}[/]",
            r.license[:15] if r.license else "?",
        )

    console.print(table)

    # Summary panel
    agg_color = "green" if report.aggregate_score >= 8 else "yellow" if report.aggregate_score >= 5 else "red"
    summary = (
        f"[{agg_color} bold]Aggregate Score: {report.aggregate_score}/10[/]  •  "
        f"Risk: {report.risk_summary}  •  "
        f"Vulns: {report.total_vulns} "
        f"({report.critical_vulns} critical, {report.high_vulns} high)  •  "
        f"Outdated: {report.outdated_count}"
    )
    console.print(Panel(summary, title="[bold]Summary[/]"))


@app.command()
def drift(
    old: str = typer.Argument(..., help="Path to the older SBOM file (JSON)"),
    new: str = typer.Argument(..., help="Path to the newer SBOM file (JSON)"),
    no_vulns: bool = typer.Option(False, "--no-vulns", help="Skip vulnerability check on changed deps"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Diff two SBOMs and show dependency drift with risk assessment."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Drift[/]", subtitle=f"v{__version__}"))

    for p, label in [(old, "old"), (new, "new")]:
        if not Path(p).exists():
            console.print(f"[red]Error:[/] {label} SBOM file not found: {p}")
            raise typer.Exit(1)

    from ossguard.analyzers.drift import analyze_drift

    with console.status("[bold green]Analyzing SBOM drift..."):
        report = analyze_drift(old, new, check_vulns=not no_vulns)

    if json_output:
        import json as json_mod
        data = {
            "old": report.old_name,
            "new": report.new_name,
            "added": report.added,
            "removed": report.removed,
            "upgraded": report.upgraded,
            "downgraded": report.downgraded,
            "new_vulns": report.new_vulns,
            "risk_delta": report.risk_delta,
            "changes": [
                {
                    "type": e.change_type,
                    "name": e.dep.name,
                    "old_version": e.old_version,
                    "new_version": e.new_version,
                    "risk": e.risk_level,
                    "vuln_count": len(e.vulns),
                }
                for e in report.entries
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    if not report.entries:
        console.print("[green]No dependency changes between the two SBOMs.[/]")
        raise typer.Exit(0)

    table = Table(title=f"SBOM Drift — {report.total_changes} changes")
    table.add_column("Change", max_width=10)
    table.add_column("Package", style="bold", max_width=35)
    table.add_column("Old Version", max_width=15)
    table.add_column("New Version", max_width=15)
    table.add_column("Vulns", justify="center", max_width=6)
    table.add_column("Risk", justify="center", max_width=10)

    change_colors = {"added": "green", "removed": "red", "upgraded": "cyan", "downgraded": "yellow"}
    risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "WARN": "yellow", "NEW": "cyan", "OK": "green"}

    for e in report.entries:
        c_style = change_colors.get(e.change_type, "white")
        r_style = risk_colors.get(e.risk_level, "white")
        table.add_row(
            f"[{c_style}]{e.change_type.upper()}[/]",
            e.dep.name,
            e.old_version or "—",
            e.new_version or "—",
            str(len(e.vulns)) if e.vulns else "[green]0[/]",
            f"[{r_style}]{e.risk_level}[/]",
        )

    console.print(table)

    # Summary
    delta_color = "red" if "INCREASE" in report.risk_delta else "green" if "DECREASED" in report.risk_delta else "yellow"
    summary = (
        f"[{delta_color} bold]Risk Delta: {report.risk_delta}[/]  •  "
        f"+{report.added} added, -{report.removed} removed, "
        f"{report.upgraded} upgraded, {report.downgraded} downgraded  •  "
        f"New vulns: {report.new_vulns}"
    )
    console.print(Panel(summary, title="[bold]Drift Summary[/]"))


@app.command()
def watch(
    sbom: str = typer.Argument(..., help="Path to the SBOM file (SPDX or CycloneDX JSON)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    output_file: str = typer.Option("", "--output", "-o", help="Save report to file"),
    webhook: str = typer.Option("", "--webhook", help="Send alerts to a webhook URL"),
) -> None:
    """Monitor an SBOM for current vulnerabilities (post-deployment watch)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Watch[/]", subtitle=f"v{__version__}"))

    if not Path(sbom).exists():
        console.print(f"[red]Error:[/] SBOM file not found: {sbom}")
        raise typer.Exit(1)

    from ossguard.analyzers.watch import watch_sbom, send_webhook

    with console.status("[bold green]Scanning SBOM for vulnerabilities..."):
        report = watch_sbom(sbom)

    if json_output or output_file:
        json_str = report.to_json()
        if output_file:
            Path(output_file).write_text(json_str)
            console.print(f"[green]Report saved to {output_file}[/]")
        if json_output:
            console.print_json(json_str)
            if webhook:
                ok = send_webhook(report, webhook)
                console.print(f"Webhook: {'[green]sent[/]' if ok else '[red]failed[/]'}")
            raise typer.Exit(0)

    if webhook:
        ok = send_webhook(report, webhook)
        console.print(f"Webhook: {'[green]sent[/]' if ok else '[red]failed[/]'}")

    if report.is_clean:
        console.print(Panel(
            f"[bold green]No vulnerabilities found![/]\n"
            f"Scanned {report.total_components} components in {report.sbom_name or sbom}",
            title="[bold]Watch Report[/]",
        ))
        raise typer.Exit(0)

    table = Table(title=f"Vulnerability Alerts — {report.sbom_name or sbom}")
    table.add_column("Package", style="bold", max_width=30)
    table.add_column("Version", max_width=12)
    table.add_column("Severity", justify="center", max_width=10)
    table.add_column("Vuln ID", max_width=20)
    table.add_column("Fix Version", max_width=12)
    table.add_column("Summary", max_width=40)

    severity_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "UNKNOWN": "dim"}

    for alert in report.alerts:
        for vuln in alert.vulns:
            s_color = severity_colors.get(vuln.severity, "white")
            table.add_row(
                alert.package_name,
                alert.package_version,
                f"[{s_color}]{vuln.severity}[/]",
                vuln.id,
                vuln.fixed_version or "—",
                vuln.summary[:40],
            )

    console.print(table)

    summary = (
        f"[bold]{report.total_components}[/] components scanned  •  "
        f"[bold red]{report.affected_components}[/] affected  •  "
        f"[bold]{report.total_vulns}[/] vulnerabilities found"
    )
    console.print(Panel(summary, title="[bold]Watch Summary[/]"))


@app.command()
def tpn(
    path: str = typer.Argument(".", help="Path to the project directory"),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text, html, json"),
    output_file: str = typer.Option("", "--output", "-o", help="Save to file (default: stdout)"),
) -> None:
    """Generate third-party notices from project dependencies."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — TPN[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.parsers.dependencies import parse_dependencies
    from ossguard.analyzers.tpn import generate_tpn

    console.print("[bold cyan]Parsing dependencies...[/]")
    dep_list = parse_dependencies(project_path)

    if not dep_list:
        console.print("[yellow]No dependencies found.[/]")
        raise typer.Exit(0)

    project_name = project_path.name
    console.print(f"Found [bold]{len(dep_list)}[/] dependencies. Fetching license info from deps.dev...\n")

    with console.status("[bold green]Generating third-party notices..."):
        report = generate_tpn(dep_list, project_name=project_name)

    # Generate output
    if output_format == "html":
        content = report.to_html()
        default_file = "THIRD_PARTY_NOTICES.html"
    elif output_format == "json":
        content = report.to_json()
        default_file = "THIRD_PARTY_NOTICES.json"
    else:
        content = report.to_text()
        default_file = "THIRD_PARTY_NOTICES.txt"

    if output_file:
        Path(output_file).write_text(content)
        console.print(f"[green]Third-party notices saved to {output_file}[/]")
    else:
        console.print(content)

    # Summary
    warnings = ""
    if report.unknown_licenses:
        warnings += f"  •  [yellow]{len(report.unknown_licenses)} unknown licenses[/]"
    if report.conflicts:
        warnings += f"  •  [red]{len(report.conflicts)} potential conflicts[/]"

    console.print(Panel(
        f"[bold]{len(report.entries)}[/] components documented{warnings}",
        title="[bold]TPN Summary[/]",
    ))

    if not output_file:
        console.print(f"\n[dim]Tip: Save with[/] [cyan]ossguard tpn --output {default_file}[/]")


@app.command()
def reach(
    path: str = typer.Argument(".", help="Path to the project directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Filter vulnerabilities by runtime reachability (static import analysis)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Reach[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.parsers.dependencies import parse_dependencies
    from ossguard.analyzers.reach import analyze_reachability

    console.print("[bold cyan]Parsing dependencies and scanning imports...[/]")
    dep_list = parse_dependencies(project_path)

    if not dep_list:
        console.print("[yellow]No dependencies found.[/]")
        raise typer.Exit(0)

    with console.status("[bold green]Analyzing reachability..."):
        report = analyze_reachability(dep_list, project_path)

    if json_output:
        import json as json_mod
        data = {
            "total_deps": report.total_deps,
            "reachable_deps": report.reachable_deps,
            "total_vulns": report.total_vulns,
            "reachable_vulns": report.reachable_vulns,
            "filtered_vulns": report.filtered_vulns,
            "noise_reduction_pct": report.noise_reduction_pct,
            "results": [
                {
                    "name": r.dep.name,
                    "reachable": r.is_reachable,
                    "import_locations": r.import_locations,
                    "vuln_count": r.vuln_count,
                }
                for r in report.results
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    # Reachable vulns table
    reachable_with_vulns = [r for r in report.results if r.is_reachable and r.vuln_count > 0]
    filtered_with_vulns = [r for r in report.results if not r.is_reachable and r.vuln_count > 0]

    if reachable_with_vulns:
        table = Table(title="Reachable Vulnerabilities (ACTION REQUIRED)")
        table.add_column("Package", style="bold red", max_width=30)
        table.add_column("Version", max_width=12)
        table.add_column("Vulns", justify="center", max_width=6)
        table.add_column("Imported In", max_width=50)

        for r in reachable_with_vulns:
            locations = ", ".join(r.import_locations[:3])
            if len(r.import_locations) > 3:
                locations += f" (+{len(r.import_locations) - 3} more)"
            table.add_row(r.dep.name, r.dep.version, str(r.vuln_count), locations)

        console.print(table)

    if filtered_with_vulns:
        table = Table(title="Filtered Vulnerabilities (not imported — lower priority)")
        table.add_column("Package", style="dim", max_width=30)
        table.add_column("Version", max_width=12)
        table.add_column("Vulns", justify="center", max_width=6)

        for r in filtered_with_vulns:
            table.add_row(r.dep.name, r.dep.version, str(r.vuln_count))

        console.print(table)

    # Summary
    if report.total_vulns > 0:
        noise_color = "green" if report.noise_reduction_pct >= 50 else "yellow"
        summary = (
            f"[bold]{report.reachable_vulns}[/] reachable vulns (action needed)  •  "
            f"[dim]{report.filtered_vulns}[/] filtered (not imported)  •  "
            f"[{noise_color} bold]{report.noise_reduction_pct}% noise reduction[/]"
        )
    else:
        summary = f"[green bold]No vulnerabilities found[/] across {report.total_deps} dependencies"

    console.print(Panel(summary, title="[bold]Reachability Summary[/]"))


@app.command()
def audit(
    path: str = typer.Argument(".", help="Path to the project directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Run a comprehensive security audit (scan + deps + reach combined)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Audit[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.audit import run_audit

    with console.status("[bold green]Running comprehensive security audit..."):
        report = run_audit(project_path)

    if json_output:
        console.print_json(report.to_json())
        raise typer.Exit(0)

    # Grade display
    grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    g_color = grade_colors.get(report.overall_grade, "white")
    console.print(Panel(
        f"[{g_color}]  {report.overall_grade}  [/]",
        title="[bold]Overall Security Grade[/]",
        width=30,
    ))

    # Config score
    cfg_color = "green" if report.config_pct == 100 else "yellow" if report.config_pct >= 50 else "red"
    console.print(f"\n[bold]Configuration:[/] [{cfg_color}]{report.config_score}/{report.config_total} ({report.config_pct}%)[/]")

    # Dep health
    if report.dep_health:
        dh = report.dep_health
        dh_color = "green" if dh.aggregate_score >= 8 else "yellow" if dh.aggregate_score >= 5 else "red"
        console.print(f"[bold]Dependency Health:[/] [{dh_color}]{dh.aggregate_score}/10[/] ({dh.total_deps} deps, {dh.total_vulns} vulns)")

    # Reachability
    if report.reachability and report.reachability.total_vulns > 0:
        r = report.reachability
        console.print(f"[bold]Reachability:[/] {r.reachable_vulns} reachable vulns, {r.filtered_vulns} filtered ({r.noise_reduction_pct}% noise reduction)")

    # Findings
    if report.findings:
        console.print("\n[bold yellow]Findings:[/]")
        for f in report.findings:
            console.print(f"  [yellow]![/] {f}")

    # Recommendations
    if report.recommendations:
        console.print("\n[bold blue]Recommendations:[/]")
        for r in report.recommendations:
            console.print(f"  [blue]>[/] {r}")


@app.command()
def fix(
    path: str = typer.Argument(".", help="Path to the project directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be fixed without applying"),
    no_deps: bool = typer.Option(False, "--no-deps", help="Skip dependency version bumps"),
    no_configs: bool = typer.Option(False, "--no-configs", help="Skip adding missing config files"),
) -> None:
    """Auto-fix common security issues (bump vulnerable deps, add missing configs)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Fix[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.fix import auto_fix

    mode = "[yellow]DRY RUN[/]" if dry_run else "[green]APPLYING[/]"
    console.print(f"Mode: {mode}\n")

    with console.status("[bold green]Analyzing and fixing issues..."):
        report = auto_fix(
            project_path,
            dry_run=dry_run,
            fix_deps=not no_deps,
            fix_configs=not no_configs,
        )

    if not report.actions:
        console.print("[green]No issues to fix! Your project looks good.[/]")
        raise typer.Exit(0)

    table = Table(title="Fix Actions")
    table.add_column("Action", style="bold", max_width=60)
    table.add_column("Type", max_width=12)
    table.add_column("Status", justify="center", max_width=10)

    for action in report.actions:
        if action.applied:
            status = "[green]APPLIED[/]"
        elif dry_run:
            status = "[yellow]PENDING[/]"
        else:
            status = "[red]FAILED[/]"

        table.add_row(action.description, action.action_type, status)

    console.print(table)

    summary = f"[bold]{report.total}[/] actions"
    if dry_run:
        summary += f" — [yellow]{report.skipped_count} pending[/] (use without --dry-run to apply)"
    else:
        summary += f" — [green]{report.applied_count} applied[/]"
        if report.failed_count:
            summary += f", [red]{report.failed_count} failed[/]"
    console.print(Panel(summary, title="[bold]Fix Summary[/]"))


@app.command()
def badge(
    path: str = typer.Argument(".", help="Path to the project directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Assess readiness for the OpenSSF Best Practices Badge."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Badge[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.badge import assess_badge_readiness

    with console.status("[bold green]Assessing badge readiness..."):
        report = assess_badge_readiness(project_path)

    if json_output:
        import json as json_mod
        data = {
            "readiness_pct": report.readiness_pct,
            "met": report.met_count,
            "unmet": report.unmet_count,
            "unknown": report.unknown_count,
            "criteria": [
                {
                    "id": c.id,
                    "category": c.category,
                    "question": c.question,
                    "status": c.status,
                    "evidence": c.evidence,
                    "suggestion": c.suggestion,
                }
                for c in report.criteria
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    # Readiness gauge
    r_color = "green" if report.readiness_pct >= 80 else "yellow" if report.readiness_pct >= 50 else "red"
    console.print(Panel(
        f"[{r_color} bold]{report.readiness_pct}%[/] ready for OpenSSF Best Practices Badge",
        title="[bold]Badge Readiness[/]",
    ))

    # Criteria table grouped by category
    current_category = ""
    table = Table(title="Criteria Assessment")
    table.add_column("Criterion", max_width=55)
    table.add_column("Status", justify="center", max_width=10)
    table.add_column("Action Needed", max_width=40)

    status_icons = {"met": "[green]PASS[/]", "unmet": "[red]FAIL[/]", "unknown": "[yellow]?[/]"}

    for c in report.criteria:
        if c.category != current_category:
            table.add_row(f"\n[bold cyan]{c.category}[/]", "", "")
            current_category = c.category
        table.add_row(
            c.question,
            status_icons.get(c.status, c.status),
            c.suggestion if c.status != "met" else "",
        )

    console.print(table)

    console.print(f"\n[dim]Apply at:[/] [cyan]{report.badge_url}[/]")


@app.command()
def ci(
    path: str = typer.Argument(".", help="Path to the project directory"),
    output_file: str = typer.Option("", "--output", "-o", help="Save to file (default: .github/workflows/ossguard-ci.yml)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without writing"),
) -> None:
    """Generate a unified CI security pipeline (single workflow with all checks)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — CI[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.ci import generate_ci_pipeline

    content = generate_ci_pipeline(project_path)

    if dry_run:
        console.print(content)
        console.print("\n[yellow]Dry run — no files written.[/]")
        raise typer.Exit(0)

    target = output_file or str(project_path / ".github" / "workflows" / "ossguard-ci.yml")
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(content)

    console.print(f"[green]Created[/] {target}")
    console.print("\n[bold]Jobs included:[/]")
    for job in ["Build & Test", "Lint & Format", "CodeQL Analysis", "Dependency Audit", "Scorecard", "SBOM Generation", "Security Gate"]:
        console.print(f"  [green]+[/] {job}")


@app.command()
def report(
    path: str = typer.Argument(".", help="Path to the project directory"),
    output_format: str = typer.Option("html", "--format", "-f", help="Output format: html, json"),
    output_file: str = typer.Option("", "--output", "-o", help="Save to file"),
) -> None:
    """Export a comprehensive security compliance report (HTML or JSON)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Report[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.report import generate_report

    with console.status("[bold green]Generating compliance report..."):
        content = generate_report(project_path, output_format=output_format)

    ext = "html" if output_format == "html" else "json"
    default_file = f"ossguard-report.{ext}"
    target = output_file or default_file

    Path(target).write_text(content)
    console.print(f"[green]Report saved to {target}[/]")

    if output_format == "html":
        console.print(f"[dim]Open in browser:[/] [cyan]open {target}[/]")


@app.command()
def policy(
    path: str = typer.Argument(".", help="Path to the project directory"),
    policy_file: str = typer.Option("", "--policy", "-p", help="Path to policy JSON file"),
    generate: bool = typer.Option(False, "--generate", help="Generate a policy template file"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Check project against org-wide security policies."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Policy[/]", subtitle=f"v{__version__}"))

    from ossguard.analyzers.policy import check_policy, generate_policy_template

    if generate:
        template = generate_policy_template()
        out_path = Path(path).resolve() / ".ossguard-policy.json"
        out_path.write_text(template)
        console.print(f"[green]Policy template saved to {out_path}[/]")
        console.print("[dim]Customize the rules and severity levels, then run:[/]")
        console.print(f"[cyan]ossguard policy --policy {out_path}[/]")
        raise typer.Exit(0)

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    pf = policy_file if policy_file else None
    with console.status("[bold green]Checking policy compliance..."):
        report_data = check_policy(project_path, policy_file=pf)

    if json_output:
        console.print_json(report_data.to_json())
        raise typer.Exit(0)

    # Compliance status
    if report_data.compliant:
        console.print(Panel("[bold green]COMPLIANT[/] — all required rules pass", title="[bold]Policy Status[/]"))
    else:
        console.print(Panel("[bold red]NON-COMPLIANT[/] — some required rules failed", title="[bold]Policy Status[/]"))

    table = Table(title=f"Policy Rules — {report_data.policy_file}")
    table.add_column("Rule", style="bold", max_width=40)
    table.add_column("Severity", max_width=10)
    table.add_column("Status", justify="center", max_width=8)
    table.add_column("Details", max_width=40)

    sev_colors = {"error": "red", "warning": "yellow", "info": "blue"}

    for rule in report_data.rules:
        s_color = sev_colors.get(rule.severity, "white")
        status = "[green]PASS[/]" if rule.passed else f"[{s_color}]FAIL[/]"
        table.add_row(
            rule.description,
            f"[{s_color}]{rule.severity.upper()}[/]",
            status,
            rule.details,
        )

    console.print(table)

    summary = f"[bold]{report_data.passed}[/] passed, [bold]{report_data.failed}[/] failed"
    if report_data.warnings:
        summary += f" ({report_data.warnings} warnings)"
    console.print(Panel(summary, title="[bold]Policy Summary[/]"))

    if not report_data.compliant:
        raise typer.Exit(1)


@app.command(name="license")
def license_check(
    path: str = typer.Argument(".", help="Path to the project directory"),
    project_license: str = typer.Option("", "--project-license", help="Your project's SPDX license ID (e.g. Apache-2.0)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Check dependency license compliance and detect conflicts."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — License[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.parsers.dependencies import parse_dependencies
    from ossguard.analyzers.license_check import check_licenses

    dep_list = parse_dependencies(project_path)
    if not dep_list:
        console.print("[yellow]No dependencies found.[/]")
        raise typer.Exit(0)

    # Try to auto-detect project license if not provided
    if not project_license:
        for lic_file in ["LICENSE", "LICENSE.md", "LICENSE.txt"]:
            lf = project_path / lic_file
            if lf.exists():
                content = lf.read_text()[:500].lower()
                if "apache" in content and "2.0" in content:
                    project_license = "Apache-2.0"
                elif "mit license" in content or "permission is hereby granted" in content:
                    project_license = "MIT"
                elif "bsd" in content:
                    project_license = "BSD-3-Clause"
                break

    console.print(f"Project license: [bold]{project_license or 'unknown'}[/]")
    console.print(f"Checking [bold]{len(dep_list)}[/] dependencies...\n")

    with console.status("[bold green]Analyzing licenses..."):
        report_data = check_licenses(dep_list, project_license=project_license)

    if json_output:
        import json as json_mod
        data = {
            "project_license": report_data.project_license,
            "compliant": report_data.compliant,
            "summary": report_data.summary,
            "unknown_count": len(report_data.unknown_licenses),
            "conflict_count": len(report_data.conflicts),
            "licenses": [
                {"name": l.name, "version": l.version, "license": l.license, "category": l.category}
                for l in report_data.licenses
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    # License table
    table = Table(title="Dependency Licenses")
    table.add_column("Package", style="bold", max_width=30)
    table.add_column("Version", max_width=12)
    table.add_column("License", max_width=20)
    table.add_column("Category", max_width=15)

    cat_colors = {"permissive": "green", "weak_copyleft": "yellow", "copyleft": "red", "unknown": "dim"}

    for lic in report_data.licenses:
        c_color = cat_colors.get(lic.category, "white")
        table.add_row(
            lic.name,
            lic.version,
            lic.license or "[dim]unknown[/]",
            f"[{c_color}]{lic.category}[/]",
        )

    console.print(table)

    # Summary
    console.print(f"\n[bold]License Summary:[/]")
    for cat, count in sorted(report_data.summary.items()):
        if count > 0:
            c_color = cat_colors.get(cat, "white")
            console.print(f"  [{c_color}]{cat}[/]: {count}")

    # Conflicts
    if report_data.conflicts:
        console.print(f"\n[bold red]License Conflicts ({len(report_data.conflicts)}):[/]")
        for c in report_data.conflicts:
            console.print(f"  [red]![/] {c.reason}")

    if report_data.unknown_licenses:
        console.print(f"\n[bold yellow]Unknown Licenses ({len(report_data.unknown_licenses)}):[/]")
        for name in report_data.unknown_licenses[:10]:
            console.print(f"  [yellow]?[/] {name}")

    # Compliance status
    if report_data.compliant:
        console.print(Panel("[bold green]COMPLIANT[/] — no license conflicts detected", title="[bold]License Status[/]"))
    else:
        console.print(Panel("[bold red]NON-COMPLIANT[/] — license issues found", title="[bold]License Status[/]"))


@app.command()
def baseline(
    path: str = typer.Argument(".", help="Path to the project directory"),
    level: int = typer.Option(3, "--level", "-l", help="Target OSPS Baseline level (1-3)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Check project against the OSPS Security Baseline (Levels 1-3)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Baseline[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.baseline import check_baseline

    with console.status("[bold green]Checking OSPS Baseline compliance..."):
        report = check_baseline(project_path, target_level=level)

    if json_output:
        import json as json_mod
        data = {
            "achieved_level": report.achieved_level,
            "level1": {"pass": report.level1_pass, "total": report.level1_total, "pct": report.level1_pct},
            "level2": {"pass": report.level2_pass, "total": report.level2_total, "pct": report.level2_pct},
            "level3": {"pass": report.level3_pass, "total": report.level3_total, "pct": report.level3_pct},
            "controls": [
                {"id": c.id, "family": c.family, "title": c.title, "level": c.level,
                 "status": c.status, "evidence": c.evidence, "recommendation": c.recommendation}
                for c in report.controls
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    # Achieved level badge
    lvl_colors = {0: "red", 1: "yellow", 2: "green", 3: "bold green"}
    lvl_color = lvl_colors.get(report.achieved_level, "white")
    console.print(Panel(
        f"[{lvl_color}]Level {report.achieved_level}[/]",
        title="[bold]OSPS Baseline — Achieved Level[/]", width=35,
    ))

    # Level progress bars
    for lvl, lbl, passed, total, pct in [
        (1, "Level 1", report.level1_pass, report.level1_total, report.level1_pct),
        (2, "Level 2", report.level2_pass, report.level2_total, report.level2_pct),
        (3, "Level 3", report.level3_pass, report.level3_total, report.level3_pct),
    ]:
        if total > 0 and lvl <= level:
            bar_color = "green" if pct == 100 else "yellow" if pct >= 50 else "red"
            console.print(f"  {lbl}: [{bar_color}]{passed}/{total} ({pct}%)[/]")

    # Controls table
    table = Table(title="Baseline Controls")
    table.add_column("ID", style="dim", max_width=14)
    table.add_column("Level", justify="center", max_width=6)
    table.add_column("Control", max_width=50)
    table.add_column("Status", justify="center", max_width=8)

    current_family = ""
    for c in report.controls:
        if c.family != current_family:
            table.add_row(f"\n[bold cyan]{c.family}[/]", "", "", "")
            current_family = c.family
        status_icon = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "unknown": "[yellow]?[/]"}
        table.add_row(c.id, str(c.level), c.title, status_icon.get(c.status, c.status))

    console.print(table)


@app.command()
def insights(
    path: str = typer.Argument(".", help="Path to the project directory"),
    validate_only: bool = typer.Option(False, "--validate", help="Only validate existing file"),
    output_file: str = typer.Option("", "--output", "-o", help="Output file path"),
) -> None:
    """Generate or validate a SECURITY-INSIGHTS.yml file."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Insights[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.insights import generate_insights, validate_insights

    if validate_only:
        report = validate_insights(project_path)
        if report.valid:
            console.print(Panel("[bold green]VALID[/]", title="[bold]Security Insights[/]"))
        else:
            console.print(Panel("[bold red]INVALID[/]", title="[bold]Security Insights[/]"))
            for err in report.errors:
                console.print(f"  [red]![/] {err}")
        for warn in report.warnings:
            console.print(f"  [yellow]![/] {warn}")
        if not report.valid:
            raise typer.Exit(1)
        raise typer.Exit(0)

    content = generate_insights(project_path)
    target = output_file or str(project_path / "SECURITY-INSIGHTS.yml")
    Path(target).write_text(content)
    console.print(f"[green]Generated[/] {target}")
    console.print("[dim]Review and customize the file, then commit it to your repository.[/]")


@app.command()
def pin(
    path: str = typer.Argument(".", help="Path to the project directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be pinned"),
) -> None:
    """Pin GitHub Actions to commit SHAs for supply-chain safety."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Pin[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    wf_dir = project_path / ".github" / "workflows"
    if not wf_dir.is_dir():
        console.print("[yellow]No .github/workflows directory found.[/]")
        raise typer.Exit(0)

    from ossguard.analyzers.pin import pin_actions, scan_actions

    if dry_run:
        report = scan_actions(project_path)
    else:
        with console.status("[bold green]Resolving action SHAs..."):
            report = pin_actions(project_path, dry_run=False)

    if not report.actions:
        console.print("[green]No GitHub Action references found.[/]")
        raise typer.Exit(0)

    table = Table(title="GitHub Actions References")
    table.add_column("File", style="dim", max_width=25)
    table.add_column("Action", max_width=35)
    table.add_column("Ref", max_width=12)
    table.add_column("Status", justify="center", max_width=12)

    for action in report.actions:
        if action.already_pinned:
            status = "[green]PINNED[/]"
        elif action.resolved_sha:
            status = "[cyan]RESOLVED[/]" if dry_run else "[green]UPDATED[/]"
        else:
            status = "[yellow]UNRESOLVED[/]"

        ref_display = action.ref[:12] + "..." if len(action.ref) > 15 else action.ref
        table.add_row(action.file, f"{action.owner}/{action.repo}", ref_display, status)

    console.print(table)

    summary = (
        f"[bold]{report.total_refs}[/] refs — "
        f"[green]{report.already_pinned_count}[/] already pinned"
    )
    if report.pinned_count:
        summary += f", [cyan]{report.pinned_count}[/] {'would be' if dry_run else ''} pinned"
    if report.failed_count:
        summary += f", [red]{report.failed_count}[/] failed"
    console.print(Panel(summary, title="[bold]Pin Summary[/]"))


@app.command()
def secrets(
    path: str = typer.Argument(".", help="Path to the project directory"),
    include_low: bool = typer.Option(False, "--include-low", help="Include low-severity findings"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Scan project for leaked secrets and credentials."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Secrets[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.secrets import scan_secrets

    with console.status("[bold green]Scanning for secrets..."):
        report = scan_secrets(project_path, include_low=include_low)

    if json_output:
        import json as json_mod
        data = {
            "clean": report.clean,
            "files_scanned": report.files_scanned,
            "total": report.total,
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "findings": [
                {"file": f.file, "line": f.line_number, "rule": f.rule_id,
                 "severity": f.severity, "description": f.description}
                for f in report.findings
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    console.print(f"Scanned [bold]{report.files_scanned}[/] files\n")

    if report.clean:
        console.print(Panel("[bold green]CLEAN[/] — no secrets detected", title="[bold]Secrets Scan[/]"))
        raise typer.Exit(0)

    table = Table(title=f"Secret Findings ({report.total})")
    table.add_column("File", style="dim", max_width=30)
    table.add_column("Line", justify="right", max_width=6)
    table.add_column("Severity", max_width=10)
    table.add_column("Description", max_width=35)

    sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}

    for f in report.findings:
        s_color = sev_colors.get(f.severity, "white")
        table.add_row(f.file, str(f.line_number), f"[{s_color}]{f.severity.upper()}[/]", f.description)

    console.print(table)

    summary = []
    if report.critical_count:
        summary.append(f"[bold red]{report.critical_count} critical[/]")
    if report.high_count:
        summary.append(f"[red]{report.high_count} high[/]")
    if report.medium_count:
        summary.append(f"[yellow]{report.medium_count} medium[/]")
    if report.low_count:
        summary.append(f"[dim]{report.low_count} low[/]")
    console.print(Panel(" • ".join(summary), title="[bold]Secrets Summary[/]"))

    if report.critical_count or report.high_count:
        console.print("\n[bold red]ACTION REQUIRED:[/] Rotate any exposed credentials immediately!")


@app.command()
def slsa(
    path: str = typer.Argument(".", help="Path to the project directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Assess SLSA (Supply-chain Levels for Software Artifacts) build level."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — SLSA[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.slsa import check_slsa

    with console.status("[bold green]Assessing SLSA build level..."):
        report = check_slsa(project_path)

    if json_output:
        import json as json_mod
        data = {
            "achieved_level": report.achieved_level,
            "level_label": report.level_label,
            "met": report.met_count,
            "total": report.total_count,
            "requirements": [
                {"id": r.id, "level": r.level, "description": r.description,
                 "status": r.status, "evidence": r.evidence}
                for r in report.requirements
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    lvl_color = "green" if report.achieved_level >= 2 else "yellow" if report.achieved_level >= 1 else "red"
    console.print(Panel(
        f"[{lvl_color} bold]{report.level_label}[/]",
        title="[bold]SLSA Assessment[/]",
    ))

    table = Table(title="SLSA Requirements")
    table.add_column("Level", justify="center", max_width=6)
    table.add_column("Requirement", max_width=55)
    table.add_column("Status", justify="center", max_width=8)

    for r in report.requirements:
        status_icon = {"met": "[green]MET[/]", "unmet": "[red]UNMET[/]", "unknown": "[yellow]?[/]"}
        table.add_row(str(r.level), r.description, status_icon.get(r.status, r.status))

    console.print(table)
    console.print(f"\n[dim]Learn more:[/] [cyan]https://slsa.dev/spec/v1.0/levels[/]")


@app.command(name="sbom-gen")
def sbom_gen(
    path: str = typer.Argument(".", help="Path to the project directory"),
    sbom_format: str = typer.Option("spdx", "--format", "-f", help="SBOM format: spdx, cyclonedx"),
    output_file: str = typer.Option("", "--output", "-o", help="Output file path"),
) -> None:
    """Generate a local SBOM (SPDX or CycloneDX) from dependency manifests."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — SBOM Gen[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.sbom_gen import generate_sbom

    content = generate_sbom(project_path, sbom_format=sbom_format)

    ext = "spdx.json" if sbom_format == "spdx" else "cdx.json"
    default_name = f"sbom.{ext}"
    target = output_file or default_name

    Path(target).write_text(content)
    console.print(f"[green]SBOM generated:[/] {target}")
    console.print(f"Format: [bold]{sbom_format.upper()}[/]")

    import json as json_mod
    data = json_mod.loads(content)
    if sbom_format == "spdx":
        pkg_count = len(data.get("packages", [])) - 1  # Minus root
    else:
        pkg_count = len(data.get("components", []))
    console.print(f"Components: [bold]{pkg_count}[/]")


@app.command(name="supply-chain")
def supply_chain(
    path: str = typer.Argument(".", help="Path to the project directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Check dependencies for supply-chain risks (malicious packages, typosquatting)."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Supply Chain[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.supply_chain import check_supply_chain

    with console.status("[bold green]Analyzing supply chain risks..."):
        report = check_supply_chain(project_path)

    if json_output:
        import json as json_mod
        data = {
            "clean": report.clean,
            "total_deps": report.total_deps,
            "malicious": report.malicious_count,
            "typosquat": report.typosquat_count,
            "risk": report.risk_count,
            "findings": [
                {"package": f.package, "version": f.version, "type": f.finding_type,
                 "severity": f.severity, "description": f.description}
                for f in report.findings
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    if report.clean:
        console.print(Panel(
            f"[bold green]CLEAN[/] — no supply chain risks detected across {report.total_deps} dependencies",
            title="[bold]Supply Chain[/]",
        ))
        raise typer.Exit(0)

    table = Table(title="Supply Chain Findings")
    table.add_column("Package", style="bold", max_width=25)
    table.add_column("Type", max_width=12)
    table.add_column("Severity", max_width=10)
    table.add_column("Description", max_width=40)

    sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
    for f in report.findings:
        s_color = sev_colors.get(f.severity, "white")
        table.add_row(f.package, f.finding_type, f"[{s_color}]{f.severity.upper()}[/]", f.description)

    console.print(table)

    summary_parts = []
    if report.malicious_count:
        summary_parts.append(f"[bold red]{report.malicious_count} malicious[/]")
    if report.typosquat_count:
        summary_parts.append(f"[red]{report.typosquat_count} typosquat[/]")
    if report.risk_count:
        summary_parts.append(f"[yellow]{report.risk_count} suspicious[/]")
    console.print(Panel(" • ".join(summary_parts), title="[bold]Supply Chain Summary[/]"))


@app.command()
def container(
    path: str = typer.Argument(".", help="Path to the project directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Lint Dockerfiles for security issues."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Container[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.container import scan_containers

    report = scan_containers(project_path)

    if report.files_scanned == 0:
        console.print("[yellow]No Dockerfiles found.[/]")
        raise typer.Exit(0)

    if json_output:
        import json as json_mod
        data = {
            "clean": report.clean,
            "files_scanned": report.files_scanned,
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "findings": [
                {"file": f.file, "line": f.line_number, "rule": f.rule_id,
                 "severity": f.severity, "description": f.description,
                 "recommendation": f.recommendation}
                for f in report.findings
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    console.print(f"Scanned [bold]{report.files_scanned}[/] Dockerfile(s)\n")

    if report.clean:
        console.print(Panel("[bold green]CLEAN[/] — no security issues found", title="[bold]Container Scan[/]"))
        raise typer.Exit(0)

    table = Table(title="Dockerfile Findings")
    table.add_column("File", style="dim", max_width=20)
    table.add_column("Rule", max_width=10)
    table.add_column("Severity", max_width=10)
    table.add_column("Issue", max_width=45)

    sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
    for f in report.findings:
        s_color = sev_colors.get(f.severity, "white")
        line_info = f"{f.file}:{f.line_number}" if f.line_number else f.file
        table.add_row(line_info, f.rule_id, f"[{s_color}]{f.severity.upper()}[/]", f.description)

    console.print(table)


@app.command()
def compare(
    path_a: str = typer.Argument(..., help="Path to the first project"),
    path_b: str = typer.Argument(..., help="Path to the second project"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Compare security posture of two projects side by side."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Compare[/]", subtitle=f"v{__version__}"))

    a = Path(path_a).resolve()
    b = Path(path_b).resolve()
    for p in [a, b]:
        if not p.is_dir():
            console.print(f"[red]Error:[/] '{p}' is not a directory.")
            raise typer.Exit(1)

    from ossguard.analyzers.compare import compare_projects

    with console.status("[bold green]Auditing both projects..."):
        report = compare_projects(a, b)

    if json_output:
        import json as json_mod
        data = {
            "project_a": report.project_a_name,
            "project_b": report.project_b_name,
            "winner": report.winner,
            "metrics": [
                {"name": m.name, "a": m.project_a_value, "b": m.project_b_value, "winner": m.winner}
                for m in report.metrics
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    table = Table(title="Security Comparison")
    table.add_column("Metric", style="bold", max_width=25)
    table.add_column(report.project_a_name, justify="center", max_width=20)
    table.add_column(report.project_b_name, justify="center", max_width=20)
    table.add_column("", max_width=3)

    for m in report.metrics:
        indicator = ""
        if m.winner == "a":
            indicator = "[green]<[/]"
        elif m.winner == "b":
            indicator = "[green]>[/]"
        elif m.winner == "tie":
            indicator = "[yellow]=[/]"
        table.add_row(m.name, m.project_a_value, m.project_b_value, indicator)

    console.print(table)

    winner_name = report.project_a_name if report.winner == "a" else report.project_b_name if report.winner == "b" else "Tie"
    w_color = "green" if report.winner != "tie" else "yellow"
    console.print(Panel(f"[{w_color} bold]{winner_name}[/]", title="[bold]Better Security Posture[/]"))


@app.command()
def update(
    path: str = typer.Argument(".", help="Path to the project directory"),
    security_only: bool = typer.Option(False, "--security-only", help="Only show security-relevant updates"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show available dependency updates prioritized by security impact."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Update[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.update import check_updates

    with console.status("[bold green]Checking for updates..."):
        report = check_updates(project_path, security_only=security_only)

    if json_output:
        import json as json_mod
        data = {
            "total_updates": report.total_updates,
            "security_updates": report.security_updates,
            "up_to_date": report.up_to_date,
            "candidates": [
                {"name": c.name, "current": c.current_version, "latest": c.latest_version,
                 "priority": c.priority, "vulns": c.vuln_count, "reason": c.reason}
                for c in report.candidates
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    if not report.candidates:
        console.print(Panel("[bold green]All dependencies are up to date![/]", title="[bold]Updates[/]"))
        raise typer.Exit(0)

    table = Table(title="Available Updates")
    table.add_column("Package", style="bold", max_width=25)
    table.add_column("Current", max_width=12)
    table.add_column("Latest", max_width=12)
    table.add_column("Priority", max_width=10)
    table.add_column("Reason", max_width=35)

    pri_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
    for c in report.candidates:
        p_color = pri_colors.get(c.priority, "white")
        table.add_row(c.name, c.current_version, c.latest_version,
                       f"[{p_color}]{c.priority.upper()}[/]", c.reason)

    console.print(table)

    summary = (
        f"[bold]{report.total_updates}[/] updates available — "
        f"[red]{report.security_updates}[/] security, "
        f"[green]{report.up_to_date}[/] up to date"
    )
    console.print(Panel(summary, title="[bold]Update Summary[/]"))
    console.print("[dim]Run `ossguard fix` to auto-apply security fixes.[/]")


@app.command()
def maturity(
    path: str = typer.Argument(".", help="Path to the project directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Assess S2C2F (Secure Supply Chain Consumption Framework) maturity level."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Maturity[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.maturity import assess_maturity

    with console.status("[bold green]Assessing S2C2F maturity..."):
        report = assess_maturity(project_path)

    if json_output:
        import json as json_mod
        data = {
            "achieved_level": report.achieved_level,
            "level1_pct": report.level1_pct,
            "level2_pct": report.level2_pct,
            "level3_pct": report.level3_pct,
            "level4_pct": report.level4_pct,
            "practices": [
                {"id": p.id, "level": p.level, "category": p.category,
                 "description": p.description, "status": p.status}
                for p in report.practices
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    lvl_color = "green" if report.achieved_level >= 2 else "yellow" if report.achieved_level >= 1 else "red"
    console.print(Panel(
        f"[{lvl_color} bold]S2C2F Level {report.achieved_level}[/]",
        title="[bold]Supply Chain Maturity[/]",
    ))

    for lvl, pct in [(1, report.level1_pct), (2, report.level2_pct),
                      (3, report.level3_pct), (4, report.level4_pct)]:
        bar_color = "green" if pct == 100 else "yellow" if pct >= 50 else "red"
        console.print(f"  Level {lvl}: [{bar_color}]{pct}%[/]")

    table = Table(title="S2C2F Practices")
    table.add_column("ID", style="dim", max_width=14)
    table.add_column("Lvl", justify="center", max_width=4)
    table.add_column("Practice", max_width=50)
    table.add_column("Status", justify="center", max_width=8)

    current_cat = ""
    for p in report.practices:
        if p.category != current_cat:
            table.add_row(f"\n[bold cyan]{p.category}[/]", "", "", "")
            current_cat = p.category
        status_icon = {"met": "[green]MET[/]", "unmet": "[red]UNMET[/]", "unknown": "[yellow]?[/]"}
        table.add_row(p.id, str(p.level), p.description, status_icon.get(p.status, p.status))

    console.print(table)
    console.print(f"\n[dim]Learn more:[/] [cyan]https://github.com/ossf/s2c2f[/]")


@app.command()
def fuzz(
    path: str = typer.Argument(".", help="Path to the project directory"),
    generate: bool = typer.Option(False, "--generate", help="Generate a starter fuzz harness"),
    output_file: str = typer.Option("", "--output", "-o", help="Output file for generated harness"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Check fuzzing readiness and generate starter harnesses."""
    console.print(Panel(BANNER, title="[bold blue]OSSGuard — Fuzz[/]", subtitle=f"v{__version__}"))

    project_path = Path(path).resolve()
    if not project_path.is_dir():
        console.print(f"[red]Error:[/] '{project_path}' is not a directory.")
        raise typer.Exit(1)

    from ossguard.analyzers.fuzz import check_fuzz_readiness

    report = check_fuzz_readiness(project_path)

    if json_output:
        import json as json_mod
        data = {
            "has_fuzzing": report.has_fuzzing,
            "framework": report.framework,
            "readiness_score": report.readiness_score,
            "language": report.language,
            "findings": [
                {"category": f.category, "description": f.description, "file": f.file}
                for f in report.findings
            ],
        }
        console.print_json(json_mod.dumps(data))
        raise typer.Exit(0)

    if generate and report.starter_harness:
        lang_ext = {"python": ".py", "go": "_test.go", "rust": ".rs",
                     "c": ".c", "c++": ".cpp", "javascript": ".js",
                     "typescript": ".ts", "java": ".java"}
        ext = lang_ext.get(report.language.lower(), ".txt")
        default_name = f"fuzz_target{ext}"
        target = output_file or default_name
        Path(target).write_text(report.starter_harness)
        console.print(f"[green]Generated starter harness:[/] {target}")
        console.print("[dim]Customize the harness for your project's functions.[/]")
        raise typer.Exit(0)

    # Readiness gauge
    r_color = "green" if report.readiness_score >= 70 else "yellow" if report.readiness_score >= 30 else "red"
    status = "Active" if report.has_fuzzing else "Not configured"
    console.print(Panel(
        f"[{r_color} bold]{report.readiness_score}%[/] ready — {status}"
        + (f" ({report.framework})" if report.framework else ""),
        title="[bold]Fuzz Readiness[/]",
    ))

    if report.findings:
        for f in report.findings:
            if f.category == "existing":
                console.print(f"  [green]+[/] {f.description}")
            else:
                console.print(f"  [blue]>[/] {f.description}")

    if not report.has_fuzzing:
        console.print(f"\n[dim]Generate a starter harness:[/] [cyan]ossguard fuzz --generate[/]")


@app.command()
def version() -> None:
    """Show the version."""
    console.print(f"ossguard v{__version__}")


if __name__ == "__main__":
    app()
