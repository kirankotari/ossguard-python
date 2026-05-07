"""Export HTML/JSON compliance report — combines audit data into a shareable document."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ossguard.analyzers.audit import AuditReport, run_audit


def generate_report(
    project_path: str | Path,
    output_format: str = "html",
) -> str:
    """Generate a comprehensive security compliance report.

    Args:
        project_path: Path to the project.
        output_format: "html" or "json".

    Returns:
        Report content as a string.
    """
    audit = run_audit(project_path)

    if output_format == "json":
        return _generate_json_report(audit)
    return _generate_html_report(audit)


def _generate_json_report(audit: AuditReport) -> str:
    """Generate JSON compliance report."""
    data = {
        "report_type": "OSSGuard Security Compliance Report",
        "generated_at": audit.audit_time,
        "overall_grade": audit.overall_grade,
        "configuration": {
            "score": f"{audit.config_score}/{audit.config_total}",
            "percentage": audit.config_pct,
        },
        "dependency_health": None,
        "reachability": None,
        "findings": audit.findings,
        "recommendations": audit.recommendations,
    }

    if audit.dep_health:
        data["dependency_health"] = {
            "total_deps": audit.dep_health.total_deps,
            "aggregate_score": audit.dep_health.aggregate_score,
            "total_vulns": audit.dep_health.total_vulns,
            "critical": audit.dep_health.critical_vulns,
            "high": audit.dep_health.high_vulns,
            "outdated": audit.dep_health.outdated_count,
        }

    if audit.reachability:
        data["reachability"] = {
            "total_deps": audit.reachability.total_deps,
            "reachable": audit.reachability.reachable_deps,
            "total_vulns": audit.reachability.total_vulns,
            "reachable_vulns": audit.reachability.reachable_vulns,
            "noise_reduction_pct": audit.reachability.noise_reduction_pct,
        }

    return json.dumps(data, indent=2)


def _generate_html_report(audit: AuditReport) -> str:
    """Generate HTML compliance report."""
    grade_color = {
        "A": "#22c55e", "B": "#84cc16", "C": "#eab308",
        "D": "#f97316", "F": "#ef4444",
    }.get(audit.overall_grade, "#6b7280")

    # Config items
    config_rows = ""
    if audit.project_info:
        info = audit.project_info
        config_items = [
            ("SECURITY.md", info.has_security_md),
            ("Scorecard", info.has_scorecard),
            ("Dependabot", info.has_dependabot),
            ("CodeQL", info.has_codeql),
            ("SBOM Workflow", info.has_sbom_workflow),
            ("Sigstore", info.has_sigstore),
        ]
        for name, configured in config_items:
            icon = "&#9989;" if configured else "&#10060;"
            status = "Configured" if configured else "Missing"
            color = "#22c55e" if configured else "#ef4444"
            config_rows += f'<tr><td>{name}</td><td style="color:{color}">{icon} {status}</td></tr>\n'

    # Dep health section
    dep_section = ""
    if audit.dep_health:
        dh = audit.dep_health
        dep_section = f"""
    <div class="section">
      <h2>Dependency Health</h2>
      <div class="metrics">
        <div class="metric">
          <span class="metric-value">{dh.total_deps}</span>
          <span class="metric-label">Dependencies</span>
        </div>
        <div class="metric">
          <span class="metric-value" style="color: {'#22c55e' if dh.aggregate_score >= 8 else '#eab308' if dh.aggregate_score >= 5 else '#ef4444'}">{dh.aggregate_score}/10</span>
          <span class="metric-label">Health Score</span>
        </div>
        <div class="metric">
          <span class="metric-value" style="color: {'#22c55e' if dh.total_vulns == 0 else '#ef4444'}">{dh.total_vulns}</span>
          <span class="metric-label">Vulnerabilities</span>
        </div>
        <div class="metric">
          <span class="metric-value">{dh.outdated_count}</span>
          <span class="metric-label">Outdated</span>
        </div>
      </div>
      <p>Critical: <strong style="color:#ef4444">{dh.critical_vulns}</strong> &bull;
         High: <strong style="color:#f97316">{dh.high_vulns}</strong> &bull;
         Medium: <strong style="color:#eab308">{dh.medium_vulns}</strong></p>
    </div>"""

    # Reachability section
    reach_section = ""
    if audit.reachability and audit.reachability.total_vulns > 0:
        r = audit.reachability
        reach_section = f"""
    <div class="section">
      <h2>Reachability Analysis</h2>
      <div class="metrics">
        <div class="metric">
          <span class="metric-value">{r.reachable_deps}/{r.total_deps}</span>
          <span class="metric-label">Reachable Deps</span>
        </div>
        <div class="metric">
          <span class="metric-value" style="color:#ef4444">{r.reachable_vulns}</span>
          <span class="metric-label">Reachable Vulns</span>
        </div>
        <div class="metric">
          <span class="metric-value" style="color:#22c55e">{r.filtered_vulns}</span>
          <span class="metric-label">Filtered</span>
        </div>
        <div class="metric">
          <span class="metric-value" style="color:#22c55e">{r.noise_reduction_pct}%</span>
          <span class="metric-label">Noise Reduction</span>
        </div>
      </div>
    </div>"""

    # Findings & recommendations
    findings_html = "".join(f"<li>{f}</li>" for f in audit.findings) if audit.findings else "<li>No issues found</li>"
    recs_html = "".join(f"<li>{r}</li>" for r in audit.recommendations) if audit.recommendations else "<li>No recommendations</li>"

    project_name = audit.project_info.repo_name if audit.project_info else "Unknown Project"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {project_name}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; }}
.container {{ max-width: 900px; margin: 0 auto; padding: 2rem; }}
header {{ text-align: center; margin-bottom: 2rem; }}
h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
.subtitle {{ color: #64748b; font-size: 0.9rem; }}
.grade-badge {{ display: inline-block; width: 80px; height: 80px; border-radius: 50%; background: {grade_color}; color: white; font-size: 2.5rem; font-weight: bold; line-height: 80px; text-align: center; margin: 1rem 0; }}
.section {{ background: white; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
h2 {{ font-size: 1.2rem; margin-bottom: 1rem; color: #334155; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
th {{ background: #f1f5f9; font-weight: 600; }}
.metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin: 1rem 0; }}
.metric {{ text-align: center; padding: 1rem; background: #f8fafc; border-radius: 8px; }}
.metric-value {{ display: block; font-size: 1.5rem; font-weight: bold; }}
.metric-label {{ display: block; font-size: 0.8rem; color: #64748b; margin-top: 0.25rem; }}
ul {{ padding-left: 1.5rem; }}
li {{ margin: 0.5rem 0; }}
.findings {{ border-left: 4px solid #f97316; }}
.recommendations {{ border-left: 4px solid #3b82f6; }}
footer {{ text-align: center; margin-top: 2rem; color: #94a3b8; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>OSSGuard Security Report</h1>
    <p class="subtitle">{project_name} &bull; {audit.audit_time[:10]}</p>
    <div class="grade-badge">{audit.overall_grade}</div>
    <p>Overall Security Grade</p>
  </header>

  <div class="section">
    <h2>Security Configuration ({audit.config_score}/{audit.config_total})</h2>
    <table>
      <thead><tr><th>Component</th><th>Status</th></tr></thead>
      <tbody>{config_rows}</tbody>
    </table>
  </div>

  {dep_section}
  {reach_section}

  <div class="section findings">
    <h2>Findings ({len(audit.findings)})</h2>
    <ul>{findings_html}</ul>
  </div>

  <div class="section recommendations">
    <h2>Recommendations ({len(audit.recommendations)})</h2>
    <ul>{recs_html}</ul>
  </div>

  <footer>
    Generated by OSSGuard &bull; {audit.audit_time}
  </footer>
</div>
</body>
</html>"""
