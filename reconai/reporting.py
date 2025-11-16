"""Reporting and output formatting."""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box

from reconai.models import AttackSurface, Finding


console = Console()


def print_banner():
    """Print tool banner."""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║      🦅 HackwithAI - LLM-Powered Security Recon           ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def print_scan_progress(message: str, prefix: str = "[*]"):
    """Print scan progress message."""
    console.print(f"{prefix}  {message}", style="bold")


def print_attack_surface_summary(attack_surface: AttackSurface):
    """Print attack surface summary to console."""
    
    console.print("\n")
    console.print(Panel.fit(
        f"[bold cyan]Target:[/bold cyan] {attack_surface.target_domain}",
        title="Scan Results",
        border_style="cyan"
    ))
    
    # Stats table
    stats_table = Table(show_header=False, box=box.ROUNDED, border_style="blue")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Count", style="bold green")
    
    stats_table.add_row("Subdomains", str(attack_surface.total_subdomains))
    stats_table.add_row("Endpoints", str(attack_surface.total_endpoints))
    stats_table.add_row("Parameters", str(attack_surface.total_parameters))
    stats_table.add_row("Alive Hosts", str(attack_surface.alive_hosts))
    stats_table.add_row("JS Files", str(attack_surface.total_js_files))
    stats_table.add_row("Secrets", str(attack_surface.total_secrets))
    stats_table.add_row("Findings", str(len(attack_surface.findings)))
    
    console.print(stats_table)
    
    # Summary
    if attack_surface.summary:
        console.print("\n")
        console.print(Panel(
            attack_surface.summary,
            title="Attack Surface Summary",
            border_style="yellow"
        ))
    
    # Secrets from JS
    if attack_surface.js_analysis and attack_surface.js_analysis.secrets:
        console.print("\n")
        secrets_table = Table(
            title="Discovered Secrets (JS Analysis)",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True
        )
        secrets_table.add_column("Type", style="bold red", width=25)
        secrets_table.add_column("Value", style="cyan", width=50)
        secrets_table.add_column("Severity", style="bold", width=10)
        
        for secret in attack_surface.js_analysis.secrets[:20]:
            secrets_table.add_row(
                secret.type,
                secret.value[:50] + "..." if len(secret.value) > 50 else secret.value,
                secret.severity
            )
        console.print(secrets_table)
    
    # Findings
    if attack_surface.findings:
        print_findings(attack_surface.findings)
    
    # Suspicious parameters
    suspicious_params = [p for p in attack_surface.parameters if p.suspicious]
    if suspicious_params:
        print_suspicious_parameters(suspicious_params[:15])
    
    # Recommendations
    if attack_surface.recommendations:
        print_recommendations(attack_surface.recommendations)


def print_findings(findings: list[Finding]):
    """Print security findings."""
    console.print("\n")
    
    # Group by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.severity.lower(), 5))
    
    # Severity colors
    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "white"
    }
    
    findings_table = Table(
        title="Security Findings",
        box=box.ROUNDED,
        border_style="red",
        show_lines=True
    )
    
    findings_table.add_column("Severity", style="bold", width=12)
    findings_table.add_column("Category", style="cyan", width=18)
    findings_table.add_column("Finding", width=60)
    
    for finding in findings_sorted[:20]:  # Show top 20
        severity_str = f"[{finding.severity.upper()}]"
        
        # Build finding description
        desc = f"[bold]{finding.title}[/bold]\n"
        if finding.description:
            desc += f"{finding.description[:150]}...\n" if len(finding.description) > 150 else f"{finding.description}\n"
        
        if finding.affected_endpoints:
            desc += f"\n[dim]Endpoints: {len(finding.affected_endpoints)}[/dim]"
        
        if finding.affected_parameters:
            desc += f"\n[dim]Parameters: {', '.join(finding.affected_parameters[:3])}[/dim]"
        
        findings_table.add_row(
            severity_str,
            finding.category,
            desc
        )
    
    console.print(findings_table)


def print_suspicious_parameters(parameters: list):
    """Print suspicious parameters."""
    console.print("\n")
    
    param_table = Table(
        title="Suspicious Parameters",
        box=box.ROUNDED,
        border_style="yellow"
    )
    
    param_table.add_column("Parameter", style="bold cyan", width=20)
    param_table.add_column("Count", style="green", width=8)
    param_table.add_column("Risk Indicators", style="red", width=40)
    param_table.add_column("Example", style="dim", width=30)
    
    for param in parameters[:15]:
        risks = ', '.join(set(param.risk_indicators)) if param.risk_indicators else "-"
        example = (param.example_value[:30] + "...") if param.example_value and len(param.example_value) > 30 else (param.example_value or "-")
        
        param_table.add_row(
            param.name,
            str(param.count),
            risks,
            example
        )
    
    console.print(param_table)


def print_recommendations(recommendations: list[str]):
    """Print recommendations."""
    console.print("\n")
    
    rec_text = "\n".join([f"{i+1}. {rec}" for i, rec in enumerate(recommendations)])
    
    console.print(Panel(
        rec_text,
        title="Recommended Next Steps",
        border_style="green"
    ))


def write_json_report(attack_surface: AttackSurface, output_path: Path):
    """Write JSON report to file."""
    try:
        with open(output_path, 'w') as f:
            json.dump(attack_surface.model_dump(), f, indent=2, default=str)
        
        console.print(f"✅ JSON report saved: {output_path}", style="green")
    except Exception as e:
        console.print(f"❌ Failed to write JSON report: {e}", style="red")


def write_markdown_report(attack_surface: AttackSurface, output_path: Path):
    """Write Markdown report to file."""
    try:
        md_content = generate_markdown_report(attack_surface)
        
        with open(output_path, 'w') as f:
            f.write(md_content)
        
        console.print(f"✅ Markdown report saved: {output_path}", style="green")
    except Exception as e:
        console.print(f"❌ Failed to write Markdown report: {e}", style="red")


def generate_markdown_report(attack_surface: AttackSurface) -> str:
    """Generate Markdown report content."""
    
    md = f"""# HackwithAI Security Report 🦅

**Target:** {attack_surface.target_domain}  
**Scan Date:** {attack_surface.scan_start.strftime('%Y-%m-%d %H:%M:%S')}  
**Model:** Analysis completed using local LLM

---

## Executive Summary

{attack_surface.summary or "No summary available."}

### Statistics

- **Subdomains Discovered:** {attack_surface.total_subdomains}
- **Total Endpoints:** {attack_surface.total_endpoints}
- **Parameters Identified:** {attack_surface.total_parameters}
- **Alive Hosts:** {attack_surface.alive_hosts}
- **Security Findings:** {len(attack_surface.findings)}

---

## 🚨 Security Findings

"""
    
    # Group findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(
        attack_surface.findings,
        key=lambda f: severity_order.get(f.severity.lower(), 5)
    )
    
    for finding in findings_sorted:
        emoji_map = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪"
        }
        emoji = emoji_map.get(finding.severity.lower(), "⚪")
        
        md += f"\n### {emoji} [{finding.severity.upper()}] {finding.title}\n\n"
        md += f"**Category:** {finding.category}  \n"
        md += f"**Confidence:** {finding.confidence}  \n\n"
        
        if finding.description:
            md += f"{finding.description}\n\n"
        
        if finding.affected_endpoints:
            md += f"**Affected Endpoints ({len(finding.affected_endpoints)}):**\n"
            for endpoint in finding.affected_endpoints[:5]:
                md += f"- `{endpoint}`\n"
            if len(finding.affected_endpoints) > 5:
                md += f"- *...and {len(finding.affected_endpoints) - 5} more*\n"
            md += "\n"
        
        if finding.affected_parameters:
            md += f"**Affected Parameters:** {', '.join(f'`{p}`' for p in finding.affected_parameters)}\n\n"
        
        if finding.exploitation_notes:
            md += f"**Exploitation:**\n{finding.exploitation_notes}\n\n"
        
        if finding.poc:
            md += f"**POC:**\n```\n{finding.poc}\n```\n\n"
        
        md += "---\n"
    
    # Suspicious parameters
    suspicious_params = [p for p in attack_surface.parameters if p.suspicious]
    if suspicious_params:
        md += "\n## Suspicious Parameters\n\n"
        md += "| Parameter | Count | Risk Indicators | Example Value |\n"
        md += "|-----------|-------|-----------------|---------------|\n"
        
        for param in suspicious_params[:20]:
            risks = ', '.join(set(param.risk_indicators)) if param.risk_indicators else "-"
            example = param.example_value[:30] if param.example_value else "-"
            md += f"| `{param.name}` | {param.count} | {risks} | `{example}` |\n"
        
        md += "\n"
    
    # Recommendations
    if attack_surface.recommendations:
        md += "\n## Recommended Actions\n\n"
        for i, rec in enumerate(attack_surface.recommendations, 1):
            md += f"{i}. {rec}\n"
        md += "\n"
    
    # Technologies
    if attack_surface.technologies:
        md += "\n## Technologies Detected\n\n"
        for tech, hosts in attack_surface.technologies.items():
            md += f"- **{tech}:** {len(hosts)} hosts\n"
        md += "\n"
    
    md += """
---

## Disclaimer

This report is generated by automated reconnaissance and LLM analysis. All findings should be manually verified before taking action. Always obtain proper authorization before conducting security testing.

*Report generated by HackwithAI - Local LLM Security Reconnaissance Tool*
"""
    
    return md
