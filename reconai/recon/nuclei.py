"""
Nuclei vulnerability scanner wrapper.
Runs Nuclei on discovered URLs for vulnerability detection.
"""

import subprocess
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional


def run_nuclei(
    targets: List[str],
    templates: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    rate_limit: int = 150,
    concurrency: int = 25,
    timeout: int = 5
) -> Dict[str, Any]:
    """
    Run Nuclei vulnerability scanner on target URLs.
    
    Args:
        targets: List of URLs to scan
        templates: Optional list of template paths/tags to use
        severity: Optional list of severities to filter (critical, high, medium, low, info)
        rate_limit: Requests per second (default: 150)
        concurrency: Parallel templates (default: 25)
        timeout: Request timeout in seconds (default: 5)
        
    Returns:
        Dict with findings list and stats
    """
    if not targets:
        return {
            "findings": [],
            "total_findings": 0,
            "by_severity": {},
            "scanned_urls": 0
        }
    
    # Check if nuclei is installed
    try:
        subprocess.run(["nuclei", "-version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {
            "error": "Nuclei not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "findings": [],
            "total_findings": 0
        }
    
    # Create temporary file with targets
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write("\n".join(targets))
        target_file = f.name
    
    try:
        # Build nuclei command
        cmd = [
            "nuclei",
            "-l", target_file,
            "-jsonl",
            "-rl", str(rate_limit),
            "-c", str(concurrency),
            "-timeout", str(timeout),
            "-silent"
        ]
        
        # Add templates if specified
        if templates:
            for tpl in templates:
                cmd.extend(["-t", tpl])
        
        # Add severity filter if specified
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        # Run nuclei
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800  # 30 minute max timeout
        )
        
        # Parse JSONL output
        findings = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template_id": finding.get("template-id", "unknown"),
                        "template_name": finding.get("info", {}).get("name", "Unknown"),
                        "severity": finding.get("info", {}).get("severity", "info").upper(),
                        "matched_url": finding.get("matched-at", finding.get("host", "")),
                        "extracted_results": finding.get("extracted-results", []),
                        "matcher_name": finding.get("matcher-name", ""),
                        "type": finding.get("type", ""),
                        "curl_command": finding.get("curl-command", ""),
                        "timestamp": finding.get("timestamp"),
                        "source": "nuclei"
                    })
                except json.JSONDecodeError:
                    continue
        
        # Calculate stats
        by_severity = {}
        for f in findings:
            sev = f["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        return {
            "findings": findings,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "scanned_urls": len(targets)
        }
        
    except subprocess.TimeoutExpired:
        return {
            "error": "Nuclei scan timed out after 30 minutes",
            "findings": [],
            "total_findings": 0
        }
    except Exception as e:
        return {
            "error": f"Nuclei scan failed: {str(e)}",
            "findings": [],
            "total_findings": 0
        }
    finally:
        # Cleanup temp file
        try:
            Path(target_file).unlink()
        except:
            pass


def format_nuclei_finding_for_llm(finding: Dict[str, Any]) -> str:
    """Format a Nuclei finding for LLM context."""
    return f"""
[{finding['severity']}] {finding['template_name']}
Template: {finding['template_id']}
URL: {finding['matched_url']}
Type: {finding['type']}
{f"Extracted: {', '.join(finding['extracted_results'])}" if finding['extracted_results'] else ''}
""".strip()
