"""AI-powered security analysis engine."""

import json
from typing import List, Dict, Any
from collections import Counter

from reconai.models import (
    AttackSurface, Finding, Parameter, Endpoint
)
from reconai.llm import OllamaBackend


# Suspicious parameter patterns
SUSPICIOUS_PARAMS = {
    'file': ['path_traversal', 'lfi'],
    'path': ['path_traversal', 'lfi'],
    'dir': ['path_traversal', 'lfi'],
    'folder': ['path_traversal', 'lfi'],
    'url': ['ssrf', 'open_redirect'],
    'uri': ['ssrf', 'open_redirect'],
    'redirect': ['open_redirect'],
    'return': ['open_redirect'],
    'next': ['open_redirect'],
    'continue': ['open_redirect'],
    'dest': ['open_redirect'],
    'destination': ['open_redirect'],
    'id': ['idor', 'sqli'],
    'user': ['idor', 'sqli'],
    'account': ['idor'],
    'userid': ['idor', 'sqli'],
    'q': ['sqli', 'xss'],
    'query': ['sqli', 'xss'],
    'search': ['sqli', 'xss'],
    'keyword': ['sqli', 'xss'],
    'cmd': ['rce', 'command_injection'],
    'command': ['rce', 'command_injection'],
    'exec': ['rce', 'command_injection'],
    'execute': ['rce', 'command_injection'],
    'ping': ['command_injection'],
    'host': ['command_injection', 'ssrf'],
    'debug': ['info_disclosure'],
    'test': ['info_disclosure'],
    'admin': ['privilege_escalation'],
    'token': ['auth_bypass'],
    'api_key': ['info_disclosure'],
    'apikey': ['info_disclosure'],
    'key': ['info_disclosure'],
    'secret': ['info_disclosure'],
}

# Suspicious endpoint patterns
SUSPICIOUS_ENDPOINTS = [
    '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
    '/debug', '/test', '/dev', '/developer',
    '/console', '/api', '/swagger', '/docs',
    '/backup', '/.git', '/.env', '/config',
    '/upload', '/fileupload', '/download',
    '/.well-known', '/internal', '/private'
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    '.bak', '.backup', '.old', '.tmp', '.temp',
    '.log', '.sql', '.db', '.sqlite',
    '.env', '.config', '.conf', '.ini',
    '.git', '.svn', '.DS_Store'
]


def mark_suspicious_parameters(parameters: List[Parameter]) -> List[Parameter]:
    """Mark parameters as suspicious based on known patterns."""
    for param in parameters:
        param_lower = param.name.lower()
        
        for pattern, risks in SUSPICIOUS_PARAMS.items():
            if pattern in param_lower:
                param.suspicious = True
                param.risk_indicators.extend(risks)
    
    return parameters


def analyze_attack_surface(
    attack_surface: AttackSurface,
    llm: 'OllamaBackend',
    temperature: float = 0.3,
    max_tokens: int = 4096,
    use_chunking: bool = True
) -> AttackSurface:
    """
    Analyze attack surface using AI with intelligent chunking.
    
    Args:
        attack_surface: Collected recon data
        llm: AI backend
        temperature: Sampling temperature
        max_tokens: Max tokens for generation
        use_chunking: Whether to use chunked analysis
        
    Returns:
        Updated attack surface with findings and summary
    """
    from reconai.utils import LLMChunker
    
    # Mark suspicious parameters
    attack_surface.parameters = mark_suspicious_parameters(attack_surface.parameters)
    
    print("\n🤖 Running AI analysis...")
    
    # Use chunked analysis to avoid timeout
    if use_chunking and (len(attack_surface.endpoints) > 100 or attack_surface.total_js_files > 10):
        print("  [*] Using chunked analysis to avoid timeout...")
        return _analyze_with_chunking(attack_surface, llm, temperature, max_tokens)
    
    # Standard analysis for smaller datasets
    prompt = build_analysis_prompt(attack_surface)
    system_prompt = get_system_prompt()
    
    try:
        # Get AI analysis with increased timeout
        response = llm.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=600  # Increase to 10 minutes
        )
        
        # Parse findings from response
        findings = parse_findings_from_response(response, attack_surface)
        attack_surface.findings = findings
        
        # Generate summary
        summary = generate_summary(response, attack_surface)
        attack_surface.summary = summary
        
        # Extract recommendations
        recommendations = extract_recommendations(response)
        attack_surface.recommendations = recommendations
        
    except Exception as e:
        print(f"⚠️  AI analysis error: {e}")
        attack_surface.summary = "AI analysis failed. Manual review required."
    
    return attack_surface


def _analyze_with_chunking(
    attack_surface: AttackSurface,
    llm: 'OllamaBackend',
    temperature: float,
    max_tokens: int
) -> AttackSurface:
    """Analyze attack surface in chunks to avoid timeout."""
    from reconai.utils import LLMChunker
    
    chunker = LLMChunker(chunk_size=20)  # Smaller chunks to avoid timeout
    all_findings = []
    all_responses = []
    
    # Create analysis batches
    print("  [*] Creating analysis batches...")
    attack_dict = attack_surface.model_dump()
    batches = chunker.create_analysis_batches(attack_dict)
    
    print(f"  [*] Analyzing in {len(batches)} batches...")
    
    for i, batch in enumerate(batches, 1):
        success = False
        retry_count = 0
        max_retries = 1
        
        while not success and retry_count <= max_retries:
            try:
                if retry_count > 0:
                    print(f"  [*] Retrying batch {i}/{len(batches)} (attempt {retry_count + 1})...")
                else:
                    print(f"  [*] Analyzing batch {i}/{len(batches)} ({batch.get('priority', 'MEDIUM')} priority)...")
                
                # Build focused prompt for this batch
                batch_prompt = _build_batch_prompt(batch, attack_surface.target_domain)
                system_prompt = get_system_prompt()
                
                # Analyze batch with sufficient timeout (longer on retry)
                timeout = 600 if retry_count == 0 else 900  # 10 or 15 minutes
                response = llm.generate(
                    prompt=batch_prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=timeout
                )
                
                all_responses.append(response)
                
                # Extract findings from batch
                batch_findings = parse_findings_from_response(response, attack_surface)
                all_findings.extend(batch_findings)
                
                print(f"  [+] Batch {i} complete: Found {len(batch_findings)} findings")
                success = True
                
            except Exception as e:
                retry_count += 1
                if retry_count > max_retries:
                    print(f"  [!] Batch {i} failed after {max_retries + 1} attempts: {e}")
                    print(f"  [!] Skipping batch {i}, continuing with remaining batches...")
                else:
                    print(f"  [!] Batch {i} failed: {e}")
                    print(f"  [*] Will retry with longer timeout...")
    
    # Aggregate results
    attack_surface.findings = all_findings
    
    # Generate summary from all responses
    combined_response = "\n\n".join(all_responses)
    attack_surface.summary = generate_summary(combined_response, attack_surface)
    attack_surface.recommendations = extract_recommendations(combined_response)
    
    print(f"  [+] Chunked analysis complete: {len(all_findings)} total findings")
    
    return attack_surface


def _build_batch_prompt(batch: Dict, target_domain: str) -> str:
    """Build focused prompt for a specific batch."""
    prompt = f"""Analyze this security data for {target_domain}:\n\n"""
    
    batch_type = batch.get('type', 'general')
    priority = batch.get('priority', 'MEDIUM')
    
    prompt += f"## Priority: {priority}\n\n"
    
    # Critical batch (secrets + suspicious items)
    if priority == 'CRITICAL':
        if batch.get('secrets'):
            prompt += f"### CRITICAL SECRETS FOUND ({len(batch['secrets'])} items):\n"
            for secret in batch['secrets'][:20]:
                prompt += f"\n- **{secret.get('type')}** [{secret.get('severity')}]\n"
                prompt += f"  Value: {secret.get('value')[:80]}...\n"
                prompt += f"  Context: {secret.get('context')[:100]}...\n"
        
        if batch.get('suspicious_params'):
            prompt += f"\n### Suspicious Parameters ({len(batch['suspicious_params'])} items):\n"
            for param in batch['suspicious_params'][:30]:
                prompt += f"- {param.get('name')} (found {param.get('count')}x)"
                if param.get('risk_indicators'):
                    prompt += f" → Risks: {', '.join(param['risk_indicators'])}\n"
        
        if batch.get('suspicious_endpoints'):
            prompt += f"\n### Suspicious Endpoints ({len(batch['suspicious_endpoints'])} items):\n"
            for ep in batch['suspicious_endpoints'][:30]:
                prompt += f"- {ep.get('url')}\n"
    
    # JS Analysis batch
    elif batch_type == 'js_analysis':
        js_files = batch.get('js_files', [])
        prompt += f"### JavaScript Files Analysis (Batch {batch.get('chunk')} - {len(js_files)} files):\n\n"
        for js_file in js_files:
            prompt += f"**{js_file.get('url')}**\n"
            if js_file.get('content'):
                prompt += f"```javascript\n{js_file['content'][:1000]}\n```\n\n"
    
    # Endpoint Analysis batch  
    elif batch_type == 'endpoint_analysis':
        endpoints = batch.get('endpoints', [])
        prompt += f"### Endpoints Analysis (Batch {batch.get('chunk')} - {len(endpoints)} endpoints):\n\n"
        for ep in endpoints[:50]:
            prompt += f"- {ep.get('url')}"
            if ep.get('status_code'):
                prompt += f" [{ep['status_code']}]"
            prompt += "\n"
    
    prompt += """

## Analysis Task:
Focus on this batch only. Identify:
1. Security vulnerabilities
2. Misconfigurations
3. Exposed sensitive data
4. Attack vectors

Provide specific, actionable findings with evidence."""
    
    return prompt


def get_system_prompt() -> str:
    """Returns the system prompt for the AI analysis."""
    return """You are an expert penetration tester specializing in web application offensive security and exploitation.
Your task is to analyze the provided reconnaissance data and identify exploitable vulnerabilities and attack vectors.

Focus on:
1. High-impact vulnerabilities (SSRF, SQLi, RCE, Path Traversal, IDOR)
2. Suspicious parameters that could lead to exploitation
3. Exposed sensitive endpoints (admin panels, debug pages, backups)
4. Information disclosure (API keys, tokens, internal paths)
5. Authentication bypasses and logic flaws

For each finding, use this EXACT format:

## [SEVERITY] Finding Title (Category)

Description: [Brief description of the vulnerability and why it's exploitable]

Affected Endpoints:
- /api/endpoint1
- /api/endpoint2

Affected Parameters:
- parameter_name1
- parameter_name2

Evidence:
- Specific evidence from scan data
- Code snippets or configuration issues
- URLs or file paths showing the issue

Exploitation: [Detailed explanation of how to exploit this vulnerability, include attack scenarios and impact]

POC: [Proof of concept - provide curl commands, code snippets, or step-by-step exploitation steps]

---

IMPORTANT: Always include:
1. Specific endpoint paths or URLs where the issue exists
2. Exact parameter names that are vulnerable
3. Direct evidence from the scan results
4. Detailed exploitation techniques and attack scenarios
5. Working POC code or commands when possible

Be precise and evidence-based. Prioritize findings by exploitability and impact. Think like an attacker."""


def build_analysis_prompt(attack_surface: AttackSurface) -> str:
    """Build analysis prompt from attack surface data."""
    
    # Prepare data summaries
    subdomain_count = len(attack_surface.subdomains)
    endpoint_count = len(attack_surface.endpoints)
    param_count = len(attack_surface.parameters)
    
    # Top suspicious parameters
    suspicious_params = [p for p in attack_surface.parameters if p.suspicious]
    suspicious_params.sort(key=lambda x: x.count, reverse=True)
    top_suspicious = suspicious_params[:20]
    
    # Endpoints with suspicious patterns
    suspicious_endpoints = []
    for endpoint in attack_surface.endpoints[:500]:  # Limit for token constraints
        url_lower = endpoint.url.lower()
        
        # Check for suspicious paths
        if any(pattern in url_lower for pattern in SUSPICIOUS_ENDPOINTS):
            suspicious_endpoints.append(endpoint)
            continue
        
        # Check for suspicious extensions
        if any(url_lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            suspicious_endpoints.append(endpoint)
    
    # Technologies detected
    tech_summary = {}
    for endpoint in attack_surface.endpoints:
        for tech in endpoint.technologies:
            tech_summary[tech] = tech_summary.get(tech, 0) + 1
    
    # Build prompt
    prompt = f"""Analyze the following web application attack surface for security vulnerabilities:

## Target
Domain: {attack_surface.target_domain}

## Reconnaissance Summary
- Subdomains discovered: {subdomain_count}
- Total endpoints: {endpoint_count}
- Parameters identified: {param_count}
- Alive hosts: {attack_surface.alive_hosts}

## Technologies Detected
{json.dumps(tech_summary, indent=2) if tech_summary else "None detected"}

## Suspicious Parameters ({len(top_suspicious)} shown)
"""
    
    for param in top_suspicious:
        prompt += f"\n- **{param.name}** (found {param.count}x)"
        if param.risk_indicators:
            prompt += f" → Risks: {', '.join(set(param.risk_indicators))}"
        if param.example_value:
            prompt += f"\n  Example: {param.example_value}"
    
    prompt += f"\n\n## Suspicious Endpoints ({len(suspicious_endpoints)} shown)\n"
    
    for endpoint in suspicious_endpoints[:30]:
        prompt += f"\n- {endpoint.url}"
        if endpoint.status_code:
            prompt += f" [{endpoint.status_code}]"
        if endpoint.title:
            prompt += f" - {endpoint.title}"
    
    # Add JavaScript analysis results if available
    if attack_surface.js_analysis:
        prompt += f"\n\n## JavaScript Analysis Results\n"
        prompt += f"- JavaScript files analyzed: {attack_surface.js_analysis.js_files_analyzed}\n"
        prompt += f"- Secrets discovered: {len(attack_surface.js_analysis.secrets)}\n"
        prompt += f"- Endpoints extracted from JS: {len(attack_surface.js_analysis.endpoints)}\n"
        prompt += f"- External links found: {len(attack_surface.js_analysis.links)}\n"
        prompt += f"- NPM modules: {len(attack_surface.js_analysis.modules)}\n"
        
        # Include top secrets
        if attack_surface.js_analysis.secrets:
            prompt += f"\n### Critical Secrets Found in JavaScript:\n"
            for secret in attack_surface.js_analysis.secrets[:10]:
                prompt += f"\n- **{secret.type}** [{secret.severity}]"
                prompt += f"\n  Value: {secret.value[:80]}..."
                prompt += f"\n  Context: {secret.context[:100]}...\n"
        
        # Include JS endpoints
        if attack_surface.js_analysis.endpoints:
            prompt += f"\n### Endpoints Extracted from JS Code ({len(attack_surface.js_analysis.endpoints[:20])} shown):\n"
            for ep in attack_surface.js_analysis.endpoints[:20]:
                prompt += f"- {ep}\n"
        
        # Include interesting variables
        if attack_surface.js_analysis.interesting_vars:
            prompt += f"\n### Interesting Variables/Config in JS:\n"
            for var in attack_surface.js_analysis.interesting_vars[:15]:
                prompt += f"- {var}\n"
    
    # Add application logic analysis
    if attack_surface.app_logic:
        prompt += f"\n\n## Application Logic Analysis\n"
        prompt += "### Understanding the Application Flow:\n\n"
        
        # Authentication flows
        if attack_surface.app_logic.get('auth_flows'):
            prompt += "**Authentication Patterns Detected:**\n"
            for flow_type, matches in attack_surface.app_logic['auth_flows'].items():
                if matches:
                    prompt += f"\n- **{flow_type.replace('_', ' ').title()}** ({len(matches)} occurrences)\n"
                    # Show first example
                    if matches and len(matches) > 0:
                        prompt += f"  Example: `{matches[0][:150]}...`\n"
        
        # API call patterns
        if attack_surface.app_logic.get('api_calls'):
            prompt += f"\n**API Call Patterns:** {len(attack_surface.app_logic['api_calls'])} unique patterns\n"
            for call in attack_surface.app_logic['api_calls'][:10]:
                prompt += f"- {call.get('type', 'unknown')}: `{call.get('value', '')[:100]}`\n"
        
        # Interesting code snippets
        if attack_surface.app_logic.get('interesting_snippets'):
            prompt += f"\n**Code Snippets for Analysis:**\n"
            for i, snippet in enumerate(attack_surface.app_logic['interesting_snippets'][:5], 1):
                prompt += f"\nSnippet {i}:\n```javascript\n{snippet[:300]}\n```\n"
    
    # Add manifest data
    if attack_surface.manifest_data and attack_surface.manifest_data.get('files_found'):
        prompt += f"\n\n## Manifest Files Discovered\n"
        prompt += f"Found {len(attack_surface.manifest_data['files_found'])} manifest files containing:\n"
        prompt += f"- {len(attack_surface.manifest_data['endpoints'])} endpoints\n"
        prompt += f"- {len(attack_surface.manifest_data['routes'])} routes\n"
        prompt += f"- {len(attack_surface.manifest_data['js_files'])} additional JS files\n"
    
    prompt += """

## Analysis Tasks

1. **Deep Application Analysis:**
   - Understand the authentication flow from JS code snippets
   - Identify password reset mechanisms and potential bypasses
   - Analyze API call patterns for access control issues
   - Review code snippets for logic flaws

2. **Comprehensive Data Review:**
   - All endpoints from httpx, katana, waybackurls, JS, and manifests
   - All parameters with their usage context
   - JavaScript secrets (CRITICAL - real exposed credentials!)
   - Application logic patterns and flows

3. **Vulnerability Identification:**
   - **Authentication Issues:** Based on auth flow analysis
   - **SSRF, SQLi, RCE, Path Traversal:** From parameter analysis
   - **Secrets Exposure:** From JS analysis (treat as CRITICAL)
   - **Logic Flaws:** From code snippet analysis
   - **Insecure Password Reset:** From flow patterns
   - **API Security Issues:** From API call patterns

4. **Prioritization:**
   - JavaScript secrets = CRITICAL (immediate exposure)
   - Authentication/authorization flaws = HIGH
   - Password reset vulnerabilities = HIGH
   - SSRF/RCE parameters = HIGH
   - Logic flaws from code analysis = MEDIUM-HIGH

5. **Application Understanding:**
   Use the code snippets and authentication patterns to understand:
   - How users authenticate
   - Token/session management
   - Password reset process
   - API authentication methods
   - State management

IMPORTANT: You have access to actual JavaScript code and application logic.
Analyze the code snippets to understand HOW the application works, not just WHAT endpoints exist.
Look for logic flaws, insecure implementations, and authentication bypasses.

Provide detailed findings with evidence from ALL sources including code analysis."""
    
    return prompt


def parse_findings_from_response(response: str, attack_surface: AttackSurface) -> List[Finding]:
    """Extract structured findings from AI response with full location details."""
    findings = []
    
    lines = response.split('\n')
    
    current_finding = None
    current_section = None  # Track which section we're in (endpoints, parameters, evidence, etc.)
    
    severity_keywords = {'critical', 'high', 'medium', 'low'}
    vuln_categories = {
        'ssrf', 'sqli', 'sql injection', 'xss', 'rce', 'command injection',
        'path traversal', 'lfi', 'idor', 'open redirect', 'info disclosure',
        'information disclosure', 'auth bypass', 'privilege escalation',
        'csrf', 'xxe', 'deserialization', 'authentication bypass', 'access control'
    }
    
    for i, line in enumerate(lines):
        line_lower = line.lower().strip()
        line_stripped = line.strip()
        
        # Detect new finding (severity OR category heading)
        is_new_finding = False
        
        # Check for severity-based finding
        for sev in severity_keywords:
            if sev in line_lower and ('severity' in line_lower or 'risk' in line_lower or 'vulnerability' in line_lower):
                # Save previous finding
                if current_finding:
                    findings.append(current_finding)
                
                current_finding = Finding(
                    severity=sev,
                    category="Unknown",
                    title=line_stripped.strip('*#- ').strip(),
                    description="",
                    evidence=[],
                    affected_endpoints=[],
                    affected_parameters=[]
                )
                current_section = None
                is_new_finding = True
                break
        
        # Check for category-based finding (numbered findings like "1. SQL Injection")
        if not is_new_finding:
            for cat in vuln_categories:
                if cat in line_lower and (line_stripped.startswith(('#', '*', '-', '•')) or 
                                         (line_stripped and line_stripped[0].isdigit() and '.' in line_stripped[:5])):
                    # Save previous finding
                    if current_finding:
                        findings.append(current_finding)
                    
                    # Extract severity from nearby text
                    detected_severity = "medium"
                    for sev in severity_keywords:
                        if sev in line_lower:
                            detected_severity = sev
                            break
                    
                    current_finding = Finding(
                        severity=detected_severity,
                        category=cat.upper().replace(' ', '_'),
                        title=line_stripped.lstrip('#*-•0123456789. ').strip(),
                        description="",
                        evidence=[],
                        affected_endpoints=[],
                        affected_parameters=[]
                    )
                    current_section = None
                    is_new_finding = True
                    break
        
        # If we have an active finding, parse its details
        if current_finding and not is_new_finding:
            # Detect section headers
            if 'affected endpoint' in line_lower or 'endpoint' in line_lower and ':' in line:
                current_section = 'endpoints'
                # Try to extract endpoints from same line
                if ':' in line:
                    endpoints_text = line.split(':', 1)[1].strip()
                    if endpoints_text:
                        # Split by commas or semicolons
                        for ep in endpoints_text.replace(';', ',').split(','):
                            ep = ep.strip().strip('`"\'')
                            if ep and (ep.startswith('/') or ep.startswith('http')):
                                current_finding.affected_endpoints.append(ep)
                continue
            
            elif 'affected parameter' in line_lower or 'parameter' in line_lower and ':' in line:
                current_section = 'parameters'
                # Try to extract parameters from same line
                if ':' in line:
                    params_text = line.split(':', 1)[1].strip()
                    if params_text:
                        for param in params_text.replace(';', ',').split(','):
                            param = param.strip().strip('`"\'')
                            if param and len(param) < 50:  # Reasonable parameter name length
                                current_finding.affected_parameters.append(param)
                continue
            
            elif 'evidence' in line_lower and ':' in line:
                current_section = 'evidence'
                # Try to extract evidence from same line
                if ':' in line:
                    evidence_text = line.split(':', 1)[1].strip()
                    if evidence_text and len(evidence_text) > 10:
                        current_finding.evidence.append(evidence_text)
                continue
            
            elif 'exploitation' in line_lower and ':' in line:
                current_section = 'exploitation'
                # Extract exploitation from same line
                if ':' in line:
                    exploitation_text = line.split(':', 1)[1].strip()
                    if exploitation_text and len(exploitation_text) > 10:
                        current_finding.exploitation_notes = exploitation_text
                continue
            
            elif 'poc' in line_lower and ':' in line:
                current_section = 'poc'
                # Extract POC from same line
                if ':' in line:
                    poc_text = line.split(':', 1)[1].strip()
                    if poc_text and len(poc_text) > 5:
                        current_finding.poc = poc_text
                continue
            
            elif 'description' in line_lower and ':' in line:
                current_section = 'description'
                # Extract description from same line
                if ':' in line:
                    desc_text = line.split(':', 1)[1].strip()
                    if desc_text and len(desc_text) > 10:
                        current_finding.description = desc_text
                continue
            
            # Add content to current section
            if current_section and line_stripped:
                # Skip empty lines and section headers
                if line_stripped.startswith(('-', '*', '•')) or line_stripped.startswith('  -'):
                    content = line_stripped.lstrip('-*•').strip()
                    
                    if current_section == 'endpoints' and content:
                        content = content.strip('`"\'')
                        if content.startswith('/') or content.startswith('http'):
                            current_finding.affected_endpoints.append(content)
                    
                    elif current_section == 'parameters' and content and len(content) < 50:
                        content = content.strip('`"\'')
                        current_finding.affected_parameters.append(content)
                    
                    elif current_section == 'evidence' and content and len(content) > 10:
                        current_finding.evidence.append(content)
                    
                    elif current_section == 'exploitation' and content and len(content) > 10:
                        if current_finding.exploitation_notes:
                            current_finding.exploitation_notes += " " + content
                        else:
                            current_finding.exploitation_notes = content
                    
                    elif current_section == 'poc' and content and len(content) > 5:
                        if current_finding.poc:
                            current_finding.poc += "\n" + content
                        else:
                            current_finding.poc = content
                    
                    elif current_section == 'description' and content and len(content) > 10:
                        if current_finding.description:
                            current_finding.description += " " + content
                        else:
                            current_finding.description = content
                
                # Also capture plain text in description if not in specific section
                elif not current_section and line_stripped and not line_stripped.startswith('#'):
                    if len(line_stripped) > 20 and not any(kw in line_lower for kw in severity_keywords | vuln_categories):
                        if current_finding.description:
                            current_finding.description += " " + line_stripped
                        else:
                            current_finding.description = line_stripped
    
    # Don't forget the last finding
    if current_finding:
        findings.append(current_finding)
    
    # If no findings parsed, create a generic one
    if not findings:
        findings.append(Finding(
            severity="info",
            category="MANUAL_REVIEW",
            title="Manual review recommended",
            description=response[:500],
            evidence=[],
            affected_endpoints=[],
            affected_parameters=[]
        ))
    
    return findings


def generate_summary(response: str, attack_surface: AttackSurface) -> str:
    """Extract summary from AI response."""
    # Try to find summary section
    lines = response.split('\n')
    summary_lines = []
    in_summary = False
    
    for line in lines:
        if 'attack surface summary' in line.lower() or 'overview' in line.lower():
            in_summary = True
            continue
        
        if in_summary:
            if line.startswith('#') and summary_lines:
                break
            if line.strip():
                summary_lines.append(line)
    
    if summary_lines:
        return '\n'.join(summary_lines[:10])  # First 10 lines of summary
    
    # Fallback: use first paragraph
    paragraphs = response.split('\n\n')
    return paragraphs[0] if paragraphs else response[:500]


def extract_recommendations(response: str) -> List[str]:
    """Extract actionable recommendations from response."""
    recommendations = []
    lines = response.split('\n')
    
    in_recommendations = False
    
    for line in lines:
        line_stripped = line.strip()
        
        if 'priority actions' in line.lower() or 'recommendations' in line.lower() or 'next steps' in line.lower():
            in_recommendations = True
            continue
        
        if in_recommendations:
            if line.startswith('#') and recommendations:
                break
            
            # Extract bullet points
            if line_stripped.startswith(('-', '*', '•')) or (line_stripped and line_stripped[0].isdigit()):
                rec = line_stripped.lstrip('-*•0123456789. ').strip()
                if rec and len(rec) > 10:
                    recommendations.append(rec)
    
    return recommendations[:10]  # Top 10 recommendations
