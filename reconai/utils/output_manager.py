"""Output Manager - Organizes scan results into folders."""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Union
from ..json_encoder import DateTimeEncoder, json_dumps, json_loads


class OutputManager:
    """Manages organized output of scan results."""
    
    def __init__(self, base_dir: Path):
        """Initialize output manager with base directory."""
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        # Create organized subdirectories
        self.dirs = {
            'subdomains': self.base_dir / 'subdomains',
            'endpoints': self.base_dir / 'endpoints',
            'parameters': self.base_dir / 'parameters',
            'js_files': self.base_dir / 'js_files',
            'secrets': self.base_dir / 'secrets',
            'findings': self.base_dir / 'findings',
            'raw': self.base_dir / 'raw',
            'reports': self.base_dir / 'reports'
        }
        
        for dir_path in self.dirs.values():
            dir_path.mkdir(exist_ok=True)
    
    def save_subdomains(self, subdomains: List[Dict]) -> Path:
        """Save subdomains to organized file."""
        output_file = self.dirs['subdomains'] / 'subdomains.txt'
        json_file = self.dirs['subdomains'] / 'subdomains.json'
        
        # Save as text list
        with output_file.open('w') as f:
            for sub in subdomains:
                f.write(f"{sub.get('host', sub)}\n")
        
        # Save as JSON
        with json_file.open('w') as f:
            json.dump(subdomains, f, indent=2)
        
        return output_file
    
    def save_endpoints(self, endpoints: List[Dict]) -> Path:
        """Save endpoints to organized file."""
        output_file = self.dirs['endpoints'] / 'endpoints.txt'
        json_file = self.dirs['endpoints'] / 'endpoints.json'
        
        # Save as text list
        with output_file.open('w') as f:
            for ep in endpoints:
                url = ep.get('url', ep) if isinstance(ep, dict) else ep
                f.write(f"{url}\n")
        
        # Save as JSON with details
        with open(json_file, 'w') as f:
            f.write(json_dumps(endpoints, indent=2))
        
        return output_file
    
    def save_js_files(self, js_files: List[Dict]) -> Path:
        """Save JavaScript files and content with source tracking."""
        json_file = self.dirs['js_files'] / 'js_files.json'
        urls_file = self.dirs['js_files'] / 'js_urls.txt'
        
        # Create raw JS directory
        js_raw_dir = self.dirs['js_files'] / 'raw'
        js_raw_dir.mkdir(exist_ok=True)
        
        # Save URLs list with source info
        with urls_file.open('w') as f:
            for js in js_files:
                source = js.get('source', 'unknown')
                f.write(f"{js.get('url', '')} [source: {source}]\n")
        
        # Save full data
        with open(json_file, 'w') as f:
            f.write(json_dumps(js_files, indent=2))
        
        # Save individual raw JS files with metadata
        for i, js in enumerate(js_files, 1):
            if 'content' in js and js['content']:
                # Create safe filename from URL
                js_url = js.get('url', f'unknown_{i}')
                safe_filename = self._sanitize_filename(js_url)
                
                # Save raw JS content
                js_file_path = js_raw_dir / f"{safe_filename}.js"
                try:
                    with js_file_path.open('w', encoding='utf-8', errors='ignore') as f:
                        f.write(js['content'])
                    
                    # Save metadata
                    meta_file = js_raw_dir / f"{safe_filename}.meta.json"
                    with open(meta_file, 'w') as f:
                        f.write(json_dumps({
                            'url': js.get('url'),
                            'source': js.get('source', 'unknown'),
                            'size': len(js['content']),
                            'timestamp': js.get('timestamp', datetime.now().isoformat()),
                            'file_path': str(js_file_path.name)
                        }, indent=2))
                except Exception as e:
                    print(f"  [!] Failed to save {js_url}: {e}")
        
        return json_file
    
    def _sanitize_filename(self, url: str, max_length: int = 100) -> str:
        """Create a safe filename from URL."""
        import re
        # Remove protocol
        filename = url.replace('https://', '').replace('http://', '')
        # Replace special chars with underscore
        filename = re.sub(r'[^\w\-\.]', '_', filename)
        # Trim to max length
        if len(filename) > max_length:
            filename = filename[:max_length]
        # Remove trailing underscores and dots
        filename = filename.strip('_.')
        return filename or 'unnamed'
    
    def save_secrets(self, secrets: List[Dict]) -> Path:
        """Save discovered secrets."""
        if not secrets:
            return None
        
        output_file = self.dirs['secrets'] / 'secrets.json'
        critical_file = self.dirs['secrets'] / 'CRITICAL_SECRETS.txt'
        
        # Save all secrets as JSON
        with open(output_file, 'w') as f:
            f.write(json_dumps(secrets, indent=2))
        
        # Save critical secrets in readable format with source tracking
        critical_secrets = [s for s in secrets if s.get('severity') == 'CRITICAL']
        if critical_secrets:
            with critical_file.open('w') as f:
                f.write("⚠️  CRITICAL SECRETS FOUND ⚠️\n")
                f.write("="*50 + "\n\n")
                for secret in critical_secrets:
                    f.write(f"Type: {secret.get('type')}\n")
                    f.write(f"Value: {secret.get('value')}\n")
                    f.write(f"Context: {secret.get('context')}\n")
                    if secret.get('js_file'):
                        f.write(f"Found in: {secret.get('js_file')}\n")
                    if secret.get('line_number'):
                        f.write(f"Line: {secret.get('line_number')}\n")
                    f.write("-"*50 + "\n\n")
        
        return output_file
    
    def save_findings(self, findings: List[Dict]) -> Path:
        """Save security findings."""
        if not findings:
            return None
        
        output_file = self.dirs['findings'] / 'findings.json'
        summary_file = self.dirs['findings'] / 'findings_summary.txt'
        
        # Save as JSON
        with open(output_file, 'w') as f:
            f.write(json_dumps(findings, indent=2))
        
        # Save readable summary
        with summary_file.open('w') as f:
            f.write("🔍 SECURITY FINDINGS\n")
            f.write("="*50 + "\n\n")
            
            for finding in findings:
                f.write(f"[{finding.get('severity', 'UNKNOWN').upper()}] {finding.get('title')}\n")
                f.write(f"Category: {finding.get('category')}\n")
                f.write(f"Description: {finding.get('description')}\n")
                if finding.get('evidence'):
                    f.write(f"Evidence: {finding.get('evidence')}\n")
                if finding.get('recommendation'):
                    f.write(f"Fix: {finding.get('recommendation')}\n")
                f.write("-"*50 + "\n\n")
        
        return output_file
    
    def save_parameters(self, parameters: List[Dict]) -> Path:
        """Save discovered parameters."""
        output_file = self.dirs['parameters'] / 'parameters.json'
        suspicious_file = self.dirs['parameters'] / 'suspicious_parameters.txt'
        
        # Save all parameters
        with open(output_file, 'w') as f:
            f.write(json_dumps(parameters, indent=2))
        
        # Save suspicious parameters
        suspicious = [p for p in parameters if p.get('suspicious') or p.get('risk_indicators')]
        if suspicious:
            with suspicious_file.open('w') as f:
                f.write("⚠️  SUSPICIOUS PARAMETERS\n")
                f.write("="*50 + "\n\n")
                for param in suspicious:
                    f.write(f"Parameter: {param.get('name')}\n")
                    f.write(f"Found in: {len(param.get('endpoints', []))} endpoints\n")
                    if param.get('risk_indicators'):
                        f.write(f"Risks: {', '.join(param['risk_indicators'])}\n")
                    f.write("-"*50 + "\n\n")
        
        return output_file
    
    def save_raw_data(self, attack_surface: Dict) -> Path:
        """Save complete raw attack surface data."""
        output_file = self.dirs['raw'] / 'attack_surface.json'
        
        with open(output_file, 'w') as f:
            f.write(json_dumps(attack_surface, indent=2))
        
        return output_file
    
    def save_scan_state(self, scan_state: Dict) -> Path:
        """Save scan state for resume capability."""
        state_file = self.base_dir / 'scan_state.json'
        
        with open(state_file, 'w') as f:
            f.write(json_dumps(scan_state, indent=2))
        
        return state_file
    
    def load_scan_state(self) -> Dict:
        """Load saved scan state."""
        state_file = self.base_dir / 'scan_state.json'
        
        if state_file.exists():
            with open(state_file, 'r') as f:
                return json_loads(f.read())
        
        return None
    
    def create_summary_report(self, attack_surface: Dict) -> Path:
        """Create a summary report."""
        report_file = self.dirs['reports'] / 'summary.txt'
        
        with report_file.open('w') as f:
            f.write("🦅 hackwithai SCAN SUMMARY\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Target: {attack_surface.get('target_domain')}\n")
            f.write(f"Scan Date: {attack_surface.get('scan_start')}\n")
            f.write(f"Duration: {attack_surface.get('scan_duration', 'N/A')}\n\n")
            
            f.write("📊 STATISTICS\n")
            f.write("-"*60 + "\n")
            f.write(f"Subdomains: {attack_surface.get('total_subdomains', 0)}\n")
            f.write(f"Endpoints: {attack_surface.get('total_endpoints', 0)}\n")
            f.write(f"Parameters: {attack_surface.get('total_parameters', 0)}\n")
            f.write(f"JS Files: {attack_surface.get('total_js_files', 0)}\n")
            f.write(f"Secrets: {attack_surface.get('total_secrets', 0)}\n")
            f.write(f"Findings: {len(attack_surface.get('findings', []))}\n\n")
            
            if attack_surface.get('findings'):
                f.write("🔍 TOP FINDINGS\n")
                f.write("-"*60 + "\n")
                for finding in attack_surface['findings'][:10]:
                    f.write(f"[{finding.get('severity', 'UNKNOWN').upper()}] {finding.get('title')}\n")
                f.write("\n")
            
            f.write(f"Full results available in: {self.base_dir}\n")
        
        return report_file
