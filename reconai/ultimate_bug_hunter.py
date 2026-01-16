"""
ULTIMATE Integrated Bug Hunter - Combines ALL tools for maximum bug discovery.

Integrates:
OLD TOOLS (Enhanced):
- Subfinder + crt.sh + 7 more sources (ultimate subdomain enum)
- httpx (enhanced with fingerprinting)
- katana (enhanced crawling)
- waybackurls (enhanced filtering)
- JSleuth (enhanced JS discovery)
- JS Analyzer (enhanced with bug detection)
- Nuclei (integrated vulnerability scanner)

NEW TOOLS:
- Advanced subdomain enumeration
- Enhanced JS security analyzer  
- Active vulnerability scanner
- Parameter fuzzer

NEVER MISSES A BUG!
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from reconai.models import AttackSurface
from reconai.utils import OutputManager

# Import ALL tools - old and new
from reconai.recon import (
    # Old tools (will be enhanced)
    run_subfinder,
    run_crtsh,
    run_httpx,
    run_katana,
    run_waybackurls,
    run_jsleuth,
    run_jsleuth_enhanced,
    run_jsfetcher,
    analyze_js_files,
    run_nuclei,
    
    # New advanced tools
    scan_endpoints_for_vulnerabilities,
    fuzz_all_parameters,
    analyze_js_for_bugs,
)

from reconai.recon.ultimate_subdomain_enum import run_ultimate_subdomain_enum_sync

logger = logging.getLogger(__name__)


class UltimateBugHunter:
    """
    The ULTIMATE bug hunting orchestrator.
    Combines 15+ tools and techniques for comprehensive bug discovery.
    """
    
    def __init__(self, target_domain: str, output_dir: Optional[Path] = None, aggressive: bool = True):
        self.target_domain = target_domain
        self.output_dir = output_dir or Path(f"./output/{target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.aggressive = aggressive
        self.output_manager = OutputManager(self.output_dir)
        
        self.attack_surface = AttackSurface(
            target_domain=target_domain,
            scan_start=datetime.now()
        )
        
        self.all_bugs = []
        self.stats = {
            'subdomains_found': 0,
            'endpoints_found': 0,
            'js_files_found': 0,
            'secrets_found': 0,
            'bugs_found': 0,
            'critical_bugs': 0,
            'high_bugs': 0,
        }
    
    async def hunt(self, progress_callback=None) -> Dict[str, Any]:
        """
        Execute ULTIMATE bug hunting workflow.
        
        Returns:
            Complete results with all bugs found
        """
        logger.info("="*80)
        logger.info(f"🎯 ULTIMATE BUG HUNTER - {self.target_domain}")
        logger.info("="*80)
        
        # Phase 1: ULTIMATE Subdomain Enumeration (10+ sources)
        await self._phase1_ultimate_subdomain_enum(progress_callback)
        
        # Phase 2: Deep Web Reconnaissance
        await self._phase2_web_recon(progress_callback)
        
        # Phase 3: JavaScript Deep Dive
        await self._phase3_javascript_hunt(progress_callback)
        
        # Phase 4: Active Vulnerability Scanning
        if self.aggressive:
            await self._phase4_active_scanning(progress_callback)
        
        # Phase 5: Parameter Fuzzing
        if self.aggressive:
            await self._phase5_parameter_fuzzing(progress_callback)
        
        # Phase 6: Nuclei Integration
        if self.aggressive:
            await self._phase6_nuclei(progress_callback)
        
        # Phase 7: Bug Correlation & Reporting
        await self._phase7_finalize(progress_callback)
        
        return self._generate_final_report()
    
    async def _phase1_ultimate_subdomain_enum(self, progress_callback):
        """Phase 1: ULTIMATE Subdomain Enumeration (10+ sources combined)."""
        if progress_callback:
            progress_callback(5, "Phase 1: ULTIMATE Subdomain Enumeration", "subdomains")
        
        logger.info("[Phase 1] 🔍 ULTIMATE Subdomain Enumeration")
        logger.info("[*] Combining: Subfinder, crt.sh, HackerTarget, ThreatCrowd, RapidDNS, AlienVault, DNS brute, Zone transfer, Permutations")
        
        loop = asyncio.get_event_loop()
        
        # Run ultimate subdomain enumeration
        subdomains = await loop.run_in_executor(
            None,
            run_ultimate_subdomain_enum_sync,
            self.target_domain,
            self.aggressive
        )
        
        self.attack_surface.subdomains = subdomains
        self.attack_surface.total_subdomains = len(subdomains)
        self.stats['subdomains_found'] = len(subdomains)
        
        logger.info(f"[✅] Found {len(subdomains)} unique subdomains across all sources")
        
        if progress_callback:
            progress_callback(15, f"Found {len(subdomains)} subdomains", "subdomains")
        
        # Save subdomains incrementally
        try:
            self.output_manager.save_subdomains(subdomains)
            logger.info(f"[✓] Saved subdomains to {self.output_dir}/subdomains/")
        except Exception as e:
            logger.error(f"[!] Failed to save subdomains: {e}")
    
    async def _phase2_web_recon(self, progress_callback):
        """Phase 2: Deep Web Reconnaissance with httpx, katana, waybackurls."""
        if progress_callback:
            progress_callback(20, "Phase 2: Web Reconnaissance", "web_recon")
        
        logger.info("[Phase 2] 🌐 Deep Web Reconnaissance")
        
        loop = asyncio.get_event_loop()
        
        # 2.1: HTTP Probing with httpx
        logger.info("[2.1] Running httpx on discovered subdomains...")
        subdomain_hosts = [s['host'] if isinstance(s, dict) else s.host if hasattr(s, 'host') else str(s) 
                          for s in self.attack_surface.subdomains]
        
        alive_endpoints = await loop.run_in_executor(None, run_httpx, subdomain_hosts[:500])
        self.attack_surface.endpoints = alive_endpoints
        self.attack_surface.alive_hosts = len(set(e.url if hasattr(e, 'url') else e.get('url', '') 
                                                   for e in alive_endpoints))
        
        logger.info(f"[✓] httpx found {len(alive_endpoints)} live endpoints")
        
        if progress_callback:
            progress_callback(30, f"Found {len(alive_endpoints)} live endpoints", "httpx")
        
        # 2.2: Web Crawling with katana
        logger.info("[2.2] Running katana web crawler...")
        crawled_urls = []
        crawled_params = []
        
        for endpoint in alive_endpoints[:30]:  # Limit for performance
            url = endpoint.url if hasattr(endpoint, 'url') else endpoint.get('url', str(endpoint))
            try:
                urls, params = await loop.run_in_executor(None, run_katana, url)
                crawled_urls.extend(urls)
                crawled_params.extend(params)
            except Exception as e:
                logger.debug(f"Katana error for {url}: {e}")
        
        self.attack_surface.endpoints.extend(crawled_urls)
        self.attack_surface.parameters = crawled_params
        self.stats['endpoints_found'] = len(self.attack_surface.endpoints)
        
        logger.info(f"[✓] katana found {len(crawled_urls)} additional URLs")
        logger.info(f"[✓] katana found {len(crawled_params)} parameters")
        
        if progress_callback:
            progress_callback(45, f"Crawled {len(crawled_urls)} URLs", "katana")
        
        # 2.3: Wayback URLs
        logger.info("[2.3] Running waybackurls...")
        wayback_endpoints, wayback_params = await loop.run_in_executor(None, run_waybackurls, self.target_domain)
        
        # Filter to exact domain only
        filtered_wayback = [e for e in wayback_endpoints 
                           if self.target_domain in (e.url if hasattr(e, 'url') else e.get('url', ''))]
        
        self.attack_surface.endpoints.extend(filtered_wayback)
        self.attack_surface.parameters.extend(wayback_params)
        
        logger.info(f"[✓] waybackurls found {len(filtered_wayback)} historical URLs")
        
        if progress_callback:
            progress_callback(55, "Web reconnaissance complete", "web_recon")
    
    async def _phase3_javascript_hunt(self, progress_callback):
        """Phase 3: Deep JavaScript Discovery & Analysis."""
        if progress_callback:
            progress_callback(60, "Phase 3: JavaScript Deep Dive", "javascript")
        
        logger.info("[Phase 3] 🔐 JavaScript Deep Dive")
        
        loop = asyncio.get_event_loop()
        
        # 3.1: JS Discovery with ENHANCED JSleuth
        logger.info("[3.1] Discovering JavaScript files with Enhanced JSleuth...")
        logger.info("      ├── Smart Scrolling & Clicking (Lazy Loading)")
        logger.info("      ├── Inline Script Extraction")
        logger.info("      └── Global Variable Inspection")
        
        # Use status-200 URLs for JS discovery
        playwright_targets = []
        for endpoint in self.attack_surface.endpoints[:100]:
            try:
                if getattr(endpoint, 'status_code', 200) == 200:
                    url = endpoint.url if hasattr(endpoint, 'url') else endpoint.get('url', str(endpoint))
                    if url not in playwright_targets:
                        playwright_targets.append(url)
            except:
                pass
        
        # Run Enhanced Discovery
        js_discovery_result = await loop.run_in_executor(None, run_jsleuth_enhanced, playwright_targets[:50])
        
        js_urls = js_discovery_result.get('urls', [])
        inline_scripts = js_discovery_result.get('inline', [])
        globals_data = js_discovery_result.get('globals', {})
        source_maps = js_discovery_result.get('sourcemaps', [])
        
        # Also extract .js URLs from endpoints (fallback)
        for endpoint in self.attack_surface.endpoints:
            url = endpoint.url if hasattr(endpoint, 'url') else endpoint.get('url', str(endpoint))
            if url.endswith('.js') or '.js?' in url:
                if url not in js_urls:
                    js_urls.append(url)
        
        js_urls = list(set(js_urls))
        self.stats['js_files_found'] = len(js_urls)
        
        logger.info(f"[✓] Discovered {len(js_urls)} unique external JavaScript files")
        logger.info(f"[✓] Captured {len(inline_scripts)} inline scripts")
        logger.info(f"[✓] Found {len(source_maps)} source maps")
        
        if progress_callback:
            progress_callback(65, f"Found {len(js_urls)} JS files + {len(inline_scripts)} inline", "js_discovery")
        
        # 3.2: Download JS files & Save Inline Scripts
        logger.info(f"[3.2] Downloading {min(len(js_urls), 200)} JavaScript files...")
        
        # Download external
        js_files = await loop.run_in_executor(None, run_jsfetcher, js_urls[:200])
        
        # Save Inline Scripts to disk so analyzers can read them
        inline_dir = self.output_dir / "js_files" / "inline"
        inline_dir.mkdir(parents=True, exist_ok=True)
        
        for idx, script in enumerate(inline_scripts):
            try:
                # Create a pseudo-filename for the inline script
                content = script.get('content', '')
                source = script.get('source', 'unknown')
                safe_source = re.sub(r'[^a-zA-Z0-9]', '_', source)[:50]
                hash_id = script.get('hash', '')[:8]
                filename = f"inline_{safe_source}_{hash_id}.js"
                file_path = inline_dir / filename
                
                with open(file_path, 'w') as f:
                    f.write(f"// Source: {source}\n// Type: Inline Script\n\n{content}")
                
                # Add to list of files to analyze
                js_files.append(str(file_path))
            except Exception:
                pass
        
        logger.info(f"[✓] Saved {len(inline_scripts)} inline scripts for analysis")
        
        # Save Source Maps info
        try:
            with open(self.output_dir / "js_files" / "sourcemaps.json", "w") as f:
                json.dump(source_maps, f, indent=2)
            with open(self.output_dir / "js_files" / "globals.json", "w") as f:
                json.dump(globals_data, f, indent=2)
        except:
            pass
        
        # Analyze Globals for Secrets IMMEDIATELY
        for source_url, data in globals_data.items():
            data_str = json.dumps(data)
            # Quick secret check on globals
            if re.search(r'(?i)(api[_-]?key|secret|token|password|auth)', data_str):
                self.all_bugs.append({
                    'type': 'Exposed Global Secrets',
                    'severity': 'HIGH',
                    'title': 'Potential Secrets in Global Window Object',
                    'description': f"Found sensitive keywords in window object for {source_url}",
                    'url': source_url,
                    'evidence': data_str[:200] + "...",
                    'method': 'jsleuth_globals',
                    'poc': 'Open DevTools -> Check window objects'
                })
        
        if not js_files:
            logger.warning("[!] No JavaScript files found, skipping JS analysis")
            return
            
        # 3.3: OLD JS Analyzer (secrets, endpoints, links)
        logger.info("[3.3] Running traditional JS analysis (secrets, endpoints)...")
        js_analysis_result = await loop.run_in_executor(None, analyze_js_files, js_files)
        
        secrets = js_analysis_result.get('secrets', [])
        js_endpoints = js_analysis_result.get('endpoints', [])
        
        self.stats['secrets_found'] = len(secrets)
        
        logger.info(f"[✓] Traditional analysis found {len(secrets)} secrets")
        logger.info(f"[✓] Traditional analysis found {len(js_endpoints)} endpoints")
        
        # 3.4: NEW Enhanced JS Security Analysis (real bugs!)
        logger.info("[3.4] Running ENHANCED JS security analysis (finding real bugs)...")
        js_bug_results = await loop.run_in_executor(None, analyze_js_for_bugs, js_files)
        
        js_bugs = js_bug_results.get('bugs', [])
        self.all_bugs.extend(js_bugs)
        
        critical_js = js_bug_results.get('critical_count', 0)
        high_js = js_bug_results.get('high_count', 0)
        
        logger.info(f"[🐛] Enhanced analysis found {len(js_bugs)} JS security bugs!")
        logger.info(f"    ├── CRITICAL: {critical_js}")
        logger.info(f"    └── HIGH: {high_js}")
        
        if progress_callback:
            progress_callback(75, f"Found {len(js_bugs)} JS bugs ({critical_js} critical)", "js_analysis")
    
    async def _phase4_active_scanning(self, progress_callback):
        """Phase 4: Active Vulnerability Scanning."""
        if progress_callback:
            progress_callback(80, "Phase 4: Active Vulnerability Scanning", "vuln_scan")
        
        logger.info("[Phase 4] ⚡ Active Vulnerability Scanning")
        logger.info("[*] Testing: SQLi, XSS, SSRF, Path Traversal, Command Injection, XXE, CORS")
        
        loop = asyncio.get_event_loop()
        
        # Scan endpoints
        endpoints_to_scan = self.attack_surface.endpoints[:100]  # Limit for safety
        
        vuln_results = await loop.run_in_executor(
            None,
            scan_endpoints_for_vulnerabilities,
            endpoints_to_scan
        )
        
        self.all_bugs.extend(vuln_results)
        
        critical_vulns = len([v for v in vuln_results if v.get('severity') == 'CRITICAL'])
        high_vulns = len([v for v in vuln_results if v.get('severity') == 'HIGH'])
        
        logger.info(f"[🐛] Active scanning found {len(vuln_results)} vulnerabilities!")
        logger.info(f"    ├── CRITICAL: {critical_vulns}")
        logger.info(f"    └── HIGH: {high_vulns}")
        
        if progress_callback:
            progress_callback(85, f"Found {len(vuln_results)} vulnerabilities", "vuln_scan")
    
    async def _phase5_parameter_fuzzing(self, progress_callback):
        """Phase 5: Intelligent Parameter Fuzzing."""
        if progress_callback:
            progress_callback(88, "Phase 5: Parameter Fuzzing", "fuzzing")
        
        logger.info("[Phase 5] 🎯 Intelligent Parameter Fuzzing")
        logger.info("[*] Testing: SQL, NoSQL, LDAP, XPath, SSTI, XML injection")
        
        loop = asyncio.get_event_loop()
        
        # Only fuzz endpoints with parameters
        endpoints_with_params = [
            ep for ep in self.attack_surface.endpoints
            if '?' in (ep.url if hasattr(ep, 'url') else ep.get('url', ''))
        ][:50]  # Limit
        
        if endpoints_with_params:
            fuzz_results = await loop.run_in_executor(None, fuzz_all_parameters, endpoints_with_params)
            self.all_bugs.extend(fuzz_results)
            
            logger.info(f"[🐛] Parameter fuzzing found {len(fuzz_results)} injection vulnerabilities!")
        else:
            logger.info("[*] No parameters to fuzz")
        
        if progress_callback:
            progress_callback(92, "Parameter fuzzing complete", "fuzzing")
    
    async def _phase6_nuclei(self, progress_callback):
        """Phase 6: Nuclei Vulnerability Scanner Integration."""
        if progress_callback:
            progress_callback(94, "Phase 6: Nuclei Scanning", "nuclei")
        
        logger.info("[Phase 6] 🔍 Nuclei Vulnerability Scanner")
        
        try:
            from reconai.recon.nuclei import run_nuclei
            
            loop = asyncio.get_event_loop()
            
            # Prepare URLs for Nuclei
            url_list = []
            for endpoint in self.attack_surface.endpoints[:200]:
                url = endpoint.url if hasattr(endpoint, 'url') else endpoint.get('url', str(endpoint))
                if url:
                    url_list.append(url)
            
            if url_list:
                nuclei_result = await loop.run_in_executor(
                    None,
                    run_nuclei,
                    url_list,
                    None,  # templates
                    ['critical', 'high', 'medium']  # severity
                )
                
                if 'findings' in nuclei_result:
                    # Add Nuclei findings to bugs
                    for finding in nuclei_result['findings']:
                        self.all_bugs.append({
                            'type': f"Nuclei: {finding.get('template-id', 'Unknown')}",
                            'severity': finding.get('severity', 'MEDIUM').upper(),
                            'title': finding.get('name', 'Nuclei Finding'),
                            'description': finding.get('description', ''),
                            'url': finding.get('matched-at', ''),
                            'evidence': finding.get('extracted-results', []),
                            'method': 'nuclei',
                            'poc': f"Template: {finding.get('template-id')}",
                        })
                    
                    logger.info(f"[🐛] Nuclei found {len(nuclei_result['findings'])} additional vulnerabilities!")
        except Exception as e:
            logger.debug(f"[!] Nuclei error: {e}")
        
        if progress_callback:
            progress_callback(97, "Nuclei scan complete", "nuclei")
    
    async def _phase7_finalize(self, progress_callback):
        """Phase 7: Bug Correlation, Deduplication, and Reporting."""
        if progress_callback:
            progress_callback(98, "Phase 7: Finalizing Report", "finalize")
        
        logger.info("[Phase 7] 🧠 Bug Correlation & Reporting")
        
        # Deduplicate bugs
        unique_bugs = self._deduplicate_bugs(self.all_bugs)
        self.all_bugs = unique_bugs
        
        # Sort by severity
        self.all_bugs.sort(key=lambda b: {
            'CRITICAL': 0,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3
        }.get(b.get('severity', 'LOW'), 4))
        
        # Update stats
        by_severity = {
            'CRITICAL': [b for b in self.all_bugs if b.get('severity') == 'CRITICAL'],
            'HIGH': [b for b in self.all_bugs if b.get('severity') == 'HIGH'],
            'MEDIUM': [b for b in self.all_bugs if b.get('severity') == 'MEDIUM'],
            'LOW': [b for b in self.all_bugs if b.get('severity') == 'LOW'],
        }
        
        self.stats['bugs_found'] = len(self.all_bugs)
        self.stats['critical_bugs'] = len(by_severity['CRITICAL'])
        self.stats['high_bugs'] = len(by_severity['HIGH'])
        
        # Save bugs
        try:
            bugs_dir = self.output_dir / "ultimate_bugs"
            bugs_dir.mkdir(exist_ok=True)
            
            import json
            with open(bugs_dir / "all_bugs.json", "w") as f:
                json.dump(self.all_bugs, f, indent=2)
            
            with open(bugs_dir / "bugs_by_severity.json", "w") as f:
                json.dump(by_severity, f, indent=2)
            
            logger.info(f"[✓] Saved {len(self.all_bugs)} bugs to {bugs_dir}/")
        except Exception as e:
            logger.error(f"[!] Failed to save bugs: {e}")
        
        logger.info(f"[✅] Deduplicated to {len(self.all_bugs)} unique bugs")
        
        if progress_callback:
            progress_callback(100, "Bug hunt complete!", "complete")
    
    def _deduplicate_bugs(self, bugs: List[Dict]) -> List[Dict]:
        """Remove duplicate bugs."""
        seen = set()
        unique = []
        
        for bug in bugs:
            key = (
                bug.get('type', ''),
                bug.get('url', ''),
                bug.get('parameter', ''),
                bug.get('payload', '')[:50]  # First 50 chars of payload
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(bug)
        
        return unique
    
    def _generate_final_report(self) -> Dict[str, Any]:
        """Generate comprehensive final report."""
        
        by_severity = {
            'CRITICAL': [b for b in self.all_bugs if b.get('severity') == 'CRITICAL'],
            'HIGH': [b for b in self.all_bugs if b.get('severity') == 'HIGH'],
            'MEDIUM': [b for b in self.all_bugs if b.get('severity') == 'MEDIUM'],
            'LOW': [b for b in self.all_bugs if b.get('severity') == 'LOW'],
        }
        
        by_type = {}
        for bug in self.all_bugs:
            bug_type = bug.get('type', 'Unknown')
            if bug_type not in by_type:
                by_type[bug_type] = []
            by_type[bug_type].append(bug)
        
        report = {
            'target_domain': self.target_domain,
            'scan_time': datetime.now().isoformat(),
            'statistics': self.stats,
            'total_bugs': len(self.all_bugs),
            'bugs_by_severity': by_severity,
            'bugs_by_type': by_type,
            'all_bugs': self.all_bugs,
        }
        
        # Print summary
        logger.info("=" * 80)
        logger.info("🎯 ULTIMATE BUG HUNT SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Target: {self.target_domain}")
        logger.info(f"")
        logger.info(f"Reconnaissance:")
        logger.info(f"  ├── Subdomains: {self.stats['subdomains_found']}")
        logger.info(f"  ├── Endpoints: {self.stats['endpoints_found']}")
        logger.info(f"  ├── JS Files: {self.stats['js_files_found']}")
        logger.info(f"  └── Secrets: {self.stats['secrets_found']}")
        logger.info(f"")
        logger.info(f"Bugs Found: {len(self.all_bugs)} TOTAL")
        logger.info(f"  ├── CRITICAL: {len(by_severity['CRITICAL'])}")
        logger.info(f"  ├── HIGH: {len(by_severity['HIGH'])}")
        logger.info(f"  ├── MEDIUM: {len(by_severity['MEDIUM'])}")
        logger.info(f"  └── LOW: {len(by_severity['LOW'])}")
        logger.info("")
        logger.info("Top Bugs by Type:")
        for bug_type, bugs in sorted(by_type.items(), key=lambda x: -len(x[1]))[:10]:
            logger.info(f"  • {bug_type}: {len(bugs)}")
        logger.info("=" * 80)
        
        # Print critical bugs
        if by_severity['CRITICAL']:
            logger.info("")
            logger.info("🚨 CRITICAL BUGS:")
            for idx, bug in enumerate(by_severity['CRITICAL'][:10], 1):
                logger.info(f"{idx}. [{bug.get('type')}] {bug.get('title', bug.get('description', 'Unknown'))}")
                logger.info(f"   URL: {bug.get('url', 'N/A')}")
                logger.info(f"   POC: {bug.get('poc', 'N/A')}")
                logger.info("")
        
        return report


async def run_ultimate_bug_hunt(target_domain: str, aggressive: bool = True, progress_callback=None) -> Dict[str, Any]:
    """
    Main entry point for ULTIMATE bug hunting.
    
    Args:
        target_domain: Target domain to scan
        aggressive: Enable active scanning (default: True)
        progress_callback: Optional callback(progress, message, step)
    
    Returns:
        Complete bug report with all findings
    """
    hunter = UltimateBugHunter(target_domain, aggressive=aggressive)
    return await hunter.hunt(progress_callback)
