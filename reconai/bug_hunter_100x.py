"""
100X Bug Bounty Hunter - Comprehensive Integration Module

Orchestrates all reconnaissance and vulnerability detection tools to find REAL bugs:
1. Advanced subdomain enumeration (multi-source)
2. Deep JavaScript analysis (authentication flaws, secrets)
3. Active vulnerability scanning (SQLi, XSS, SSRF, etc.)
4. Parameter fuzzing (injection attacks)
5. Real-time bug correlation and prioritization
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from reconai.models import AttackSurface, Finding
from reconai.recon import (
    run_subfinder,
    run_advanced_subdomain_enum,
    run_httpx,
    run_katana,
    run_waybackurls,
    run_jsfetcher,
    analyze_js_for_bugs,
    scan_endpoints_for_vulnerabilities,
    fuzz_all_parameters,
)
from reconai.llm import OllamaBackend
from reconai.utils import OutputManager

logger = logging.getLogger(__name__)


class BugHunter100X:
    """
    100X Bug Bounty Hunter - Finds REAL exploitable vulnerabilities.
    
    This orchestrator combines multiple techniques:
    - Multi-source subdomain discovery
    - Deep JS security analysis
    - Active vulnerability scanning  
    - Intelligent parameter fuzzing
    - Bug correlation and prioritization
    """
    
    def __init__(self, target_domain: str, output_dir: Optional[Path] = None,
                 aggressive_mode: bool = True, config: Optional[Dict] = None):
        """
        Initialize Bug Hunter.
        
        Args:
            target_domain: Target domain to scan
            output_dir: Output directory for results
            aggressive_mode: Enable active scanning
            config: Dictionary containing scan limits and configuration
        """
        self.target_domain = target_domain
        self.output_dir = output_dir or Path(f"./output/{target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.aggressive_mode = aggressive_mode
        self.output_manager = OutputManager(self.output_dir)
        
        # Load configuration limits (with defaults)
        self.config = config or {}
        
        # 0 or negative means UNLIMITED (None in slicing)
        limit_js_val = int(self.config.get('limit_js', 2000))
        self.limit_js = limit_js_val if limit_js_val > 0 else None
        
        limit_vuln_val = int(self.config.get('limit_vuln', 500))
        self.limit_vuln = limit_vuln_val if limit_vuln_val > 0 else None
        
        limit_fuzz_val = int(self.config.get('limit_fuzz', 200))
        self.limit_fuzz = limit_fuzz_val if limit_fuzz_val > 0 else None
        
        logger.info(f"🔧 Scan Configuration: JS Limit={self.limit_js or 'ALL'}, Vuln Limit={self.limit_vuln or 'ALL'}, Fuzz Limit={self.limit_fuzz or 'ALL'}")
        
        self.bugs_found = []
        self.attack_surface = AttackSurface(
            target_domain=target_domain,
            scan_start=datetime.now()
        )
    
    async def hunt(self, progress_callback=None) -> Dict[str, Any]:
        """
        Execute comprehensive bug hunting workflow.
        
        Returns:
            Dictionary with all bugs found, categorized by severity and type
        """
        logger.info(f"🎯 Starting 100X Bug Hunt for {self.target_domain}")
        
        # Phase 1: Reconnaissance (Passive & Active)
        await self._phase1_reconnaissance(progress_callback)
        
        # Phase 2: Deep JavaScript Analysis
        await self._phase2_javascript_analysis(progress_callback)
        
        # Phase 3: Active Vulnerability Scanning
        if self.aggressive_mode:
            await self._phase3_active_scanning(progress_callback)
        
        # Phase 4: Parameter Fuzzing
        if self.aggressive_mode:
            await self._phase4_parameter_fuzzing(progress_callback)
        
        # Phase 5: Bug Correlation and Prioritization
        await self._phase5_bug_correlation(progress_callback)
        
        # Generate final report
        return self._generate_bug_report()
    
    async def _phase1_reconnaissance(self, progress_callback):
        """Phase 1: Multi-source subdomain enumeration and endpoint discovery."""
        if progress_callback:
            progress_callback(5, "Phase 1: Advanced Reconnaissance", "recon")
        
        logger.info("[Phase 1] 🔍 Advanced Reconnaissance")
        
        # 1.1: Advanced multi-source subdomain enumeration
        if progress_callback:
            progress_callback(10, "Enumerating subdomains (multi-source)", "subdomains")
        
        logger.info("[1.1] Running advanced subdomain enumeration...")
        
        # Combine traditional subfinder with advanced techniques
        loop = asyncio.get_event_loop()
        
        # Run both in parallel
        traditional_subs = await loop.run_in_executor(None, run_subfinder, self.target_domain)
        advanced_subs = await loop.run_in_executor(None, run_advanced_subdomain_enum, self.target_domain, 'all')
        
        # Merge results
        all_subdomains = traditional_subs + advanced_subs
        unique_hosts = {sub['host'] if isinstance(sub, dict) else sub.host if hasattr(sub, 'host') else str(sub) 
                       for sub in all_subdomains}
        
        self.attack_surface.subdomains = [{'host': h, 'source': 'merged'} for h in unique_hosts]
        self.attack_surface.total_subdomains = len(unique_hosts)
        
        logger.info(f"[✓] Found {len(unique_hosts)} unique subdomains")
        
        if progress_callback:
            progress_callback(20, f"Found {len(unique_hosts)} subdomains", "subdomains")
        
        # 1.2: HTTP probing with httpx
        logger.info("[1.2] Probing for live hosts...")
        subdomain_list = list(unique_hosts)
        alive_endpoints = await loop.run_in_executor(None, run_httpx, subdomain_list)  # NO LIMIT
        
        self.attack_surface.endpoints = alive_endpoints
        self.attack_surface.total_urls = len(alive_endpoints)
        
        logger.info(f"[✓] Found {len(alive_endpoints)} live endpoints")
        
        if progress_callback:
            progress_callback(35, f"Found {len(alive_endpoints)} live endpoints", "endpoints")
        
        # 1.3: Web crawling with katana
        logger.info("[1.3] Crawling for URLs and parameters...")
        crawled_urls = []
        crawled_params = []
        
        for endpoint in alive_endpoints[:50]:  # Limit crawl targets
            url = endpoint.url if hasattr(endpoint, 'url') else endpoint.get('url', str(endpoint))
            try:
                urls, params = await loop.run_in_executor(None, run_katana, url)
                crawled_urls.extend(urls)
                crawled_params.extend(params)
            except Exception as e:
                logger.debug(f"Katana error for {url}: {e}")
        
        self.attack_surface.endpoints.extend(crawled_urls)
        self.attack_surface.parameters = crawled_params
        self.attack_surface.total_parameters = len(crawled_params)
        
        logger.info(f"[✓] Crawled {len(crawled_urls)} additional URLs")
        logger.info(f"[✓] Found {len(crawled_params)} parameters")
        
        if progress_callback:
            progress_callback(50, "Reconnaissance complete", "recon")
    
    async def _phase2_javascript_analysis(self, progress_callback):
        """Phase 2: Deep JavaScript security analysis for bugs."""
        if progress_callback:
            progress_callback(55, "Phase 2: Deep JavaScript Analysis", "js_analysis")
        
        logger.info("[Phase 2] 🔐 Deep JavaScript Security Analysis")
        
        # 2.1: Collect all JavaScript files
        logger.info("[2.1] Collecting JavaScript files...")
        js_urls = set()
        
        # Extract from endpoints
        for endpoint in self.attack_surface.endpoints:
            url = endpoint.url if hasattr(endpoint, 'url') else endpoint.get('url', str(endpoint))
            if url.endswith('.js') or '.js?' in url:
                js_urls.add(url)
        
        logger.info(f"[✓] Found {len(js_urls)} JavaScript URLs")
        
        if not js_urls:
            logger.warning("[!] No JavaScript files found. Skipping JS analysis.")
            return
        
        # 2.2: Download JavaScript content
        if progress_callback:
            progress_callback(60, f"Downloading {len(js_urls)} JS files", "js_download")
        
        logger.info(f"[2.2] Downloading {len(js_urls)} JavaScript files...")
        loop = asyncio.get_event_loop()
        
        # Limit to prevent overwhelming the system (Configurable)
        js_files = await loop.run_in_executor(None, run_jsfetcher, list(js_urls)[:self.limit_js])
        
        logger.info(f"[✓] Downloaded {len(js_files)} JavaScript files")
        
        # 2.3: Analyze for security bugs
        if progress_callback:
            progress_callback(70, "Analyzing JS for security bugs", "js_bugs")
        
        logger.info("[2.3] Analyzing JavaScript for security bugs...")
        js_bug_results = await loop.run_in_executor(None, analyze_js_for_bugs, js_files)
        
        # Extract bugs
        js_bugs = js_bug_results.get('bugs', [])
        self.bugs_found.extend(js_bugs)
        
        critical_js_bugs = js_bug_results.get('critical_count', 0)
        high_js_bugs = js_bug_results.get('high_count', 0)
        
        logger.info(f"[🐛] Found {len(js_bugs)} JS bugs ({critical_js_bugs} critical, {high_js_bugs} high)")
        
        if progress_callback:
            progress_callback(75, f"Found {len(js_bugs)} JS bugs", "js_analysis")
    
    async def _phase3_active_scanning(self, progress_callback):
        """Phase 3: Active vulnerability scanning."""
        if progress_callback:
            progress_callback(80, "Phase 3: Active Vulnerability Scanning", "vuln_scan")
        
        logger.info("[Phase 3] ⚡ Active Vulnerability Scanning")
        
        # Only scan alive endpoints (Configurable limit)
        endpoints_to_scan = self.attack_surface.endpoints[:self.limit_vuln]
        
        logger.info(f"[3.1] Scanning {len(endpoints_to_scan)} endpoints for vulnerabilities...")
        logger.info("[*] Testing: SQLi, XSS, SSRF, Path Traversal, Command Injection, XXE, CORS")
        
        loop = asyncio.get_event_loop()
        vuln_results = await loop.run_in_executor(
            None, 
            scan_endpoints_for_vulnerabilities, 
            endpoints_to_scan
        )
        
        self.bugs_found.extend(vuln_results)
        
        critical_vulns = len([v for v in vuln_results if v.get('severity') == 'CRITICAL'])
        high_vulns = len([v for v in vuln_results if v.get('severity') == 'HIGH'])
        
        logger.info(f"[🐛] Found {len(vuln_results)} vulnerabilities ({critical_vulns} critical, {high_vulns} high)")
        
        if progress_callback:
            progress_callback(85, f"Found {len(vuln_results)} vulnerabilities", "vuln_scan")
    
    async def _phase4_parameter_fuzzing(self, progress_callback):
        """Phase 4: Intelligent parameter fuzzing."""
        if progress_callback:
            progress_callback(90, "Phase 4: Parameter Fuzzing", "fuzzing")
        
        logger.info("[Phase 4] 🎯 Intelligent Parameter Fuzzing")
        
        # Only fuzz endpoints with parameters
        endpoints_with_params = [
            ep for ep in self.attack_surface.endpoints 
            if '?' in (ep.url if hasattr(ep, 'url') else ep.get('url', ''))
            if '?' in (ep.url if hasattr(ep, 'url') else ep.get('url', ''))
        ][:self.limit_fuzz]  # Limit (Configurable)
        
        logger.info(f"[4.1] Fuzzing {len(endpoints_with_params)} endpoints with parameters...")
        logger.info("[*] Testing: SQLi, NoSQL, LDAP, XPath, SSTI, XML injection")
        
        loop = asyncio.get_event_loop()
        fuzz_results = await loop.run_in_executor(None, fuzz_all_parameters, endpoints_with_params)
        
        self.bugs_found.extend(fuzz_results)
        
        logger.info(f"[🐛] Found {len(fuzz_results)} injection vulnerabilities via fuzzing")
        
        if progress_callback:
            progress_callback(95, f"Found {len(fuzz_results)} injection bugs", "fuzzing")
    
    async def _phase5_bug_correlation(self, progress_callback):
        """Phase 5: Correlate and prioritize bugs."""
        if progress_callback:
            progress_callback(98, "Phase 5: Bug Correlation", "correlation")
        
        logger.info("[Phase 5] 🧠 Bug Correlation and Prioritization")
        
        # Deduplicate bugs
        unique_bugs = self._deduplicate_bugs(self.bugs_found)
        self.bugs_found = unique_bugs
        
        # Prioritize by severity and exploitability
        self.bugs_found.sort(key=lambda b: (
            {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(b.get('severity', 'LOW'), 4),
            -len(b.get('evidence', ''))
        ))
        
        logger.info(f"[✓] Deduplicated to {len(self.bugs_found)} unique bugs")
        
        # Save bugs to disk
        self.output_manager.save_raw_file('bugs.json', self.bugs_found)
        
        if progress_callback:
            progress_callback(100, "Bug hunt complete!", "complete")
    
    def _deduplicate_bugs(self, bugs: List[Dict]) -> List[Dict]:
        """Remove duplicate bug findings."""
        seen = set()
        unique = []
        
        for bug in bugs:
            # Create unique key from type, URL, and parameter
            key = (
                bug.get('type', ''),
                bug.get('url', ''),
                bug.get('parameter', ''),
                bug.get('payload', '')
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(bug)
        
        return unique
    
    def _generate_bug_report(self) -> Dict[str, Any]:
        """Generate comprehensive bug report."""
        
        # Categorize by severity
        by_severity = {
            'CRITICAL': [b for b in self.bugs_found if b.get('severity') == 'CRITICAL'],
            'HIGH': [b for b in self.bugs_found if b.get('severity') == 'HIGH'],
            'MEDIUM': [b for b in self.bugs_found if b.get('severity') == 'MEDIUM'],
            'LOW': [b for b in self.bugs_found if b.get('severity') == 'LOW'],
        }
        
        # Categorize by type
        by_type = {}
        for bug in self.bugs_found:
            bug_type = bug.get('type', 'Unknown')
            if bug_type not in by_type:
                by_type[bug_type] = []
            by_type[bug_type].append(bug)
        
        # Identify high-impact bugs
        high_impact_bugs = [
            b for b in self.bugs_found 
            if b.get('severity') in ['CRITICAL', 'HIGH']
        ]
        
        report = {
            'target_domain': self.target_domain,
            'scan_time': datetime.now().isoformat(),
            'total_bugs': len(self.bugs_found),
            'critical_bugs': len(by_severity['CRITICAL']),
            'high_bugs': len(by_severity['HIGH']),
            'medium_bugs': len(by_severity['MEDIUM']),
            'low_bugs': len(by_severity['LOW']),
            'bugs_by_severity': by_severity,
            'bugs_by_type': by_type,
            'high_impact_bugs': high_impact_bugs,
            'attack_surface': {
                'subdomains': self.attack_surface.total_subdomains,
                'endpoints': self.attack_surface.total_urls,
                'parameters': self.attack_surface.total_parameters,
            },
            'all_bugs': self.bugs_found
        }
        
        # Save report
        self.output_manager.save_raw_file('bug_report.json', report)
        
        # Generate summary
        logger.info("=" * 80)
        logger.info("🎯 BUG HUNT SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Target: {self.target_domain}")
        logger.info(f"Total Bugs Found: {len(self.bugs_found)}")
        logger.info(f"  ├── CRITICAL: {len(by_severity['CRITICAL'])}")
        logger.info(f"  ├── HIGH:     {len(by_severity['HIGH'])}")
        logger.info(f"  ├── MEDIUM:   {len(by_severity['MEDIUM'])}")
        logger.info(f"  └── LOW:      {len(by_severity['LOW'])}")
        logger.info("")
        logger.info("Top Vulnerabilities by Type:")
        for bug_type, bugs in sorted(by_type.items(), key=lambda x: -len(x[1]))[:10]:
            logger.info(f"  • {bug_type}: {len(bugs)} findings")
        logger.info("=" * 80)
        
        # Print critical bugs
        if by_severity['CRITICAL']:
            logger.info("")
            logger.info("🚨 CRITICAL BUGS (IMMEDIATE ACTION REQUIRED):")
            for idx, bug in enumerate(by_severity['CRITICAL'][:5], 1):
                logger.info(f"{idx}. [{bug.get('type')}] {bug.get('title', bug.get('description', 'Unknown'))}")
                logger.info(f"   URL: {bug.get('url', 'N/A')}")
                logger.info(f"   POC: {bug.get('poc', 'N/A')}")
                logger.info("")
        
        return report


async def hunt_bugs_100x(target_domain: str, aggressive: bool = True,
                         progress_callback=None, config: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main entry point for 100X bug hunting.
    
    Args:
        target_domain: Target domain to scan
        aggressive: Enable active scanning (default: True)
        progress_callback: Optional callback(progress, message, step)
        config: Scan configuration limits
    
    Returns:
        Complete bug report
    """
    hunter = BugHunter100X(target_domain, aggressive_mode=aggressive, config=config)
    return await hunter.hunt(progress_callback)
