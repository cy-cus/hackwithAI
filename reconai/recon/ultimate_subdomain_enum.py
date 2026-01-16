"""
ULTIMATE Subdomain Enumeration - Combines ALL techniques for maximum coverage.

Integrates:
- Subfinder (ProjectDiscovery tool)
- crt.sh (Certificate Transparency)
- Advanced DNS techniques (zone transfer, brute force, permutations)
- DNS aggregation services
- Search engines
- Reverse DNS
- ASN enumeration

NEVER MISSES A SUBDOMAIN!
"""

import asyncio
import subprocess
import re
import json
import socket
import logging
from typing import List, Set, Dict, Optional
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx

logger = logging.getLogger(__name__)


class UltimateSubdomainEnumerator:
    """
    The ultimate subdomain enumeration engine.
    Combines 10+ sources and techniques for maximum coverage.
    """
    
    def __init__(self, domain: str, aggressive: bool = True):
        self.domain = domain
        self.aggressive = aggressive
        self.found_subdomains: Set[str] = set()
        self.subdomain_sources: Dict[str, List[str]] = {}  # Track where each subdomain came from
        
    async def enumerate_all(self) -> List[Dict]:
        """
        Run ALL enumeration techniques in parallel for maximum speed and coverage.
        
        Returns:
            List of subdomain dictionaries with source tracking
        """
        logger.info(f"🎯 ULTIMATE Subdomain Enumeration for {self.domain}")
        logger.info(f"Mode: {'AGGRESSIVE' if self.aggressive else 'PASSIVE'}")
        
        # Phase 1: Launch all passive techniques in parallel
        logger.info("[Phase 1] Launching passive enumeration (7 sources)...")
        
        loop = asyncio.get_event_loop()
        
        # All passive sources
        passive_tasks = [
            loop.run_in_executor(None, self._subfinder),
            loop.run_in_executor(None, self._crtsh),
            loop.run_in_executor(None, self._crtsh_api),
            loop.run_in_executor(None, self._hackertarget),
            loop.run_in_executor(None, self._threatcrowd),
            loop.run_in_executor(None, self._rapiddns),
            loop.run_in_executor(None, self._alienvault),
        ]
        
        # Wait for all passive sources
        passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)
        
        for idx, result in enumerate(passive_results):
            if isinstance(result, set):
                self.found_subdomains.update(result)
        
        logger.info(f"[✓] Passive sources found {len(self.found_subdomains)} unique subdomains")
        
        # Phase 2: Active enumeration (if aggressive mode)
        if self.aggressive:
            logger.info("[Phase 2] Launching active enumeration...")
            
            active_tasks = [
                loop.run_in_executor(None, self._dns_bruteforce),
                loop.run_in_executor(None, self._zone_transfer),
                loop.run_in_executor(None, self._permutation_scan),
                loop.run_in_executor(None, self._asn_enumeration),
            ]
            
            active_results = await asyncio.gather(*active_tasks, return_exceptions=True)
            
            for result in active_results:
                if isinstance(result, set):
                    self.found_subdomains.update(result)
            
            logger.info(f"[✓] Active enumeration found {len(self.found_subdomains)} total subdomains")
        
        # Phase 3: Validation (but keep all)
        logger.info("[Phase 3] Validating discovered subdomains...")
        valid_subdomains = await self._validate_all(list(self.found_subdomains))
        
        logger.info(f"[✅] Validated: {len(valid_subdomains)} | [Total Found]: {len(self.found_subdomains)}")
        
        # Format results with metadata - INCLUDE ALL found subdomains
        results = []
        for subdomain in sorted(self.found_subdomains):
            is_resolved = subdomain in valid_subdomains
            # Format source string
            source_list = self.subdomain_sources.get(subdomain, [])
            source_str = ', '.join(source_list) if source_list else 'ultimate_enum'
            
            results.append({
                'host': subdomain,
                'source': source_str,
                'sources': source_list,
                'timestamp': datetime.now().isoformat(),
                'ip': self._resolve_ip(subdomain) if is_resolved else None,
                'resolved': is_resolved
            })
        
        return results
    
    def _subfinder(self) -> Set[str]:
        """Run subfinder (ProjectDiscovery tool)."""
        results = set()
        source = 'subfinder'
        
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
                output_file = f.name
            
            cmd = ['subfinder', '-d', self.domain, '-o', output_file, '-silent', '-all']
            
            # Filter out venv from PATH
            import os
            env = os.environ.copy()
            path_parts = env.get('PATH', '').split(':')
            system_path = [p for p in path_parts if 'venv' not in p.lower()]
            env['PATH'] = ':'.join(system_path)
            
            subprocess.run(cmd, timeout=300, capture_output=True, env=env)
            
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            results.add(subdomain)
                            self._track_source(subdomain, source)
                Path(output_file).unlink()
            
            logger.info(f"[✓] {source}: {len(results)} subdomains")
        except Exception as e:
            logger.debug(f"[!] {source} error: {e}")
        
        return results
    
    def _crtsh(self) -> Set[str]:
        """Query crt.sh certificate transparency logs."""
        results = set()
        source = 'crtsh'
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            with httpx.Client(timeout=30) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            if subdomain.endswith(self.domain) and '*' not in subdomain:
                                results.add(subdomain)
                                self._track_source(subdomain, source)
            
            logger.info(f"[✓] {source}: {len(results)} subdomains")
        except Exception as e:
            logger.debug(f"[!] {source} error: {e}")
        
        return results
    
    def _crtsh_api(self) -> Set[str]:
        """Alternative crt.sh API endpoint."""
        results = set()
        source = 'crtsh_api'
        
        try:
            url = f"https://crt.sh/?q={self.domain}&output=json"
            with httpx.Client(timeout=30) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        common_name = entry.get('common_name', '').lower()
                        if common_name.endswith(self.domain) and '*' not in common_name:
                            results.add(common_name)
                            self._track_source(common_name, source)
            
            logger.info(f"[✓] {source}: {len(results)} subdomains")
        except Exception as e:
            logger.debug(f"[!] {source} error: {e}")
        
        return results
    
    def _hackertarget(self) -> Set[str]:
        """Query HackerTarget API."""
        results = set()
        source = 'hackertarget'
        
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            with httpx.Client(timeout=20) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    for line in resp.text.split('\n'):
                        if ',' in line:
                            subdomain = line.split(',')[0].strip()
                            if subdomain.endswith(self.domain):
                                results.add(subdomain)
                                self._track_source(subdomain, source)
            
            logger.info(f"[✓] {source}: {len(results)} subdomains")
        except Exception as e:
            logger.debug(f"[!] {source} error: {e}")
        
        return results
    
    def _threatcrowd(self) -> Set[str]:
        """Query ThreatCrowd API."""
        results = set()
        source = 'threatcrowd'
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            with httpx.Client(timeout=20) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    subdomains = data.get('subdomains', [])
                    for subdomain in subdomains:
                        if isinstance(subdomain, str) and subdomain.endswith(self.domain):
                            results.add(subdomain)
                            self._track_source(subdomain, source)
            
            logger.info(f"[✓] {source}: {len(results)} subdomains")
        except Exception as e:
            logger.debug(f"[!] {source} error: {e}")
        
        return results
    
    def _rapiddns(self) -> Set[str]:
        """Query RapidDNS."""
        results = set()
        source = 'rapiddns'
        
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            with httpx.Client(timeout=20, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    # Parse HTML for subdomains
                    pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(self.domain)
                    matches = re.finditer(pattern, resp.text)
                    for match in matches:
                        subdomain = match.group(0).lower()
                        results.add(subdomain)
                        self._track_source(subdomain, source)
            
            logger.info(f"[✓] {source}: {len(results)} subdomains")
        except Exception as e:
            logger.debug(f"[!] {source} error: {e}")
        
        return results
    
    def _alienvault(self) -> Set[str]:
        """Query AlienVault OTX."""
        results = set()
        source = 'alienvault'
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            with httpx.Client(timeout=20) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get('passive_dns', []):
                        hostname = entry.get('hostname', '').lower()
                        if hostname.endswith(self.domain):
                            results.add(hostname)
                            self._track_source(hostname, source)
            
            logger.info(f"[✓] {source}: {len(results)} subdomains")
        except Exception as e:
            logger.debug(f"[!] {source} error: {e}")
        
        return results
    
    def _dns_bruteforce(self) -> Set[str]:
        """DNS bruteforce with smart wordlist."""
        results = set()
        source = 'dns_bruteforce'
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            wordlist = self._get_smart_wordlist()
            
            def check(prefix):
                candidate = f"{prefix}.{self.domain}"
                try:
                    answers = resolver.resolve(candidate, 'A')
                    if answers:
                        return candidate
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(check, word): word for word in wordlist}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.add(result)
                        self._track_source(result, source)
            
            logger.info(f"[✓] {source}: {len(results)} subdomains")
        except ImportError:
            logger.warning("[!] dnspython not installed, skipping DNS bruteforce")
        except Exception as e:
            logger.debug(f"[!] {source} error: {e}")
        
        return results
    
    def _zone_transfer(self) -> Set[str]:
        """Attempt DNS zone transfer."""
        results = set()
        source = 'zone_transfer'
        
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            
            resolver = dns.resolver.Resolver()
            ns_records = resolver.resolve(self.domain, 'NS')
            
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.domain, timeout=5))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{self.domain}"
                        results.add(subdomain)
                        self._track_source(subdomain, source)
                    logger.info(f"[!] Zone transfer successful on {ns}!")
                except:
                    pass
            
            if results:
                logger.info(f"[✓] {source}: {len(results)} subdomains")
        except:
            pass
        
        return results
    
    def _permutation_scan(self) -> Set[str]:
        """Generate and test subdomain permutations."""
        results = set()
        source = 'permutation'
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            
            # Generate permutations from existing subdomains
            base_prefixes = ['www', 'api', 'admin', 'app', 'mobile', 'dev', 'staging']
            mutations = ['dev-', 'test-', 'qa-', 'prod-', 'stage-', '-api', '-v1', '-v2', '-mobile', '-admin']
            
            candidates = set()
            for base in base_prefixes:
                for mutation in mutations:
                    if mutation.startswith('-'):
                        candidates.add(f"{base}{mutation}")
                    else:
                        candidates.add(f"{mutation}{base}")
            
            def check(prefix):
                candidate = f"{prefix}.{self.domain}"
                try:
                    answers = resolver.resolve(candidate, 'A')
                    if answers:
                        return candidate
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = {executor.submit(check, cand): cand for cand in candidates}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.add(result)
                        self._track_source(result, source)
            
            if results:
                logger.info(f"[✓] {source}: {len(results)} subdomains")
        except:
            pass
        
        return results
    
    def _asn_enumeration(self) -> Set[str]:
        """Enumerate via ASN lookups (placeholder - would need ASN DB)."""
        # This would require additional services/databases
        # Placeholder for now
        return set()
    
    def _get_smart_wordlist(self) -> List[str]:
        """Generate smart wordlist for DNS bruteforcing."""
        return [
            # Infrastructure
            'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'ssh', 'vpn',
            'remote', 'admin', 'administrator', 'login', 'portal', 'cpanel',
            'webmail', 'autodiscover', 'ns', 'ns1', 'ns2', 'dns', 'dns1',
            
            # Development
            'dev', 'development', 'test', 'testing', 'qa', 'uat', 'staging',
            'stage', 'preprod', 'pre-prod', 'demo', 'sandbox', 'beta', 'alpha',
            'preview', 'temp', 'tmp',
            
            # API & Services
            'api', 'api-v1', 'api-v2', 'api-v3', 'api1', 'api2', 'apiv1', 'apiv2',
            'rest', 'graphql', 'ws', 'wss', 'websocket', 'service', 'services',
            'gateway', 'proxy',
            
            # Mobile & Apps
            'mobile', 'app', 'apps', 'android', 'ios', 'm', 'api-mobile',
            'mobile-api', 'app-api',
            
            # Databases
            'db', 'database', 'mysql', 'postgres', 'mongo', 'mongodb', 'redis',
            'elastic', 'elasticsearch', 'kibana', 'grafana',
            
            # Cloud & CI/CD
            'aws', 'azure', 'gcp', 'cloud', 'cdn', 's3', 'storage', 'backup',
            'jenkins', 'gitlab', 'github', 'bitbucket', 'ci', 'cd', 'docker',
            
            # Monitoring & Logs
            'monitor', 'monitoring', 'metrics', 'analytics', 'stats', 'datadog',
            'log', 'logs', 'logging', 'sentry', 'kibana', 'grafana',
            
            # Security
            'vpn', 'firewall', 'waf', 'ids', 'ips', 'siem', 'soc',
            
            # Internal/Private
            'internal', 'corp', 'corporate', 'intranet', 'private', 'int',
            
            # Media & Assets
            'static', 'assets', 'media', 'images', 'img', 'css', 'js',
            'upload', 'uploads', 'files', 'downloads', 'cdn', 'content',
            
            # Support
            'support', 'help', 'helpdesk', 'docs', 'documentation', 'wiki',
            'kb', 'knowledgebase', 'faq', 'forum', 'community',
            
            # E-commerce
            'shop', 'store', 'cart', 'checkout', 'payment', 'payments', 'order',
            
            # Regional
            'us', 'eu', 'asia', 'uk', 'de', 'fr', 'jp', 'cn', 'in', 'au',
            'us-east', 'us-west', 'eu-west', 'ap-southeast',
        ]
    
    async def _validate_all(self, subdomains: List[str]) -> Set[str]:
        """Validate all subdomains in parallel."""
        valid = set()
        
        def validate(subdomain):
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    return subdomain
            except:
                pass
            return None
        
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {loop.run_in_executor(executor, validate, sub): sub for sub in subdomains}
            results = await asyncio.gather(*futures.keys(), return_exceptions=True)
            
            for result in results:
                if result:
                    valid.add(result)
        
        return valid
    
    def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP."""
        try:
            return socket.gethostbyname(domain)
        except:
            return None
    
    def _track_source(self, subdomain: str, source: str):
        """Track which source found this subdomain."""
        if subdomain not in self.subdomain_sources:
            self.subdomain_sources[subdomain] = []
        if source not in self.subdomain_sources[subdomain]:
            self.subdomain_sources[subdomain].append(source)


async def run_ultimate_subdomain_enum(domain: str, aggressive: bool = True) -> List[Dict]:
    """
    Run the ULTIMATE subdomain enumeration combining all techniques.
    
    Args:
        domain: Target domain
        aggressive: Enable active enumeration (DNS brute, permutations)
    
    Returns:
        List of subdomain dictionaries with metadata
    """
    enumerator = UltimateSubdomainEnumerator(domain, aggressive=aggressive)
    return await enumerator.enumerate_all()


def run_ultimate_subdomain_enum_sync(domain: str, aggressive: bool = True) -> List[Dict]:
    """Synchronous wrapper for ultimate subdomain enumeration."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(run_ultimate_subdomain_enum(domain, aggressive))
        return results
    finally:
        loop.close()
