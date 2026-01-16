"""Advanced multi-source subdomain enumeration for bug bounty hunting.

Combines multiple techniques:
- DNS brute forcing with smart wordlists
- Certificate transparency logs (crt.sh, censys)
- Search engine scraping
- DNS zone transfers
- Subdomain permutations
- Reverse DNS lookups
"""

import asyncio
import subprocess
import re
import socket
import dns.resolver
import dns.zone
import dns.query
from typing import List, Set, Dict, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger(__name__)


class AdvancedSubdomainEnumerator:
    """Multi-source subdomain discovery for maximum coverage."""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.found_subdomains: Set[str] = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
    def enumerate_all(self, max_workers: int = 50) -> List[str]:
        """Run all enumeration techniques in parallel."""
        logger.info(f"[*] Starting advanced subdomain enumeration for {self.domain}")
        
        # Run all techniques
        techniques = [
            self._crtsh_enum(),
            self._dns_bruteforce(),
            self._zone_transfer(),
            self._permutation_scan(),
            self._reverse_dns_scan(),
            self._search_engine_scrape(),
        ]
        
        # Execute all techniques concurrently
        for technique in techniques:
            try:
                result = technique
                if isinstance(result, list):
                    self.found_subdomains.update(result)
            except Exception as e:
                logger.debug(f"Technique failed: {e}")
        
        # Validate all found subdomains
        validated = self._validate_subdomains(list(self.found_subdomains), max_workers)
        
        logger.info(f"[✓] Found {len(validated)} valid subdomains for {self.domain}")
        return sorted(validated)
    
    def _crtsh_enum(self) -> List[str]:
        """Query crt.sh certificate transparency logs."""
        results = []
        try:
            import requests
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(self.domain) and '*' not in subdomain:
                            results.append(subdomain)
            logger.info(f"[✓] crt.sh found {len(set(results))} subdomains")
        except Exception as e:
            logger.debug(f"crt.sh enum failed: {e}")
        return list(set(results))
    
    def _dns_bruteforce(self, wordlist_size: str = 'medium') -> List[str]:
        """Brute force DNS with smart wordlists."""
        results = []
        
        # Smart wordlist based on common patterns
        if wordlist_size == 'small':
            wordlist = self._get_common_subdomains()[:100]
        elif wordlist_size == 'large':
            wordlist = self._get_common_subdomains()[:5000]
        else:  # medium
            wordlist = self._get_common_subdomains()[:1000]
        
        def check_subdomain(prefix):
            candidate = f"{prefix}.{self.domain}"
            try:
                answers = self.resolver.resolve(candidate, 'A')
                if answers:
                    return candidate
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_subdomain, prefix): prefix for prefix in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        logger.info(f"[✓] DNS bruteforce found {len(results)} subdomains")
        return results
    
    def _get_common_subdomains(self) -> List[str]:
        """Generate smart subdomain wordlist based on bug bounty patterns."""
        common = [
            # Infrastructure
            'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'ssh', 'vpn',
            'remote', 'admin', 'administrator', 'login', 'portal',
            
            # Development & Testing
            'dev', 'development', 'test', 'testing', 'qa', 'uat', 'staging',
            'stage', 'preprod', 'pre-prod', 'demo', 'sandbox', 'beta', 'alpha',
            
            # API & Services
            'api', 'api-v1', 'api-v2', 'api-v3', 'api1', 'api2', 'rest', 'graphql',
            'ws', 'wss', 'websocket', 'service', 'services', 'microservice',
            
            # Databases & Storage
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
            'elasticsearch', 'kibana', 'grafana', 'prometheus',
            
            # Cloud & Infrastructure
            'aws', 'azure', 'gcp', 'cloud', 'cdn', 's3', 'storage', 'backup',
            'jenkins', 'gitlab', 'github', 'bitbucket', 'ci', 'cd',
            
            # Security Red Flags
            'internal', 'corp', 'corporate', 'intranet', 'private',
            'secret', 'secure', 'security', 'auth', 'sso', 'oauth',
            
            # Mobile & Apps
            'mobile', 'app', 'apps', 'android', 'ios', 'm', 'api-mobile',
            
            # Media & Content
            'static', 'assets', 'media', 'images', 'img', 'css', 'js',
            'upload', 'uploads', 'files', 'downloads',
            
            # Monitoring & Analytics
            'monitor', 'monitoring', 'metrics', 'analytics', 'stats',
            'log', 'logs', 'logging', 'sentry', 'datadog',
            
            # Payment & Commerce
            'payment', 'payments', 'pay', 'checkout', 'shop', 'store',
            'cart', 'order', 'orders',
            
            # Support & Docs
            'support', 'help', 'helpdesk', 'docs', 'documentation',
            'wiki', 'kb', 'knowledgebase', 'faq',
            
            # Regional
            'us', 'eu', 'asia', 'uk', 'de', 'fr', 'jp', 'cn', 'in',
            'us-east', 'us-west', 'eu-west', 'ap-southeast',
        ]
        
        return common
    
    def _zone_transfer(self) -> List[str]:
        """Attempt DNS zone transfer (rarely works but worth trying)."""
        results = []
        try:
            ns_records = self.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.domain, timeout=5))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{self.domain}"
                        results.append(subdomain)
                    logger.info(f"[!] Zone transfer successful on {ns}!")
                except:
                    pass
        except Exception as e:
            logger.debug(f"Zone transfer failed: {e}")
        return results
    
    def _permutation_scan(self) -> List[str]:
        """Generate permutations of found subdomains."""
        results = []
        
        # Common prefixes/suffixes for permutations
        mutations = ['dev-', 'test-', 'qa-', 'prod-', 'stage-', 'staging-',
                     '-dev', '-test', '-qa', '-prod', '-staging', '-api',
                     '-1', '-2', '-v1', '-v2', '-new', '-old', '-mobile']
        
        # Base subdomains to mutate
        base_subs = ['www', 'api', 'admin', 'app', 'mobile']
        
        candidates = []
        for base in base_subs:
            for mutation in mutations:
                if mutation.startswith('-'):
                    candidates.append(f"{base}{mutation}")
                else:
                    candidates.append(f"{mutation}{base}")
        
        # Check each candidate
        for candidate in candidates[:100]:  # Limit to avoid noise
            full_domain = f"{candidate}.{self.domain}"
            try:
                answers = self.resolver.resolve(full_domain, 'A')
                if answers:
                    results.append(full_domain)
            except:
                pass
        
        logger.info(f"[✓] Permutation scan found {len(results)} subdomains")
        return results
    
    def _reverse_dns_scan(self) -> List[str]:
        """Perform reverse DNS lookups on found IPs."""
        results = []
        # This would require IPs from existing subdomains
        # Placeholder for now
        return results
    
    def _search_engine_scrape(self) -> List[str]:
        """Scrape search engines for subdomains (Google, Bing)."""
        results = []
        # Placeholder - could use SerpAPI or similar
        # Avoiding aggressive scraping to prevent IP blocks
        return results
    
    def _validate_subdomains(self, subdomains: List[str], max_workers: int = 50) -> List[str]:
        """Validate that subdomains resolve to IPs."""
        valid = []
        
        def validate(subdomain):
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                if answers:
                    return subdomain
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(validate, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    valid.append(result)
        
        return valid


def run_advanced_subdomain_enum(domain: str, techniques: str = 'all') -> List[Dict]:
    """
    Run advanced subdomain enumeration.
    
    Args:
        domain: Target domain
        techniques: 'all', 'passive', or 'active'
    
    Returns:
        List of subdomain dictionaries with metadata
    """
    enumerator = AdvancedSubdomainEnumerator(domain)
    
    if techniques == 'passive':
        # Only passive techniques (crt.sh, search engines)
        subdomains = enumerator._crtsh_enum()
    elif techniques == 'active':
        # Active techniques (DNS brute force, zone transfer)
        subdomains = []
        subdomains.extend(enumerator._dns_bruteforce())
        subdomains.extend(enumerator._zone_transfer())
    else:  # 'all'
        subdomains = enumerator.enumerate_all()
    
    # Format results
    results = []
    for subdomain in set(subdomains):
        results.append({
            'host': subdomain,
            'source': 'advanced_enum',
            'ip': _resolve_ip(subdomain)
        })
    
    return results


def _resolve_ip(domain: str) -> Optional[str]:
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except:
        return None
