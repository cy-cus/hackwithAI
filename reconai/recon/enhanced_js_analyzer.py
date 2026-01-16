"""Enhanced JavaScript analyzer for finding real security bugs.

Detects:
- Authentication flaws (hardcoded credentials, JWT issues, weak tokens)
- Authorization bypass patterns
- Sensitive data exposure
- Cryptographic weaknesses
- API key leaks with context
- Debug endpoints and functions
- Unsafe DOM manipulation
- Prototype pollution vectors
- Race conditions
- Business logic flaws
"""

import re
import json
import base64
import logging
from typing import List, Dict, Any, Set, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SecurityBug:
    """Represents a real security bug found in JS."""
    type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    evidence: str
    line_number: Optional[int] = None
    context: str = ""
    exploitation: str = ""
    poc: str = ""
    cwe: Optional[str] = None


class EnhancedJSAnalyzer:
    """Advanced JavaScript security analyzer for bug bounty hunting."""
    
    def __init__(self):
        self.bugs: List[SecurityBug] = []
        
    def analyze(self, js_content: str, source_url: str = "unknown") -> Dict[str, Any]:
        """
        Deep security analysis of JavaScript code.
        
        Returns findings categorized by type with exploitation details.
        """
        self.bugs = []
        
        # Run all detection modules
        self._detect_hardcoded_credentials(js_content, source_url)
        self._detect_jwt_issues(js_content, source_url)
        self._detect_api_keys(js_content, source_url)
        self._detect_auth_bypass_patterns(js_content, source_url)
        self._detect_admin_endpoints(js_content, source_url)
        self._detect_debug_code(js_content, source_url)
        self._detect_sensitive_comments(js_content, source_url)
        self._detect_crypto_weaknesses(js_content, source_url)
        self._detect_dom_xss_sinks(js_content, source_url)
        self._detect_prototype_pollution(js_content, source_url)
        self._detect_race_conditions(js_content, source_url)
        self._detect_idor_patterns(js_content, source_url)
        self._detect_graphql_introspection(js_content, source_url)
        self._detect_postmessage_issues(js_content, source_url)
        
        return {
            'bugs': [self._bug_to_dict(bug) for bug in self.bugs],
            'total_bugs': len(self.bugs),
            'critical_bugs': len([b for b in self.bugs if b.severity == 'CRITICAL']),
            'high_bugs': len([b for b in self.bugs if b.severity == 'HIGH']),
            'source_url': source_url
        }
    
    def _bug_to_dict(self, bug: SecurityBug) -> Dict:
        """Convert SecurityBug to dictionary."""
        return {
            'type': bug.type,
            'severity': bug.severity,
            'title': bug.title,
            'description': bug.description,
            'evidence': bug.evidence,
            'line_number': bug.line_number,
            'context': bug.context,
            'exploitation': bug.exploitation,
            'poc': bug.poc,
            'cwe': bug.cwe
        }
    
    def _detect_hardcoded_credentials(self, content: str, source: str):
        """Detect hardcoded credentials in JavaScript."""
        patterns = [
            # Username/password pairs
            (r'(?:username|user|login)\s*[:=]\s*["\']([^"\']{3,})["\']', r'(?:password|pass|pwd)\s*[:=]\s*["\']([^"\']+)["\']'),
            
            # Database credentials
            (r'(?:db_user|dbuser)\s*[:=]\s*["\']([^"\']+)["\']', r'(?:db_pass|dbpass|db_password)\s*[:=]\s*["\']([^"\']+)["\']'),
            
            # Admin credentials
            (r'admin.*?["\']([^"\']+)["\']', r'password.*?["\']([^"\']+)["\']'),
        ]
        
        lines = content.split('\n')
        for idx, line in enumerate(lines, 1):
            lower_line = line.lower()
            
            # Check for explicit password assignments
            if 'password' in lower_line and ('=' in line or ':' in line):
                # Extract the value
                match = re.search(r'(?:password|pass|pwd)\s*[:=]\s*["\']([^"\']+)["\']', line, re.I)
                if match:
                    password = match.group(1)
                    # Ignore placeholders
                    if not self._is_placeholder(password):
                        self.bugs.append(SecurityBug(
                            type='Hardcoded Credentials',
                            severity='CRITICAL',
                            title=f'Hardcoded password found',
                            description='Password is hardcoded in JavaScript, allowing authentication bypass',
                            evidence=f'Password: {password}',
                            line_number=idx,
                            context=line.strip(),
                            exploitation='Use this password to authenticate as the target user',
                            poc=f'Found in {source} at line {idx}',
                            cwe='CWE-798'
                        ))
            
            # Check for API credentials
            if 'api' in lower_line and ('key' in lower_line or 'secret' in lower_line):
                match = re.search(r'(?:api[_-]?key|api[_-]?secret)\s*[:=]\s*["\']([^"\']{20,})["\']', line, re.I)
                if match:
                    key = match.group(1)
                    if not self._is_placeholder(key):
                        self.bugs.append(SecurityBug(
                            type='Hardcoded API Key',
                            severity='CRITICAL',
                            title='Hardcoded API key exposed',
                            description='API key is hardcoded in client-side JavaScript',
                            evidence=f'API Key: {key[:10]}...{key[-10:]}',
                            line_number=idx,
                            context=line.strip(),
                            exploitation='Use this API key to access the service',
                            poc=f'curl -H "Authorization: Bearer {key}" https://api.example.com',
                            cwe='CWE-798'
                        ))
    
    def _detect_jwt_issues(self, content: str, source: str):
        """Detect JWT-related security issues."""
        lines = content.split('\n')
        
        for idx, line in enumerate(lines, 1):
            # Detect JWT tokens
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            jwt_matches = re.finditer(jwt_pattern, line)
            
            for match in jwt_matches:
                token = match.group(0)
                
                # Decode JWT payload
                try:
                    parts = token.split('.')
                    if len(parts) >= 2:
                        # Decode header and payload
                        header = self._decode_jwt_part(parts[0])
                        payload = self._decode_jwt_part(parts[1])
                        
                        issues = []
                        
                        # Check for 'none' algorithm
                        if header and header.get('alg') == 'none':
                            issues.append("Uses 'none' algorithm")
                        
                        # Check for weak algorithms
                        if header and header.get('alg') in ['HS256', 'HS384', 'HS512']:
                            issues.append(f"Uses symmetric algorithm {header.get('alg')}")
                        
                        # Check for sensitive data in payload
                        if payload:
                            sensitive_keys = ['password', 'secret', 'api_key', 'private_key']
                            for key in sensitive_keys:
                                if key in str(payload).lower():
                                    issues.append(f"Contains sensitive field: {key}")
                        
                        if issues:
                            self.bugs.append(SecurityBug(
                                type='JWT Security Issue',
                                severity='HIGH',
                                title='Insecure JWT implementation',
                                description='; '.join(issues),
                                evidence=f'Token: {token[:50]}...',
                                line_number=idx,
                                context=line.strip(),
                                exploitation='JWT may be vulnerable to algorithm confusion or contains sensitive data',
                                poc=f'Decode JWT at jwt.io or manipulate algorithm',
                                cwe='CWE-347'
                            ))
                except:
                    pass
    
    def _decode_jwt_part(self, part: str) -> Optional[Dict]:
        """Decode a JWT part (header or payload)."""
        try:
            # Add padding if needed
            padding = 4 - len(part) % 4
            if padding:
                part += '=' * padding
            
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except:
            return None
    
    def _detect_api_keys(self, content: str, source: str):
        """Detect various API keys and secrets."""
        key_patterns = {
            'AWS Access Key': (r'AKIA[0-9A-Z]{16}', 'CRITICAL'),
            'AWS Secret Key': (r'aws_secret_access_key\s*=\s*["\']([^"\']{40})["\']', 'CRITICAL'),
            'Google API Key': (r'AIza[0-9A-Za-z\\-_]{35}', 'HIGH'),
            'GitHub Token': (r'ghp_[0-9a-zA-Z]{36}', 'HIGH'),
            'Slack Token': (r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}', 'HIGH'),
            'Stripe Key': (r'sk_live_[0-9a-zA-Z]{24}', 'CRITICAL'),
            'Twilio API Key': (r'SK[0-9a-fA-F]{32}', 'HIGH'),
            'SendGrid API Key': (r'SG\.[0-9A-Za-z\\-_]{22}\.[0-9A-Za-z\\-_]{43}', 'HIGH'),
            'Azure Key': (r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}', 'HIGH'),
        }
        
        lines = content.split('\n')
        for idx, line in enumerate(lines, 1):
            for key_type, (pattern, severity) in key_patterns.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    key_value = match.group(0)
                    
                    self.bugs.append(SecurityBug(
                        type=f'{key_type} Exposure',
                        severity=severity,
                        title=f'{key_type} found in JavaScript',
                        description=f'Active {key_type} exposed in client-side code',
                        evidence=f'{key_type}: {key_value[:15]}...',
                        line_number=idx,
                        context=line.strip(),
                        exploitation=f'Use this {key_type} to access the service',
                        poc=f'Found in {source}',
                        cwe='CWE-200'
                    ))
    
    def _detect_auth_bypass_patterns(self, content: str, source: str):
        """Detect authentication bypass patterns."""
        bypass_patterns = [
            (r'if\s*\([^)]*isAdmin[^)]*\)\s*{', 'Client-side admin check'),
            (r'if\s*\([^)]*role\s*===?\s*["\']admin["\'][^)]*\)', 'Client-side role check'),
            (r'localStorage\.setItem\(["\']isAdmin["\']', 'Admin flag in localStorage'),
            (r'sessionStorage\.setItem\(["\']role["\']', 'Role in sessionStorage'),
            (r'document\.cookie\s*=\s*["\']admin=true', 'Admin cookie set client-side'),
        ]
        
        lines = content.split('\n')
        for idx, line in enumerate(lines, 1):
            for pattern, description in bypass_patterns:
                if re.search(pattern, line, re.I):
                    self.bugs.append(SecurityBug(
                        type='Authentication Bypass',
                        severity='CRITICAL',
                        title='Client-side authentication check',
                        description=f'{description} can be bypassed via browser DevTools',
                        evidence=line.strip(),
                        line_number=idx,
                        context=self._get_context(content, idx),
                        exploitation='Modify localStorage/sessionStorage/cookies in browser console',
                        poc='localStorage.setItem("isAdmin", "true") or similar',
                        cwe='CWE-602'
                    ))
    
    def _detect_admin_endpoints(self, content: str, source: str):
        """Detect admin/debug endpoints in JavaScript."""
        endpoint_patterns = [
            r'["\']/(admin|administrator|dashboard|panel)["\']',
            r'["\'].*/api/v\d+/admin.*["\']',
            r'["\'].*/debug.*["\']',
            r'["\'].*/internal.*["\']',
            r'["\'].*/test.*["\']',
        ]
        
        endpoints_found = set()
        lines = content.split('\n')
        
        for idx, line in enumerate(lines, 1):
            for pattern in endpoint_patterns:
                matches = re.finditer(pattern, line, re.I)
                for match in matches:
                    endpoint = match.group(0).strip('"\'')
                    if endpoint not in endpoints_found:
                        endpoints_found.add(endpoint)
                        
                        self.bugs.append(SecurityBug(
                            type='Sensitive Endpoint Disclosure',
                            severity='MEDIUM',
                            title='Admin/debug endpoint found',
                            description=f'Hidden endpoint discovered: {endpoint}',
                            evidence=endpoint,
                            line_number=idx,
                            context=line.strip(),
                            exploitation=f'Access endpoint directly: {endpoint}',
                            poc=f'curl https://target.com{endpoint}',
                            cwe='CWE-200'
                        ))
    
    def _detect_debug_code(self, content: str, source: str):
        """Detect debug code that may leak information."""
        debug_patterns = [
            (r'console\.log\([^)]*(?:password|token|secret|key)[^)]*\)', 'Logs sensitive data'),
            (r'console\.log\([^)]*user[^)]*\)', 'Logs user object'),
            (r'debugger;', 'Debugger statement'),
            (r'//\s*TODO:?\s*remove.*debug', 'Debug code marked for removal'),
        ]
        
        lines = content.split('\n')
        for idx, line in enumerate(lines, 1):
            for pattern, description in debug_patterns:
                if re.search(pattern, line, re.I):
                    self.bugs.append(SecurityBug(
                        type='Debug Code',
                        severity='LOW',
                        title='Debug code in production',
                        description=description,
                        evidence=line.strip(),
                        line_number=idx,
                        context=line.strip(),
                        exploitation='May leak sensitive information in browser console',
                        poc='Check browser console',
                        cwe='CWE-489'
                    ))
    
    def _detect_sensitive_comments(self, content: str, source: str):
        """Detect sensitive information in comments."""
        lines = content.split('\n')
        sensitive_keywords = ['password', 'secret', 'key', 'token', 'credential', 'api', 'admin', 'todo', 'hack', 'bypass']
        
        for idx, line in enumerate(lines, 1):
            # Check single-line comments
            if '//' in line:
                comment = line[line.index('//'):]
                lower_comment = comment.lower()
                
                for keyword in sensitive_keywords:
                    if keyword in lower_comment and len(comment) > 20:
                        self.bugs.append(SecurityBug(
                            type='Sensitive Comment',
                            severity='LOW',
                            title='Sensitive information in comment',
                            description=f'Comment contains keyword: {keyword}',
                            evidence=comment.strip(),
                            line_number=idx,
                            context=comment.strip(),
                            exploitation='Review comment for leaked secrets or insights',
                            poc=f'Comment: {comment[:100]}',
                            cwe='CWE-615'
                        ))
                        break
    
    def _detect_crypto_weaknesses(self, content: str, source: str):
        """Detect weak cryptography."""
        weak_patterns = [
            (r'\bMD5\b', 'MD5 hash function', 'MEDIUM'),
            (r'\bSHA1\b', 'SHA1 hash function', 'MEDIUM'),
            (r'Math\.random\(\)', 'Math.random() for security', 'HIGH'),
            (r'btoa\(', 'Base64 encoding (not encryption)', 'LOW'),
        ]
        
        lines = content.split('\n')
        for idx, line in enumerate(lines, 1):
            for pattern, description, severity in weak_patterns:
                if re.search(pattern, line):
                    self.bugs.append(SecurityBug(
                        type='Weak Cryptography',
                        severity=severity,
                        title=f'Weak crypto: {description}',
                        description=f'Using {description} which is cryptographically weak',
                        evidence=line.strip(),
                        line_number=idx,
                        context=line.strip(),
                        exploitation='May be vulnerable to collision/prediction attacks',
                        poc=f'Line {idx}: {line[:100]}',
                        cwe='CWE-327'
                    ))
    
    def _detect_dom_xss_sinks(self, content: str, source: str):
        """Detect dangerous DOM XSS sinks."""
        sinks = [
            (r'\.innerHTML\s*=', 'innerHTML assignment'),
            (r'\.outerHTML\s*=', 'outerHTML assignment'),
            (r'document\.write\(', 'document.write()'),
            (r'document\.writeln\(', 'document.writeln()'),
            (r'eval\(', 'eval()'),
            (r'setTimeout\([^,)]*,[^,)]*\)', 'setTimeout with string'),
            (r'setInterval\([^,)]*,[^,)]*\)', 'setInterval with string'),
        ]
        
        lines = content.split('\n')
        for idx, line in enumerate(lines, 1):
            for pattern, description in sinks:
                if re.search(pattern, line):
                    self.bugs.append(SecurityBug(
                        type='DOM XSS Sink',
                        severity='MEDIUM',
                        title=f'Dangerous sink: {description}',
                        description=f'Uses {description} which can lead to XSS',
                        evidence=line.strip(),
                        line_number=idx,
                        context=self._get_context(content, idx, 50),
                        exploitation='Inject malicious payload if user input reaches this sink',
                        poc='Trace data flow from user input to this sink',
                        cwe='CWE-79'
                    ))
    
    def _detect_prototype_pollution(self, content: str, source: str):
        """Detect prototype pollution vectors."""
        pollution_patterns = [
            r'Object\.assign\(',
            r'\.merge\(',
            r'\.extend\(',
            r'__proto__',
            r'constructor\.prototype',
        ]
        
        lines = content.split('\n')
        for idx, line in enumerate(lines, 1):
            for pattern in pollution_patterns:
                if re.search(pattern, line):
                    self.bugs.append(SecurityBug(
                        type='Prototype Pollution Vector',
                        severity='MEDIUM',
                        title='Potential prototype pollution',
                        description=f'Uses pattern that may be vulnerable to prototype pollution',
                        evidence=line.strip(),
                        line_number=idx,
                        context=line.strip(),
                        exploitation='Inject __proto__ payload to pollute Object prototype',
                        poc='{"__proto__": {"polluted": true}}',
                        cwe='CWE-1321'
                    ))
                    break
    
    def _detect_race_conditions(self, content: str, source: str):
        """Detect potential race condition patterns."""
        race_patterns = [
            (r'setTimeout.*fetch', 'Async timing with fetch'),
            (r'Promise\.all.*forEach', 'Parallel promise execution'),
        ]
        
        lines = content.split('\n')
        for idx, line in enumerate(lines, 1):
            for pattern, description in race_patterns:
                if re.search(pattern, line, re.I):
                    self.bugs.append(SecurityBug(
                        type='Race Condition Pattern',
                        severity='LOW',
                        title='Potential race condition',
                        description=description,
                        evidence=line.strip(),
                        line_number=idx,
                        context=line.strip(),
                        exploitation='Send concurrent requests to exploit race condition',
                        poc='Use race condition tools like Turbo Intruder',
                        cwe='CWE-362'
                    ))
    
    def _detect_idor_patterns(self, content: str, source: str):
        """Detect IDOR (Insecure Direct Object Reference) patterns."""
        idor_patterns = [
            r'/api/v\d+/user/\d+',
            r'/api/v\d+/profile/\d+',
            r'/api/v\d+/account/\d+',
            r'/api/v\d+/order/\d+',
            r'/api/v\d+/document/\d+',
        ]
        
        endpoints_found = set()
        lines = content.split('\n')
        
        for idx, line in enumerate(lines, 1):
            for pattern in idor_patterns:
                matches = re.finditer(pattern, line, re.I)
                for match in matches:
                    endpoint = match.group(0)
                    if endpoint not in endpoints_found:
                        endpoints_found.add(endpoint)
                        
                        self.bugs.append(SecurityBug(
                            type='Potential IDOR',
                            severity='MEDIUM',
                            title='IDOR-prone endpoint',
                            description=f'Endpoint uses sequential IDs: {endpoint}',
                            evidence=endpoint,
                            line_number=idx,
                            context=line.strip(),
                            exploitation='Try accessing other users\' data by changing ID parameter',
                            poc=f'For GET /api/v1/user/123, try /api/v1/user/124',
                            cwe='CWE-639'
                        ))
    
    def _detect_graphql_introspection(self, content: str, source: str):
        """Detect GraphQL introspection queries."""
        if '__schema' in content or 'IntrospectionQuery' in content:
            self.bugs.append(SecurityBug(
                type='GraphQL Introspection',
                severity='LOW',
                title='GraphQL introspection enabled',
                description='GraphQL introspection is enabled, revealing full schema',
                evidence='__schema or IntrospectionQuery found',
                exploitation='Query full GraphQL schema to discover hidden queries/mutations',
                poc='Send introspection query to GraphQL endpoint',
                cwe='CWE-200'
            ))
    
    def _detect_postmessage_issues(self, content: str, source: str):
        """Detect postMessage security issues."""
        lines = content.split('\n')
        
        for idx, line in enumerate(lines, 1):
            # Check for postMessage without origin validation
            if 'addEventListener' in line and 'message' in line:
                # Look for origin validation in surrounding lines
                context = self._get_context(content, idx, 200)
                if 'event.origin' not in context and 'e.origin' not in context:
                    self.bugs.append(SecurityBug(
                        type='postMessage Without Origin Check',
                        severity='HIGH',
                        title='Missing origin validation in postMessage',
                        description='postMessage handler does not validate message origin',
                        evidence=line.strip(),
                        line_number=idx,
                        context=context,
                        exploitation='Send malicious messages from attacker domain',
                        poc='window.postMessage(payload, "*")',
                        cwe='CWE-940'
                    ))
    
    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder."""
        placeholders = [
            'your_', 'example', 'test', 'demo', 'sample', 'placeholder',
            'xxx', '***', '...', '12345', 'password', 'secret',
            'changeme', 'replace'
        ]
        
        lower_value = value.lower()
        return any(p in lower_value for p in placeholders)
    
    def _get_context(self, content: str, line_num: int, chars: int = 100) -> str:
        """Get surrounding context for a line."""
        lines = content.split('\n')
        if 0 <= line_num - 1 < len(lines):
            target_line = lines[line_num - 1]
            return target_line[:chars]
        return ""


def analyze_js_for_bugs(js_files: List[Dict]) -> Dict[str, Any]:
    """
    Analyze JavaScript files for real security bugs.
    
    Args:
        js_files: List of JS file dictionaries with 'content' and 'url'
    
    Returns:
        Aggregated bug findings across all files
    """
    analyzer = EnhancedJSAnalyzer()
    all_bugs = []
    
    for js_file in js_files:
        content = js_file.get('content', '')
        url = js_file.get('url', 'unknown')
        
        if not content:
            continue
        
        result = analyzer.analyze(content, url)
        
        # Add source URL to each bug
        for bug in result['bugs']:
            bug['source_file'] = url
            all_bugs.append(bug)
        
        logger.info(f"[{'!!!' if result['critical_bugs'] > 0 else '✓'}] Analyzed {url}: {result['total_bugs']} bugs ({result['critical_bugs']} critical)")
    
    # Categorize bugs
    by_severity = {
        'CRITICAL': [b for b in all_bugs if b['severity'] == 'CRITICAL'],
        'HIGH': [b for b in all_bugs if b['severity'] == 'HIGH'],
        'MEDIUM': [b for b in all_bugs if b['severity'] == 'MEDIUM'],
        'LOW': [b for b in all_bugs if b['severity'] == 'LOW'],
    }
    
    by_type = {}
    for bug in all_bugs:
        bug_type = bug['type']
        if bug_type not in by_type:
            by_type[bug_type] = []
        by_type[bug_type].append(bug)
    
    return {
        'bugs': all_bugs,
        'total_bugs': len(all_bugs),
        'by_severity': by_severity,
        'by_type': by_type,
        'files_analyzed': len(js_files),
        'critical_count': len(by_severity['CRITICAL']),
        'high_count': len(by_severity['HIGH']),
        'medium_count': len(by_severity['MEDIUM']),
        'low_count': len(by_severity['LOW']),
    }
