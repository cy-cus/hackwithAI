"""JS Analyzer - Analyzes JavaScript content for secrets, endpoints, and vulnerabilities."""

import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class Secret:
    """Discovered secret/credential."""
    type: str
    value: str
    context: str
    severity: str = "HIGH"


class JSAnalyzer:
    """
    Analyzes JavaScript content for security patterns.
    Based on AllSuite scanner.js patterns.
    """
    
    # Secret patterns from AllSuite
    SECRET_PATTERNS = {
        # Cloud & Infrastructure
        'AWS Access Key': (r'AKIA[0-9A-Z]{16}', 'CRITICAL'),
        'AWS Secret Key': (r'aws.{0,20}[\'"][0-9a-zA-Z\/+]{40}[\'"]', 'CRITICAL'),
        'AWS Account ID': (r'aws.{0,20}[\'"][0-9]{12}[\'"]', 'HIGH'),
        'Azure Tenant ID': (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'MEDIUM'),
        'Google API Key': (r'AIza[0-9A-Za-z\-_]{35}', 'CRITICAL'),
        'Google OAuth': (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'HIGH'),
        
        # Firebase
        'Firebase URL': (r'[a-z0-9-]+\.firebaseio\.com', 'MEDIUM'),
        'Firebase API Key': (r'AIza[0-9A-Za-z\-_]{35}', 'CRITICAL'),
        
        # GitHub
        'GitHub Token (classic)': (r'gh[pousr]_[0-9a-zA-Z]{36}', 'CRITICAL'),
        'GitHub Token (fine-grained)': (r'github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}', 'CRITICAL'),
        'GitHub App Token': (r'ghs_[0-9a-zA-Z]{36}', 'CRITICAL'),
        
        # Slack
        'Slack Token': (r'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}', 'CRITICAL'),
        'Slack Webhook': (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}', 'HIGH'),
        
        # Stripe
        'Stripe API Key': (r'sk_(live|test)_[0-9a-zA-Z]{24,}', 'CRITICAL'),
        'Stripe Publishable Key': (r'pk_(live|test)_[0-9a-zA-Z]{24,}', 'MEDIUM'),
        
        # Database
        'MongoDB Connection': (r'mongodb(\+srv)?://[^\s"\'<>]+', 'CRITICAL'),
        'PostgreSQL Connection': (r'postgres(ql)?://[^\s"\'<>]+', 'CRITICAL'),
        'MySQL Connection': (r'mysql://[^\s"\'<>]+', 'CRITICAL'),
        
        # API Keys & Tokens
        'Generic API Key': (r'(api[_-]?key|apikey)[\'\":\s=]+[0-9a-zA-Z\-_]{16,64}', 'HIGH'),
        'Generic Secret': (r'(secret|secret[_-]?key)[\'\":\s=]+[0-9a-zA-Z\-_]{16,64}', 'HIGH'),
        'Auth Token': (r'(auth[_-]?token|authorization)[\'\":\s=]+[0-9a-zA-Z\-_]{16,}', 'HIGH'),
        
        # JWT
        'JWT Token': (r'eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}', 'HIGH'),
        
        # Private Keys
        'RSA Private Key': (r'-----BEGIN RSA PRIVATE KEY-----', 'CRITICAL'),
        'EC Private Key': (r'-----BEGIN EC PRIVATE KEY-----', 'CRITICAL'),
        'SSH Private Key': (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'CRITICAL'),
        'PGP Private Key': (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'CRITICAL'),
        
        # OAuth & Social
        'Facebook Access Token': (r'EAACEdEose0cBA[0-9A-Za-z]+', 'CRITICAL'),
        'Twitter OAuth': (r'[1-9][0-9]+-[0-9a-zA-Z]{40}', 'HIGH'),
        
        # Cloud Specific
        'SendGrid API Key': (r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}', 'CRITICAL'),
        'Twilio API Key': (r'SK[0-9a-fA-F]{32}', 'CRITICAL'),
        'Mailgun API Key': (r'key-[0-9a-zA-Z]{32}', 'CRITICAL'),
        
        # Generic Patterns
        # Only flag password-like values when they are non-trivial quoted strings,
        # to avoid noisy matches on minified control flags like password:!0 or password:null
        'Password in Code': (r'(password|passwd|pwd)[\'\":\s=]+[\'\"]\w{8,}[\'"]', 'HIGH'),
        'Bearer Token': (r'bearer\s+[0-9a-zA-Z\-._~+\/]+=*', 'HIGH'),
        'Basic Auth': (r'basic\s+[A-Za-z0-9+\/=]{20,}', 'HIGH'),
    }
    
    # Endpoint patterns - Enhanced to catch more API paths in JS
    ENDPOINT_PATTERNS = {
        'api': r'/api/[A-Za-z0-9_\-\/\.?=&\{\}:]+',
        'v1_v2': r'/v[0-9]+/[A-Za-z0-9_\-\/\.?=&]+',
        'graphql': r'/graphql|/gql',
        'rest': r'/[A-Za-z0-9_\-\/]{3,}',
        'websocket': r'wss?://[^\s"\'<>]+',
        'quoted_paths': r'["\']\/[a-zA-Z0-9_\-\/\.?=&\{\}:]+["\']',
        'axios_fetch': r'(?:axios\.(?:get|post|put|delete|patch)|fetch)\s*\(["\']([^"\']+)["\']',
        'route_paths': r'(?:path|route|url|endpoint)\s*[:=]\s*["\']([^"\']+)["\']',
    }
    
    # Ignore patterns for false positives
    IGNORE_PATTERNS = [
        'example.com', 'localhost', '127.0.0.1', 'test123',
        'foobar', 'xxxxx', 'your_api_key_here', 'YOUR_SECRET_KEY',
        'sample', 'dummy', 'placeholder'
    ]
    
    IGNORE_EXTENSIONS = [
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
        '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.css', '.map'
    ]
    
    def analyze_js_content(self, js_content: str, source_url: str = "unknown") -> Dict:
        """
        Analyze JavaScript content comprehensively.
        
        Args:
            js_content: JavaScript source code
            source_url: Source URL for context
            
        Returns:
            Dict with endpoints, secrets, links, modules, interesting_vars
        """
        return {
            'endpoints': self.extract_endpoints(js_content),
            'secrets': self.extract_secrets(js_content, source_url),
            'links': self.extract_links(js_content),
            'modules': self.extract_modules(js_content),
            'interesting_vars': self.extract_interesting_vars(js_content)
        }
    
    def extract_secrets(self, text: str, source_url: str = "") -> List[Secret]:
        """Extract secrets and credentials from JS with source tracking."""
        secrets = []
        seen = set()
        
        for secret_type, (pattern, severity) in self.SECRET_PATTERNS.items():
            try:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                
                for match in matches:
                    value = match.group(0)
                    
                    # Skip false positives
                    if self._is_false_positive(value):
                        continue
                    
                    key = f"{secret_type}:{value}"
                    if key not in seen:
                        seen.add(key)
                        context = self._get_context(text, match.start())
                        # Calculate line number
                        line_number = text[:match.start()].count('\n') + 1
                        
                        secrets.append(Secret(
                            type=secret_type,
                            value=value,
                            context=context,
                            severity=severity,
                            js_file=source_url,  # Track which JS file
                            line_number=line_number  # Track line number
                        ))
            except Exception:
                continue
        
        return secrets
    
    def extract_endpoints(self, text: str) -> List[str]:
        """Extract API endpoints and paths from JS content."""
        endpoints = set()
        
        for name, pattern in self.ENDPOINT_PATTERNS.items():
            try:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    # Handle patterns with capture groups (axios_fetch, route_paths)
                    if match.groups():
                        # Use captured group (the URL inside quotes)
                        endpoint = match.group(1).strip('\'"')
                    else:
                        # Use full match
                        endpoint = match.group(0).strip('\'"')
                    
                    if self._is_valid_endpoint(endpoint):
                        endpoints.add(endpoint)
            except Exception:
                continue
        
        return sorted(list(endpoints))
    
    def extract_links(self, text: str) -> List[str]:
        """Extract HTTP(S) links."""
        links = set()
        
        # HTTP(S) URLs
        url_pattern = r'https?://[^\s"\'<>)}\]]+' 
        matches = re.finditer(url_pattern, text, re.IGNORECASE)
        
        for match in matches:
            url = match.group(0).rstrip(',;)]}>')
            if not self._is_false_positive(url):
                links.add(url)
        
        return sorted(list(links))
    
    def extract_modules(self, text: str) -> List[str]:
        """Extract NPM modules and imports."""
        modules = set()
        
        # require() statements
        require_pattern = r'require\s*\(\s*["\']([^"\']+)["\']\s*\)'
        for match in re.finditer(require_pattern, text):
            module = match.group(1)
            if not module.startswith('.') and not module.startswith('/'):
                modules.add(module)
        
        # import statements
        import_pattern = r'import\s+.+\s+from\s+["\']([^"\']+)["\']'
        for match in re.finditer(import_pattern, text):
            module = match.group(1)
            if not module.startswith('.') and not module.startswith('/'):
                modules.add(module)
        
        return sorted(list(modules))
    
    def extract_interesting_vars(self, text: str) -> List[str]:
        """Extract interesting variable names (config, keys, etc)."""
        interesting = set()
        
        # Look for suspicious variable patterns
        var_patterns = [
            r'(api[_-]?key|apiKey)\s*[:=]',
            r'(secret|secretKey)\s*[:=]',
            r'(token|accessToken)\s*[:=]',
            r'(password|passwd)\s*[:=]',
            r'(config|configuration)\s*[:=]',
            r'(credentials|creds)\s*[:=]',
        ]
        
        for pattern in var_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                interesting.add(match.group(0))
        
        return sorted(list(interesting))[:50]  # Limit to top 50
    
    def _is_false_positive(self, value: str) -> bool:
        """Check if value is likely a false positive."""
        value_lower = value.lower()
        
        for ignore in self.IGNORE_PATTERNS:
            if ignore.lower() in value_lower:
                return True
        
        return False
    
    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is valid."""
        if len(endpoint) < 4:
            return False
        
        endpoint_lower = endpoint.lower()
        
        # Check ignore extensions
        for ext in self.IGNORE_EXTENSIONS:
            if endpoint_lower.endswith(ext):
                return False
        
        # Must start with / or http/ws
        if not (endpoint.startswith('/') or endpoint.startswith('http') or endpoint.startswith('ws')):
            return False
        
        return True
    
    def _get_context(self, text: str, index: int, length: int = 100) -> str:
        """Get surrounding context for a match."""
        start = max(0, index - length)
        end = min(len(text), index + length)
        return text[start:end].replace('\n', ' ').strip()


def analyze_js_files(js_files: List[Dict]) -> Dict:
    """
    Analyze multiple JS files and aggregate results with source tracking.
    
    Args:
        js_files: List of JS file data from JSFetcher (with 'content' and 'url')
        
    Returns:
        Aggregated analysis results with source tracking
    """
    analyzer = JSAnalyzer()
    
    all_endpoints = set()
    all_secrets = []
    all_links = set()
    all_modules = set()
    all_vars = set()
    
    # Track sources for endpoints and links
    endpoint_sources = {}  # {endpoint_url: [js_file_url, ...]}
    link_sources = {}  # {link_url: [js_file_url, ...]}
    
    for js_file in js_files:
        try:
            js_url = js_file['url']
            result = analyzer.analyze_js_content(js_file['content'], js_url)
            
            # Track endpoint sources
            for endpoint in result['endpoints']:
                all_endpoints.add(endpoint)
                if endpoint not in endpoint_sources:
                    endpoint_sources[endpoint] = []
                endpoint_sources[endpoint].append(js_url)
            
            # Secrets already have source tracking from extract_secrets
            all_secrets.extend(result['secrets'])
            
            # Track link sources
            for link in result['links']:
                all_links.add(link)
                if link not in link_sources:
                    link_sources[link] = []
                link_sources[link].append(js_url)
            
            all_modules.update(result['modules'])
            all_vars.update(result['interesting_vars'])
        except Exception as e:
            print(f"  Error analyzing {js_file.get('url', 'unknown')}: {e}")
    
    return {
        'endpoints': sorted(list(all_endpoints)),
        'secrets': all_secrets,
        'links': sorted(list(all_links)),
        'modules': sorted(list(all_modules)),
        'interesting_vars': sorted(list(all_vars)),
        'js_files_analyzed': len(js_files),
        'endpoint_sources': endpoint_sources,  # NEW: Track where each endpoint came from
        'link_sources': link_sources  # NEW: Track where each link came from
    }
