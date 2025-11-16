"""Application Logic Analyzer - Extracts application flows from JavaScript."""

import re
from typing import List, Dict


class AppLogicAnalyzer:
    """Analyzes JavaScript to understand application logic and flows."""
    
    # Authentication patterns
    AUTH_PATTERNS = {
        'login': [
            r'login\s*\(',
            r'signin\s*\(',
            r'authenticate\s*\(',
            r'["\']login["\']',
            r'/auth/login',
            r'/api/login',
            r'username.*password',
            r'credentials',
        ],
        'register': [
            r'register\s*\(',
            r'signup\s*\(',
            r'createAccount',
            r'/auth/register',
            r'/api/signup',
        ],
        'password_reset': [
            r'resetPassword',
            r'forgotPassword',
            r'reset-password',
            r'/auth/reset',
            r'/forgot',
            r'passwordReset',
        ],
        'token_handling': [
            r'token\s*[:=]',
            r'jwt\s*[:=]',
            r'bearer',
            r'refreshToken',
            r'accessToken',
            r'localStorage\.setItem.*token',
            r'sessionStorage\.setItem.*token',
        ],
        'session': [
            r'session\s*[:=]',
            r'sessionId',
            r'cookie',
            r'session_id',
        ]
    }
    
    # API patterns
    API_PATTERNS = {
        'fetch_calls': r'fetch\s*\(\s*["\']([^"\']+)["\']',
        'axios_calls': r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        'ajax_calls': r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        'api_base': r'(API_URL|BASE_URL|apiUrl|baseUrl)\s*[:=]\s*["\']([^"\']+)["\']',
    }
    
    # Data flow patterns
    DATA_PATTERNS = {
        'form_submission': r'onSubmit|handleSubmit|submitForm',
        'validation': r'validate|validator|isValid',
        'error_handling': r'catch\s*\(|onError|handleError',
        'state_management': r'useState|setState|store\.|redux',
    }
    
    def analyze_js_content(self, js_content: str, url: str) -> Dict:
        """
        Analyze JavaScript content for application logic.
        
        Args:
            js_content: JavaScript source code
            url: Source URL
            
        Returns:
            Dict with discovered patterns and flows
        """
        return {
            'url': url,
            'auth_flows': self._detect_auth_flows(js_content),
            'api_calls': self._extract_api_calls(js_content),
            'data_flows': self._detect_data_flows(js_content),
            'interesting_snippets': self._extract_interesting_snippets(js_content),
        }
    
    def _detect_auth_flows(self, content: str) -> Dict:
        """Detect authentication-related flows."""
        flows = {}
        
        for flow_type, patterns in self.AUTH_PATTERNS.items():
            matches = []
            for pattern in patterns:
                found = re.finditer(pattern, content, re.IGNORECASE)
                for match in found:
                    context = self._get_context(content, match.start())
                    matches.append(context)
            
            if matches:
                flows[flow_type] = matches[:5]  # Limit to 5 per type
        
        return flows
    
    def _extract_api_calls(self, content: str) -> List[Dict]:
        """Extract API call patterns."""
        api_calls = []
        
        for call_type, pattern in self.API_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                api_calls.append({
                    'type': call_type,
                    'value': match.group(0),
                    'context': self._get_context(content, match.start())
                })
        
        return api_calls[:20]  # Limit
    
    def _detect_data_flows(self, content: str) -> Dict:
        """Detect data flow patterns."""
        flows = {}
        
        for flow_type, pattern in self.DATA_PATTERNS.items():
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                flows[flow_type] = len(matches)
        
        return flows
    
    def _extract_interesting_snippets(self, content: str) -> List[str]:
        """Extract interesting code snippets."""
        snippets = []
        
        # Look for function definitions related to auth/API
        interesting_functions = [
            'login', 'auth', 'token', 'api', 'fetch',
            'password', 'reset', 'register', 'admin'
        ]
        
        for func in interesting_functions:
            pattern = rf'(function\s+{func}\w*\s*\([^)]*\)\s*\{{[^}}]{{0,300}}\}})'
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                snippet = match.group(1)
                if len(snippet) < 500:  # Only reasonable sized snippets
                    snippets.append(snippet)
        
        return snippets[:10]  # Limit to 10
    
    def _get_context(self, text: str, index: int, length: int = 150) -> str:
        """Get surrounding context."""
        start = max(0, index - length)
        end = min(len(text), index + length)
        return text[start:end].replace('\n', ' ').strip()


def analyze_application_logic(js_files: List[Dict]) -> Dict:
    """
    Analyze multiple JS files for application logic.
    
    Args:
        js_files: List of JS file data with content
        
    Returns:
        Aggregated application logic analysis
    """
    analyzer = AppLogicAnalyzer()
    
    all_auth_flows = {}
    all_api_calls = []
    all_data_flows = {}
    all_snippets = []
    
    for js_file in js_files[:50]:  # Analyze up to 50 files
        try:
            result = analyzer.analyze_js_content(js_file['content'], js_file['url'])
            
            # Merge auth flows
            for flow_type, matches in result['auth_flows'].items():
                if flow_type not in all_auth_flows:
                    all_auth_flows[flow_type] = []
                all_auth_flows[flow_type].extend(matches)
            
            # Collect API calls
            all_api_calls.extend(result['api_calls'])
            
            # Merge data flows
            for flow_type, count in result['data_flows'].items():
                all_data_flows[flow_type] = all_data_flows.get(flow_type, 0) + count
            
            # Collect snippets
            all_snippets.extend(result['interesting_snippets'])
            
        except Exception as e:
            print(f"  Error analyzing {js_file.get('url', 'unknown')}: {e}")
    
    return {
        'auth_flows': all_auth_flows,
        'api_calls': all_api_calls[:30],  # Limit
        'data_flows': all_data_flows,
        'interesting_snippets': all_snippets[:15],  # Limit
    }
