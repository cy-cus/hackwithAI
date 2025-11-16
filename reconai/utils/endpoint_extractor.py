"""Extract API endpoint paths from URLs and JS content."""

from typing import List, Set
from urllib.parse import urlparse


def extract_api_paths_from_urls(urls: List[str]) -> List[str]:
    """
    Extract API endpoint paths from full URLs.
    
    Args:
        urls: List of full URLs (e.g., ['https://example.com/api/users', ...])
        
    Returns:
        List of unique API paths (e.g., ['/api/users', '/admin', ...])
    """
    api_paths = set()
    
    for url in urls:
        try:
            if isinstance(url, dict):
                # Handle Endpoint objects as dicts
                url = url.get('url', '')
            
            # Parse URL to extract path
            parsed = urlparse(str(url))
            path = parsed.path
            
            # Skip root path or empty
            if not path or path == '/':
                continue
            
            # Add query string if present
            if parsed.query:
                path = f"{path}?{parsed.query}"
            
            # Filter for API-like paths
            if _is_api_path(path):
                api_paths.add(path)
                
        except Exception:
            continue
    
    return sorted(list(api_paths))


def _is_api_path(path: str) -> bool:
    """
    Check if a path looks like an API endpoint.
    
    Args:
        path: URL path to check
        
    Returns:
        True if it looks like an API endpoint
    """
    if not path:
        return False
    
    # Skip static files
    static_extensions = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff',
        '.woff2', '.ttf', '.eot', '.css', '.js', '.map', '.json',
        '.xml', '.txt', '.pdf', '.zip', '.tar', '.gz'
    ]
    
    path_lower = path.lower()
    for ext in static_extensions:
        if path_lower.endswith(ext):
            return False
    
    # Patterns that indicate API endpoints
    api_indicators = [
        '/api/',
        '/v1/', '/v2/', '/v3/', '/v4/',
        '/graphql', '/gql',
        '/rest/',
        '/oauth',
        '/auth',
        '/login', '/logout',
        '/admin',
        '/user', '/account',
        '/data',
        '/query'
    ]
    
    for indicator in api_indicators:
        if indicator in path_lower:
            return True
    
    # If path has at least 2 segments and isn't too long, consider it
    segments = [s for s in path.split('/') if s]
    if 1 <= len(segments) <= 6:
        return True
    
    return False


def merge_api_paths(url_paths: List[str], js_paths: List[str]) -> List[str]:
    """
    Merge API paths from URLs and JS analysis, removing duplicates.
    
    Args:
        url_paths: Paths extracted from URLs
        js_paths: Paths extracted from JS files
        
    Returns:
        Deduplicated list of API paths
    """
    all_paths = set()
    
    for path in url_paths:
        if path:
            all_paths.add(path)
    
    for path in js_paths:
        if path and _is_api_path(path):
            all_paths.add(path)
    
    return sorted(list(all_paths))
