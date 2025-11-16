"""Manifest Hunter - Discovers and analyzes build manifests and endpoint lists."""

import asyncio
import aiohttp
import json
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
import re


class ManifestHunter:
    """Hunts for manifest files that contain endpoint lists."""
    
    # Patterns that indicate manifest/endpoint list files
    MANIFEST_PATTERNS = [
        'buildmanifest',
        'build-manifest',
        'webpack.json',
        'asset-manifest',
        'manifest.json',
        'routes.json',
        'sitemap.json',
        'endpoints.json',
        'api-manifest',
        'next-manifest',
        '_next/static',
        'chunk-map',
        'route-manifest',
        'pages-manifest'
    ]
    
    def __init__(self, timeout: int = 30):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    async def hunt_manifests(self, js_urls: List[str], base_urls: List[str]) -> Dict:
        """
        Hunt for manifest files from JS URLs and base URLs.
        
        Args:
            js_urls: List of discovered JS file URLs
            base_urls: List of base URLs to check for manifests
            
        Returns:
            Dict with discovered manifests and extracted endpoints
        """
        manifest_candidates = []
        
        # 1. Check JS URLs for manifest patterns
        for url in js_urls:
            if self._is_manifest_file(url):
                manifest_candidates.append(url)
        
        # 2. Check common manifest locations on base URLs
        for base_url in base_urls:
            common_manifests = self._generate_manifest_urls(base_url)
            manifest_candidates.extend(common_manifests)
        
        # 3. Fetch and analyze manifests
        results = await self._fetch_manifests(list(set(manifest_candidates)))
        
        return results
    
    def _is_manifest_file(self, url: str) -> bool:
        """Check if URL looks like a manifest file."""
        url_lower = url.lower()
        for pattern in self.MANIFEST_PATTERNS:
            if pattern in url_lower:
                return True
        return False
    
    def _generate_manifest_urls(self, base_url: str) -> List[str]:
        """Generate common manifest file URLs."""
        manifests = []
        
        common_paths = [
            '/_next/static/chunks/pages-manifest.json',
            '/_next/data/buildManifest.json',
            '/build-manifest.json',
            '/asset-manifest.json',
            '/webpack.json',
            '/manifest.json',
            '/api-manifest.json',
            '/routes.json',
            '/.next/routes-manifest.json',
            '/static/manifest.json',
            '/_app/manifest.json'
        ]
        
        for path in common_paths:
            manifests.append(urljoin(base_url, path))
        
        return manifests
    
    async def _fetch_manifests(self, urls: List[str]) -> Dict:
        """Fetch and parse manifest files."""
        manifests_data = {
            'files_found': [],
            'endpoints': [],
            'js_files': [],
            'routes': []
        }
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            tasks = [self._fetch_single_manifest(session, url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and result:
                    manifests_data['files_found'].append(result.get('url'))
                    manifests_data['endpoints'].extend(result.get('endpoints', []))
                    manifests_data['js_files'].extend(result.get('js_files', []))
                    manifests_data['routes'].extend(result.get('routes', []))
        
        # Deduplicate
        manifests_data['endpoints'] = list(set(manifests_data['endpoints']))
        manifests_data['js_files'] = list(set(manifests_data['js_files']))
        manifests_data['routes'] = list(set(manifests_data['routes']))
        
        return manifests_data
    
    async def _fetch_single_manifest(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """Fetch and parse a single manifest file."""
        try:
            headers = {'User-Agent': self.user_agent}
            
            async with session.get(url, headers=headers, ssl=False) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                
                # Try to parse as JSON
                try:
                    data = json.loads(content)
                    return self._extract_from_manifest(data, url)
                except json.JSONDecodeError:
                    # Not JSON, try regex extraction
                    return self._extract_from_text(content, url)
        
        except Exception:
            return None
    
    def _extract_from_manifest(self, data: Dict, source_url: str) -> Dict:
        """Extract endpoints and files from JSON manifest."""
        result = {
            'url': source_url,
            'endpoints': [],
            'js_files': [],
            'routes': []
        }
        
        def recursive_extract(obj, base_url=''):
            """Recursively extract URLs from nested JSON."""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    # Check if key or value looks like a route/endpoint
                    if isinstance(value, str):
                        if value.startswith(('/api/', '/v1/', '/v2/', '/_next/')):
                            result['endpoints'].append(value)
                        elif value.endswith('.js'):
                            result['js_files'].append(value)
                        elif '/' in value and not value.startswith('http'):
                            result['routes'].append(value)
                    
                    # Recurse
                    recursive_extract(value, base_url)
            
            elif isinstance(obj, list):
                for item in obj:
                    recursive_extract(item, base_url)
        
        recursive_extract(data)
        return result
    
    def _extract_from_text(self, content: str, source_url: str) -> Dict:
        """Extract endpoints from text content using regex."""
        result = {
            'url': source_url,
            'endpoints': [],
            'js_files': [],
            'routes': []
        }
        
        # Extract quoted paths
        path_pattern = r'["\']([/][a-zA-Z0-9_\-/\.]+)["\']'
        for match in re.finditer(path_pattern, content):
            path = match.group(1)
            if path.endswith('.js'):
                result['js_files'].append(path)
            elif any(x in path for x in ['/api/', '/v1/', '/v2/']):
                result['endpoints'].append(path)
            else:
                result['routes'].append(path)
        
        return result


class SmartURLConstructor:
    """Intelligently constructs full URLs from partial paths."""
    
    @staticmethod
    def construct_urls(partial_paths: List[str], base_urls: List[str]) -> List[str]:
        """
        Construct full URLs from partial paths and base URLs.
        
        Args:
            partial_paths: List of partial paths like '/api/users'
            base_urls: List of discovered base URLs
            
        Returns:
            List of constructed full URLs
        """
        full_urls = []
        
        # Extract unique domains from base URLs
        domains = set()
        for base_url in base_urls:
            parsed = urlparse(base_url)
            if parsed.netloc:
                domains.add(f"{parsed.scheme}://{parsed.netloc}")
        
        # If no domains, try to infer from paths
        if not domains and partial_paths:
            # Extract domain hints from paths
            for path in partial_paths:
                if path.startswith('http'):
                    parsed = urlparse(path)
                    if parsed.netloc:
                        domains.add(f"{parsed.scheme}://{parsed.netloc}")
        
        # Construct URLs
        for domain in domains:
            for path in partial_paths:
                if path.startswith('http'):
                    full_urls.append(path)
                elif path.startswith('/'):
                    full_urls.append(f"{domain}{path}")
                else:
                    full_urls.append(f"{domain}/{path}")
        
        return list(set(full_urls))
    
    @staticmethod
    def extract_base_urls(urls: List[str]) -> List[str]:
        """Extract unique base URLs from a list of full URLs."""
        base_urls = set()
        
        for url in urls:
            parsed = urlparse(url)
            if parsed.netloc:
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                base_urls.add(base_url)
        
        return list(base_urls)


def run_manifest_hunter(js_urls: List[str], base_urls: List[str]) -> Dict:
    """
    Synchronous wrapper for ManifestHunter.
    
    Args:
        js_urls: Discovered JS file URLs
        base_urls: Base URLs of the target
        
    Returns:
        Dict with manifest data
    """
    if not js_urls and not base_urls:
        return {
            'files_found': [],
            'endpoints': [],
            'js_files': [],
            'routes': []
        }
    
    hunter = ManifestHunter()
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(hunter.hunt_manifests(js_urls, base_urls))
        loop.close()
        return results
    except Exception as e:
        print(f"Manifest hunter error: {e}")
        return {
            'files_found': [],
            'endpoints': [],
            'js_files': [],
            'routes': []
        }
