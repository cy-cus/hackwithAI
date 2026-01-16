"""
Manifest Hunter - Advanced discovery of hidden JS assets via build manifests.

Detects and parses:
- Webpack asset-manifest.json
- Next.js _buildManifest.js
- Vite/Rollup manifest.json
- Runtime chunk maps
- SourceMappingURL references
"""

import re
import json
import logging
import asyncio
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import httpx

logger = logging.getLogger(__name__)

class ManifestHunter:
    """
    Hunts for build manifests and extracts hidden JS file paths.
    """
    
    # Common paths where manifests live
    MANIFEST_PATHS = [
        # React / Generic Webpack
        '/asset-manifest.json',
        '/manifest.json',
        '/assets-manifest.json',
        '/webpack-assets.json',
        
        # Next.js
        '/_next/static/development/_buildManifest.js',
        '/_next/static/_buildManifest.js',
        '/_next/static/chunks/manifest.js',
        
        # Vite
        '/assets/manifest.json',
        
        # Nuxt
        '/_nuxt/manifest.json',
        
        # Angular
        '/runtime.js',  # Often contains the chunk map
        '/main.js'      # Often contains the chunk map
    ]
    
    def __init__(self, concurrency: int = 5):
        self.concurrency = concurrency
        
    async def hunt(self, base_url: str) -> List[str]:
        """
        Probe for manifest files and extract JS URLs from them.
        """
        found_files = set()
        
        # Normalize base URL
        if not base_url.endswith('/'):
            base_url += '/'
            
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # 1. Active Probing
            tasks = []
            for path in self.MANIFEST_PATHS:
                target_url = urljoin(base_url, path.lstrip('/'))
                tasks.append(self._check_and_parse(client, target_url))
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for res in results:
                if isinstance(res, list):
                    found_files.update(res)
                    
        return list(found_files)

    async def _check_and_parse(self, client: httpx.AsyncClient, url: str) -> List[str]:
        """Check if manifest exists and parse it."""
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                content_type = resp.headers.get('content-type', '').lower()
                content = resp.text
                
                # Check if it looks valid
                if len(content) < 10 or len(content) > 5000000: # Safety limits
                    return []
                
                logger.info(f"[ManifestHunter] Found potential manifest: {url}")
                return self._parse_content(content, url)
        except Exception:
            pass
        return []

    def _parse_content(self, content: str, source_url: str) -> List[str]:
        """
        Intelligently parse manifest content to find JS paths.
        Handles JSON and JS assignments.
        """
        urls = set()
        
        # Strategy 1: Try JSON Parsing
        try:
            data = json.loads(content)
            urls.update(self._extract_from_json(data, source_url))
            return list(urls) # If it was valid JSON, stop here
        except json.JSONDecodeError:
            pass
            
        # Strategy 2: Next.js / JS Object Parsing
        # Look for __BUILD_MANIFEST = { ... }
        if '__BUILD_MANIFEST' in content or 'self.__BUILD_MANIFEST' in content:
            urls.update(self._extract_nextjs_chunks(content, source_url))
            
        # Strategy 3: Webpack Chunk Maps (Regex)
        # Look for patterns like "1": "static/chunks/1.js"
        urls.update(self._extract_webpack_chunks(content, source_url))
        
        return list(urls)

    def _extract_from_json(self, data: Any, base_url: str) -> Set[str]:
        """Recursive extraction from JSON."""
        urls = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                urls.update(self._extract_from_json(value, base_url))
        elif isinstance(data, list):
            for item in data:
                urls.update(self._extract_from_json(item, base_url))
        elif isinstance(data, str):
            if self._is_interesting_asset(data):
                full_url = SmartURLConstructor.construct(base_url, data)
                urls.add(full_url)
                
        return urls

    def _extract_nextjs_chunks(self, content: str, base_url: str) -> Set[str]:
        """Convert Next.js manifest object string to URLs."""
        urls = set()
        # Find strings ending in .js inside the content
        # Next.js manifests look like: "index": ["static/chunks/pages/index-123.js"]
        matches = re.finditer(r'["\']([^"\']+\.js)["\']', content)
        for match in matches:
            path = match.group(1)
            # Typically Next.js paths in manifest are relative to _next/
            if path.startswith('static/'):
                # We need to reconstruct carefully.
                # If manifest found at /_next/static/_buildManifest.js
                # And path is static/chunks/abc.js
                # It usually maps to /_next/static/chunks/abc.js
                
                # Heuristic: try to preserve the /_next/ prefix if it exists in base
                parsed = urlparse(base_url)
                if '/_next/' in parsed.path:
                    # e.g. https://site.com/_next/static/_buildManifest.js
                    # root is https://site.com/_next/
                    root = base_url.split('/static/')[0]
                    if not root.endswith('/'): root += '/'
                    urls.add(urljoin(root, path))
                else:
                    urls.add(SmartURLConstructor.construct(base_url, path))
            else:
                urls.add(SmartURLConstructor.construct(base_url, path))
        return urls

    def _extract_webpack_chunks(self, content: str, base_url: str) -> Set[str]:
        """Extract generic JS paths from text."""
        urls = set()
        # Look for file paths ending in .js
        matches = re.finditer(r'["\']([a-zA-Z0-9_\-\/\.]+\.js)["\']', content)
        for match in matches:
            path = match.group(1)
            if self._is_interesting_asset(path):
                 urls.add(SmartURLConstructor.construct(base_url, path))
        return urls

    def _is_interesting_asset(self, path: str) -> bool:
        """Filter for JS files, ignoring generic vendor/polyfills if valid."""
        return path.endswith('.js') and not path.startswith(('http', '//'))

class SmartURLConstructor:
    """Helper to reconstruct absolute URLs from relative manifest paths."""
    
    @staticmethod
    def construct(manifest_url: str, relative_path: str) -> str:
        """
        Constructs a URL, handling the tricky logic of where assets live 
        relative to the manifest file.
        """
        # If relative path starts with /, it's relative to domain root
        if relative_path.startswith('/'):
            parsed = urlparse(manifest_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            return urljoin(base, relative_path)
            
        # Otherwise, resolving relative to manifest can be tricky.
        # Often asset-manifest.json is at root, but points to static/js/
        # which works fine with urljoin.
        # But checking for common prefixes helps.
        
        return urljoin(manifest_url, relative_path)

async def run_manifest_hunter(url: str) -> List[str]:
    """Runner function."""
    hunter = ManifestHunter()
    return await hunter.hunt(url)
