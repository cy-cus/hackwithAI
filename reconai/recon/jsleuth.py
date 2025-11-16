"""JSleuth - Discovers JavaScript files by opening domains/subdomains."""

import asyncio
import aiohttp
from typing import List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re


class JSleuth:
    """Discovers JavaScript file URLs by crawling domains/subdomains."""
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    async def discover_js_files(self, urls: List[str]) -> List[str]:
        """
        Discover JavaScript file URLs by opening domains/subdomains.
        
        Args:
            urls: List of domain/subdomain URLs to crawl
            
        Returns:
            List of discovered JavaScript file URLs
        """
        all_js_urls = set()
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            tasks = []
            for url in urls:
                # Ensure URL has scheme
                if not url.startswith(('http://', 'https://')):
                    # Try both
                    tasks.append(self._discover_from_url(session, f'https://{url}'))
                    tasks.append(self._discover_from_url(session, f'http://{url}'))
                else:
                    tasks.append(self._discover_from_url(session, url))
            
            # Process in batches
            for i in range(0, len(tasks), self.max_concurrent):
                batch = tasks[i:i + self.max_concurrent]
                results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, set):
                        all_js_urls.update(result)
        
        return sorted(list(all_js_urls))
    
    async def _discover_from_url(self, session: aiohttp.ClientSession, url: str) -> Set[str]:
        """Discover JS files from a single URL."""
        js_urls = set()
        
        try:
            headers = {'User-Agent': self.user_agent}
            
            async with session.get(url, headers=headers, ssl=False, allow_redirects=True) as response:
                if response.status != 200:
                    return js_urls
                
                # Check if content is HTML
                content_type = response.headers.get('Content-Type', '')
                if 'html' not in content_type.lower():
                    return js_urls
                
                html = await response.text()
                base_url = str(response.url)
                
                # Extract JS file URLs
                js_urls = self._extract_js_urls(html, base_url)
        
        except Exception:
            pass
        
        return js_urls
    
    def _extract_js_urls(self, html: str, base_url: str) -> Set[str]:
        """Extract JavaScript file URLs from HTML."""
        js_urls = set()
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # 1. Script tags with src
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urljoin(base_url, src)
                
                # Only add if it's a JS file
                if self._is_js_url(full_url):
                    js_urls.add(full_url)
            
            # 2. Inline script references
            js_pattern = r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']'
            for match in re.finditer(js_pattern, html, re.IGNORECASE):
                js_url = match.group(1)
                full_url = urljoin(base_url, js_url)
                if self._is_js_url(full_url):
                    js_urls.add(full_url)
            
            # 3. Direct URLs
            url_pattern = r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?'
            for match in re.finditer(url_pattern, html, re.IGNORECASE):
                js_url = match.group(0)
                if self._is_js_url(js_url):
                    js_urls.add(js_url)
            
            # 4. Webpack/Next.js chunks
            chunk_pattern = r'["\']([A-Za-z0-9\-_]+\.chunk\.js)["\']'
            for match in re.finditer(chunk_pattern, html):
                chunk_file = match.group(1)
                full_url = urljoin(base_url, chunk_file)
                js_urls.add(full_url)
            
            # 5. Common patterns
            common_patterns = [
                r'["\']([/_]static/[^"\']+\.js)["\']',
                r'["\']([/_]assets/[^"\']+\.js)["\']',
                r'["\']([/_]js/[^"\']+\.js)["\']',
                r'["\']([/_]scripts/[^"\']+\.js)["\']',
            ]
            
            for pattern in common_patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    js_path = match.group(1)
                    full_url = urljoin(base_url, js_path)
                    if self._is_js_url(full_url):
                        js_urls.add(full_url)
        
        except Exception:
            pass
        
        return js_urls
    
    def _is_js_url(self, url: str) -> bool:
        """Check if URL is a valid JavaScript file."""
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Must end with .js or have .js?
            if not (path.endswith('.js') or '.js?' in path):
                return False
            
            # Ignore common false positives
            ignore_patterns = ['jquery', 'bootstrap', 'analytics', 'gtag']
            for pattern in ignore_patterns:
                if pattern in url.lower():
                    return False
            
            return True
        except:
            return False


def run_jsleuth(urls: List[str]) -> List[str]:
    """
    Synchronous wrapper for JSleuth.
    
    Args:
        urls: List of domain/subdomain URLs to discover JS from
        
    Returns:
        List of discovered JavaScript file URLs
    """
    if not urls:
        return []
    
    sleuth = JSleuth()
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(sleuth.discover_js_files(urls))
        loop.close()
        return results
    except Exception as e:
        print(f"JSleuth error: {e}")
        return []
