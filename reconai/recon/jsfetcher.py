"""JavaScript file fetcher and analyzer - extracts all JS from domains."""

import asyncio
import aiohttp
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
import re
from datetime import datetime
from bs4 import BeautifulSoup

from reconai.models import Endpoint


class JSFetcher:
    """Fetch and extract JavaScript files from domains."""
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    async def fetch_js_files(self, js_urls: List[str], progress_callback=None) -> List[Dict]:
        """
        Fetch JavaScript file content from given URLs.
        
        Args:
            js_urls: List of JavaScript file URLs to fetch
            progress_callback: Optional callback(current, total, filename) for progress updates
            
        Returns:
            List of JS file data with content and metadata
        """
        results = []
        total_files = len(js_urls)
        current_count = 0
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            # Process in batches to avoid overwhelming
            for i in range(0, len(js_urls), self.max_concurrent):
                batch_urls = js_urls[i:i + self.max_concurrent]
                tasks = [self._fetch_js_content(session, url) for url in batch_urls]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for j, result in enumerate(batch_results):
                    current_count += 1
                    current_url = batch_urls[j]
                    
                    # Extract filename from URL
                    filename = current_url.split('/')[-1].split('?')[0]
                    if len(filename) > 50:
                        filename = filename[:47] + "..."
                    
                    # Call progress callback
                    if progress_callback:
                        progress_callback(current_count, total_files, filename)
                    
                    if isinstance(result, dict) and result:
                        results.append(result)
        
        return results
    
    async def _fetch_url_js(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Fetch JS files from a single URL."""
        js_files = []
        
        try:
            headers = {'User-Agent': self.user_agent}
            
            async with session.get(url, headers=headers, ssl=False) as response:
                if response.status != 200:
                    return js_files
                
                html = await response.text()
                base_url = str(response.url)
                
                # Extract JS file URLs
                js_urls = self._extract_js_urls(html, base_url)
                
                # Fetch each JS file
                for js_url in js_urls:
                    js_data = await self._fetch_js_content(session, js_url, base_url)
                    if js_data:
                        js_files.append(js_data)
        
        except Exception as e:
            print(f"  Error fetching {url}: {e}")
        
        return js_files
    
    def _extract_js_urls(self, html: str, base_url: str) -> Set[str]:
        """Extract JavaScript file URLs from HTML."""
        js_urls = set()
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find all script tags with src
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urljoin(base_url, src)
                
                # Only add .js files
                if full_url.endswith('.js') or '.js?' in full_url:
                    js_urls.add(full_url)
            
            # Also check for inline script references
            js_pattern = r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?'
            for match in re.finditer(js_pattern, html, re.IGNORECASE):
                js_urls.add(match.group(0))
            
            # Webpack/Next.js chunks
            chunk_pattern = r'["\']([A-Za-z0-9\-_]+\.chunk\.js)["\']'
            for match in re.finditer(chunk_pattern, html):
                chunk_url = urljoin(base_url, match.group(1))
                js_urls.add(chunk_url)
        
        except Exception as e:
            print(f"  Error parsing HTML: {e}")
        
        return js_urls
    
    async def _fetch_js_content(self, session: aiohttp.ClientSession, js_url: str) -> Dict:
        """Fetch JavaScript file content."""
        try:
            headers = {
                'User-Agent': self.user_agent
            }
            
            async with session.get(js_url, headers=headers, ssl=False, allow_redirects=True) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                
                # Only store if reasonable size (< 5MB)
                if len(content) > 5 * 1024 * 1024:
                    content = content[:5 * 1024 * 1024] + "\n[TRUNCATED]"
                
                return {
                    'url': js_url,
                    'content': content,
                    'size': len(content),
                    'source': js_url,
                    'timestamp': datetime.now().isoformat()
                }
        
        except Exception:
            return None


def run_jsfetcher(js_urls: List[str], progress_callback=None) -> List[Dict]:
    """
    Synchronous wrapper for JSFetcher.
    
    Args:
        js_urls: List of JavaScript file URLs to fetch content from
        progress_callback: Optional callback(current, total, filename) for progress updates
        
    Returns:
        List of JS file data with content
    """
    if not js_urls:
        return []
    
    fetcher = JSFetcher()
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(fetcher.fetch_js_files(js_urls, progress_callback))
        loop.close()
        return results
    except Exception as e:
        print(f"JSFetcher error: {e}")
        return []
