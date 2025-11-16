"""Playwright-based JavaScript discovery - captures JS files from fully rendered pages."""

import asyncio
from typing import List, Set
from urllib.parse import urlparse
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout


class PlaywrightJSCollector:
    """Discovers JavaScript files using a headless browser to capture dynamically loaded scripts."""
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 3):
        """
        Initialize Playwright JS collector.
        
        Args:
            timeout: Page load timeout in seconds
            max_concurrent: Maximum concurrent browser contexts
        """
        self.timeout = timeout * 1000  # Convert to milliseconds
        self.max_concurrent = max_concurrent
    
    async def discover_js_files(self, urls: List[str]) -> List[str]:
        """
        Discover JavaScript files by rendering pages with Playwright.
        
        Args:
            urls: List of URLs to visit
            
        Returns:
            List of discovered JavaScript file URLs
        """
        all_js_urls = set()
        
        async with async_playwright() as p:
            # Launch headless browser (Chromium is most compatible)
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox'
                ]
            )
            
            try:
                # Process URLs in batches to limit resource usage
                for i in range(0, len(urls), self.max_concurrent):
                    batch = urls[i:i + self.max_concurrent]
                    tasks = [self._discover_from_url(browser, url) for url in batch]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for result in results:
                        if isinstance(result, set):
                            all_js_urls.update(result)
            finally:
                await browser.close()
        
        return sorted(list(all_js_urls))
    
    async def _discover_from_url(self, browser, url: str) -> Set[str]:
        """Discover JS files from a single URL using Playwright."""
        js_urls = set()
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        context = None
        page = None
        
        try:
            # Create a new context (isolated session)
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                viewport={'width': 1920, 'height': 1080},
                ignore_https_errors=True
            )
            
            page = await context.new_page()
            
            # Track network requests for .js files
            js_requests = set()
            
            async def handle_request(request):
                req_url = request.url
                if req_url.endswith('.js') or '.js?' in req_url:
                    js_requests.add(req_url)
            
            page.on('request', handle_request)
            
            # Navigate and wait for network to be idle
            try:
                await page.goto(
                    url,
                    wait_until='networkidle',
                    timeout=self.timeout
                )
            except PlaywrightTimeout:
                # If timeout, try with domcontentloaded instead
                await page.goto(
                    url,
                    wait_until='domcontentloaded',
                    timeout=self.timeout
                )
                # Give it a moment for async scripts
                await asyncio.sleep(2)
            
            # Extract JS files from DOM (after JS execution)
            script_srcs = await page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(script => script.src)
                        .filter(src => src && (src.endsWith('.js') || src.includes('.js?')));
                }
            """)
            
            # Combine network requests and DOM scripts
            js_urls.update(script_srcs)
            js_urls.update(js_requests)
            
            # Filter out common libraries if needed
            js_urls = {url for url in js_urls if self._is_valid_js_url(url)}
            
        except Exception as e:
            print(f"  [!] Playwright error for {url}: {e}")
        
        finally:
            # Clean up resources
            if page:
                await page.close()
            if context:
                await context.close()
        
        return js_urls
    
    def _is_valid_js_url(self, url: str) -> bool:
        """Check if URL is a valid JavaScript file."""
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Must be a JS file
            if not (path.endswith('.js') or '.js?' in path):
                return False
            
            # Filter out data URIs and blob URLs
            if url.startswith(('data:', 'blob:')):
                return False
            
            return True
        except:
            return False


def run_playwright_js(urls: List[str]) -> List[str]:
    """
    Synchronous wrapper for PlaywrightJSCollector.
    
    Args:
        urls: List of URLs to discover JS from
        
    Returns:
        List of discovered JavaScript file URLs
    """
    if not urls:
        return []
    
    collector = PlaywrightJSCollector()
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(collector.discover_js_files(urls))
        loop.close()
        return results
    except Exception as e:
        print(f"  [!] Playwright JS discovery error: {e}")
        return []
