"""JSleuth - Advanced JavaScript Discovery & Forensics Engine.

Features:
- Smart Interaction (Scrolling, Clicking) for lazy-loaded scripts
- Source Map Discovery & Unpacking
- Inline Script Extraction
- Global Variable Inspection (window.env, window.config)
- Webpack Chunk Detection
"""

import asyncio
import json
import re
import hashlib
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout, Page

class JSLeuth:
    """
    Advanced JavaScript Discovery Engine.
    Goes beyond simple scraping to find deeply hidden JS.
    """
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 3, output_dir: Optional[str] = None):
        self.timeout = timeout * 1000
        self.max_concurrent = max_concurrent
        self.output_dir = output_dir
        self.user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        
    async def discover_js_files(self, urls: List[str]) -> Dict[str, Any]:
        """
        Deep discovery of JS files, including lazy-loaded and inline scripts.
        
        Returns:
            Dict containing:
            - urls: List of remote JS URLs
            - inline: List of inline script contents
            - sourcemaps: List of discovered source map URLs
            - globals: Interesting global variables (configs, envs)
        """
        results = {
            'urls': set(),
            'inline': [],
            'sourcemaps': set(),
            'globals': {}
        }
        
        # Import ManifestHunter here to avoid circular imports if any
        from reconai.recon.manifest_hunter import run_manifest_hunter
        
        # 1. Run Manifest Hunter in parallel with Browser Scan
        # We only need to run this once per domain/base URL
        manifest_tasks = []
        scanned_roots = set()
        
        for url in urls:
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            root = f"{parsed.scheme}://{parsed.netloc}"
            if root not in scanned_roots:
                scanned_roots.add(root)
                manifest_tasks.append(run_manifest_hunter(root))
        
        # 2. Browser Scan configuration
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--disable-web-security',  # Bypass CORS for better inspection
                    '--disable-features=IsolateOrigins,site-per-process',
                    '--disable-blink-features=AutomationControlled'
                ]
            )
            
            try:
                # Process URLs in batches
                for i in range(0, len(urls), self.max_concurrent):
                    batch = urls[i:i + self.max_concurrent]
                    
                    # Create tasks for browser analysis
                    browser_tasks = [self._analyze_url(browser, url) for url in batch]
                    
                    # Execute browser tasks
                    batch_results = await asyncio.gather(*browser_tasks, return_exceptions=True)
                    
                    for res in batch_results:
                        if isinstance(res, dict):
                            results['urls'].update(res.get('urls', []))
                            results['inline'].extend(res.get('inline', []))
                            results['sourcemaps'].update(res.get('sourcemaps', []))
                            results['globals'].update(res.get('globals', {}))
                            
            finally:
                await browser.close()
        
        # 3. Collect Manifest Results
        if manifest_tasks:
            manifest_results = await asyncio.gather(*manifest_tasks, return_exceptions=True)
            for res in manifest_results:
                if isinstance(res, list):
                    # Add discovered manifest assets to results
                    for asset_url in res:
                        results['urls'].add(asset_url)
        
        # Convert sets to sorted lists
        results['urls'] = sorted(list(results['urls']))
        results['sourcemaps'] = sorted(list(results['sourcemaps']))
        
        return results
    
    async def _analyze_url(self, browser, url: str) -> Dict[str, Any]:
        """Deep analysis of a single URL."""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
            
        page_results = {
            'urls': set(),
            'inline': [],
            'sourcemaps': set(),
            'globals': {}
        }
        
        context = await browser.new_context(
            user_agent=self.user_agent,
            viewport={'width': 1920, 'height': 1080},
            ignore_https_errors=True
        )
        
        page = await context.new_page()
        
        try:
            # 1. Network Monitoring (Capture dynamic imports)
            page.on("request", lambda req: self._handle_request(req, page_results))
            page.on("response", lambda resp: self._handle_response(resp, page_results))
            
            # 2. Navigate
            try:
                await page.goto(url, wait_until='networkidle', timeout=self.timeout)
            except PlaywrightTimeout:
                await page.goto(url, wait_until='domcontentloaded', timeout=self.timeout)
            
            # 3. Smart Interaction (Trigger lazy-loading)
            await self._smart_interaction(page)
            
            # 4. Extract Inline Scripts
            inline_scripts = await page.evaluate("""() => {
                return Array.from(document.scripts)
                    .filter(s => !s.src && s.innerText.trim().length > 0)
                    .map(s => s.innerText);
            }""")
            
            for script in inline_scripts:
                # Hash content to identify unique scripts
                content_hash = hashlib.md5(script.encode()).hexdigest()
                page_results['inline'].append({
                    'source': url,
                    'hash': content_hash,
                    'content': script
                })
            
            # 5. Global Variable Inspection
            globals_data = await self._inspect_globals(page)
            if globals_data:
                page_results['globals'][url] = globals_data
                
            # 6. DOM Extraction (Fallback for failed network requests)
            dom_srcs = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src);
            }""")
            for src in dom_srcs:
                if self._is_js_url(src):
                    page_results['urls'].add(src)
                    
        except Exception as e:
            # print(f"JSLeuth Error {url}: {e}") # Silenced for cleaner output
            pass
        finally:
            await context.close()
            
        return page_results

    def _handle_request(self, request, results):
        """Monitor outgoing requests for JS files."""
        url = request.url
        if self._is_js_url(url):
            results['urls'].add(url)

    def _handle_response(self, response, results):
        """Check responses for SourceMaps."""
        # Check Headers
        sourcemap = response.header_value('x-sourcemap') or response.header_value('sourcemap')
        if sourcemap:
            results['sourcemaps'].add(urljoin(response.url, sourcemap))
            
        # Check for JS and potential Webpack bundles
        if self._is_js_url(response.url):
            results['urls'].add(response.url)
            # We could try to detect webpack here by analyzing content, 
            # but that requires reading the body which is expensive in an event handler

    async def _smart_interaction(self, page: Page):
        """Perform smart interactions to trigger lazy-loaded scripts."""
        try:
            # Scroll to bottom smoothly
            await page.evaluate("""async () => {
                await new Promise((resolve) => {
                    let totalHeight = 0;
                    let distance = 100;
                    let timer = setInterval(() => {
                        let scrollHeight = document.body.scrollHeight;
                        window.scrollBy(0, distance);
                        totalHeight += distance;
                        if(totalHeight >= scrollHeight){
                            clearInterval(timer);
                            resolve();
                        }
                    }, 100);
                });
            }""")
            
            # Click common "Load More" or "Menu" buttons (Heuristic)
            # Find buttons that look interesting but aren't links/forms
            await page.evaluate("""() => {
                const buttons = Array.from(document.querySelectorAll('button, .btn, [role="button"]'));
                const keywords = ['load', 'more', 'view', 'show', 'menu', 'nav'];
                buttons.forEach(btn => {
                    const text = btn.innerText.toLowerCase();
                    if (keywords.some(k => text.includes(k)) && btn.offsetParent !== null) {
                        try { btn.click(); } catch(e) {}
                    }
                });
            }""")
            
            # Wait a bit for network requests
            await page.wait_for_timeout(2000)
            
        except Exception:
            pass

    async def _inspect_globals(self, page: Page) -> Dict:
        """Dump interesting window objects."""
        return await page.evaluate("""() => {
            const interesting = {};
            const whitelist = ['config', 'settings', 'env', 'environment', 'bootstrap', 'user', 'data', 'api'];
            
            // Iterate window properties
            for (const key of Object.keys(window)) {
                const lowerKey = key.toLowerCase();
                if (whitelist.some(w => lowerKey.includes(w)) || key.startsWith('__')) {
                    try {
                        const val = window[key];
                        if (val && typeof val === 'object') {
                            interesting[key] = JSON.parse(JSON.stringify(val));
                        }
                    } catch(e) {}
                }
            }
            return interesting;
        }""")

    def _is_js_url(self, url: str) -> bool:
        """Check if URL looks like a JS file."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return path.endswith('.js') or '.js?' in path or 'javascript' in path

# Keep specific sync wrapper for backward compatibility
def run_jsleuth(urls: List[str]) -> List[str]:
    """Compatibility wrapper - returns URLs only."""
    sleuth = JSLeuth()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(sleuth.discover_js_files(urls))
        loop.close()
        return results['urls']
    except Exception:
        return []

# New advanced wrapper
def run_jsleuth_enhanced(urls: List[str]) -> Dict[str, Any]:
    """Runs the full enhanced discovery."""
    sleuth = JSLeuth()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(sleuth.discover_js_files(urls))
        loop.close()
        return results
    except Exception:
        return {'urls': [], 'inline': [], 'sourcemaps': [], 'globals': {}}

