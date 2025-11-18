"""Enhanced JSleuth - Comprehensive JS discovery and extraction using Playwright."""

import asyncio
import re
from typing import List, Dict, Set, Any
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout


# Common CDN and analytics domains to ignore
IGNORE_HOSTS = {
    "w3.org", "reactjs.org", "googleapis.com", "googletagmanager.com",
    "schema.org", "wikipedia.org", "googleadservices.com", "doubleclick.net",
    "cdnjs.cloudflare.com", "use.typekit.net", "react.dev", "hubspot.com",
    "hs-analytics.net", "cloudfront.net", "gstatic.com", "fonts.googleapis.com",
    "ajax.googleapis.com", "cdn.jsdelivr.net", "bootstrapcdn.com", "jsdelivr.net",
    "stackpathcdn.com", "optimizely.com", "akamai.net", "akamaihd.net",
    "google-analytics.com", "googlesyndication.com", "adsafeprotected.com",
    "cloudflare.com", "ytimg.com", "pixel.wp.com", "cdn.optimizely.com",
    "cdn.segment.com", "d3js.org", "fastly.net", "googletagservices.com",
    "ads-twitter.com", "googleusercontent.com", "tiktokcdn.com", "fbcdn.net",
    "twimg.com", "fbsbx.com", "cdn.ampproject.org", "azureedge.net"
}

# Regex patterns
REGEX_LINKS = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
REGEX_ENDPOINTS = re.compile(r'/[A-Za-z0-9_\-\/\.?=&]{3,}', re.IGNORECASE)
REGEX_IMPORTS = re.compile(
    r'(?:import\s+.*?from\s+[\'"]([^\'"]+)[\'"]|require\([\'"]([^\'"]+)[\'"]\))',
    re.IGNORECASE
)


def should_ignore(url: str) -> bool:
    """Check if URL should be ignored based on common CDN/analytics hosts."""
    try:
        parsed = urlparse(url)
        return any(host in parsed.hostname for host in IGNORE_HOSTS if parsed.hostname)
    except:
        return False


class JSleuthEnhanced:
    """Enhanced JS discovery using Playwright with comprehensive extraction."""
    
    def __init__(self, timeout: int = 45, max_concurrent: int = 5, max_links_per_page: int = None, allowed_domains: List[str] = None):
        self.timeout = timeout * 1000
        self.max_concurrent = max_concurrent
        self.max_links_per_page = max_links_per_page  # None = unlimited
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.visited_urls = set()  # Track visited URLs to avoid loops
        self.allowed_domains = set(allowed_domains or [])

    def _is_allowed_host(self, host: str, fallback_host: str = None) -> bool:
        """Check whether a hostname is within the allowed set or matches fallback host when unset."""
        if not host:
            return False
        host = host.lower()
        if self.allowed_domains:
            for domain in self.allowed_domains:
                domain = domain.lower()
                if host == domain or host.endswith('.' + domain):
                    return True
            return False
        if fallback_host:
            fallback = fallback_host.lower()
            return host == fallback
        return True

    def _is_allowed_url(self, url: str, fallback_host: str = None) -> bool:
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ''
            if not host:
                return True  # relative URLs belong to current host
            return self._is_allowed_host(host, fallback_host)
        except Exception:
            return False
    
    async def discover_from_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Discover JS files and extract endpoints, links from multiple URLs.
        
        Returns:
            Dict with keys: js_files, endpoints, links, modules, raw_files
        """
        all_results = {
            'js_files': set(),
            'endpoints': set(),
            'links': set(),
            'modules': set(),
            'raw_files': {},
            'endpoint_sources': {},
            'link_sources': {}
        }
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox'
                ]
            )
            
            try:
                # Process all URLs in batches
                total_urls = len(urls)
                print(f"  [*] Processing {total_urls} URLs in batches of {self.max_concurrent}...")
                
                for i in range(0, len(urls), self.max_concurrent):
                    batch = urls[i:i + self.max_concurrent]
                    batch_num = (i // self.max_concurrent) + 1
                    total_batches = (total_urls + self.max_concurrent - 1) // self.max_concurrent
                    print(f"  [*] Processing batch {batch_num}/{total_batches}...")
                    
                    tasks = [self._extract_from_page(browser, url) for url in batch]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for result in results:
                        if isinstance(result, dict):
                            all_results['js_files'].update(result.get('js_files', []))
                            all_results['endpoints'].update(result.get('endpoints', []))
                            all_results['links'].update(result.get('links', []))
                            all_results['modules'].update(result.get('modules', []))
                            all_results['raw_files'].update(result.get('raw_files', {}))
                            all_results['endpoint_sources'].update(result.get('endpoint_sources', {}))
                            all_results['link_sources'].update(result.get('link_sources', {}))
            finally:
                await browser.close()
        
        # Convert sets to lists for JSON serialization
        final_results = {
            'js_files': sorted(list(all_results['js_files'])),
            'endpoints': sorted(list(all_results['endpoints'])),
            'links': sorted(list(all_results['links'])),
            'modules': sorted(list(all_results['modules'])),
            'raw_files': all_results['raw_files'],
            'endpoint_sources': all_results['endpoint_sources'],
            'link_sources': all_results['link_sources']
        }
        
        # Print comprehensive summary
        print(f"\n  [✓] JSleuth Enhanced Summary:")
        print(f"      • Total URLs processed: {len(urls)}")
        print(f"      • Total unique URLs visited (including links): {len(self.visited_urls)}")
        print(f"      • JS files discovered: {len(final_results['js_files'])}")
        print(f"      • Endpoints extracted: {len(final_results['endpoints'])}")
        print(f"      • Links found: {len(final_results['links'])}")
        print(f"      • Modules identified: {len(final_results['modules'])}")
        print(f"      • Raw files captured: {len(final_results['raw_files'])}\n")
        
        return final_results
    
    async def _extract_from_page(self, browser, url: str) -> Dict[str, Any]:
        """Extract comprehensive data from a single page."""
        results = {
            'js_files': set(),
            'endpoints': set(),
            'links': set(),
            'modules': set(),
            'raw_files': {},
            'endpoint_sources': {},  # {endpoint: source}
            'link_sources': {}  # {link: source}
        }
        
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        parsed_url = urlparse(url)
        base_host = parsed_url.hostname or ''
        if not self._is_allowed_host(base_host):
            print(f"    [!] Skipping {url} (outside allowed domains)")
            return results

        context = None
        page = None
        
        try:
            context = await browser.new_context(
                user_agent=self.user_agent,
                viewport={'width': 1920, 'height': 1080},
                ignore_https_errors=True
            )
            
            page = await context.new_page()
            
            # Track network JS requests
            js_requests = set()
            
            async def handle_request(request):
                req_url = request.url
                resource_type = request.resource_type
                
                # Capture scripts by type or extension
                if resource_type == 'script' or req_url.endswith('.js') or '.js?' in req_url:
                    if not should_ignore(req_url) and self._is_allowed_url(req_url, base_host):
                        js_requests.add(req_url)
            
            page.on('request', handle_request)
            
            # Navigate to page
            try:
                await page.goto(url, wait_until='networkidle', timeout=self.timeout)
            except PlaywrightTimeout:
                await page.goto(url, wait_until='domcontentloaded', timeout=self.timeout)
                await asyncio.sleep(2)
            
            # Mark as visited
            self.visited_urls.add(url)
            
            # Scroll to trigger lazy-loaded scripts
            await self._scroll_page(page)
            
            # Hover over navigation elements to trigger dropdown menus
            await self._trigger_hovers(page)
            
            # Wait a bit for any delayed script loads
            await asyncio.sleep(2)
            
            # Extract script content from DOM
            script_data = await page.evaluate("""
                () => {
                    const scripts = Array.from(document.scripts);
                    const data = { inline: [], external: [] };
                    
                    scripts.forEach((script, index) => {
                        const src = script.src?.trim();
                        const content = script.textContent?.trim();
                        
                        if (src) {
                            data.external.push(src);
                        } else if (content) {
                            data.inline.push({ id: `inline#${index}`, content });
                        }
                    });
                    
                    return data;
                }
            """)
            
            # Store inline scripts
            for inline_script in script_data.get('inline', []):
                script_id = inline_script['id']
                content = inline_script['content']
                if content:
                    results['raw_files'][script_id] = content
                    self._extract_from_content(content, url, script_id, results)
            
            # Collect external script URLs
            external_scripts = script_data.get('external', [])
            for src in external_scripts:
                if src and not should_ignore(src) and self._is_allowed_url(src, base_host):
                    results['js_files'].add(src)
                    # Try to fetch and analyze content
                    try:
                        content = await page.evaluate(f"""
                            async () => {{
                                try {{
                                    const resp = await fetch('{src}');
                                    if (resp.ok) return await resp.text();
                                }} catch (e) {{}}
                                return null;
                            }}
                        """)
                        if content:
                            results['raw_files'][src] = content
                            script_name = src.split('/')[-1].split('?')[0] or src
                            self._extract_from_content(content, url, script_name, results)
                    except:
                        pass
            
            # Add network-captured JS files
            for js_url in js_requests:
                if self._is_allowed_url(js_url, base_host):
                    results['js_files'].add(js_url)

            # LINK WALKER: Navigate to internal links to trigger route-specific JS
            await self._walk_links(page, url, base_host, results, js_requests)
            
        except Exception as e:
            print(f"  [!] JSleuth enhanced error for {url}: {e}")
        
        finally:
            if page:
                await page.close()
            if context:
                await context.close()
        
        return results
    
    async def _walk_links(self, page, base_url: str, base_host: str, results: Dict, js_requests: Set):
        """Walk internal links to trigger SPA route changes and capture JS chunks."""
        try:
            # Extract internal links from the page
            internal_links = await page.evaluate("""
                () => {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    const internal = [];
                    
                    for (const link of links) {
                        try {
                            const href = link.getAttribute('href');
                            if (!href) continue;
                            
                            // Skip anchors, javascript:, mailto:, tel:, etc.
                            if (href.startsWith('#') || href.startsWith('javascript:') || 
                                href.startsWith('mailto:') || href.startsWith('tel:')) {
                                continue;
                            }
                            
                            // Resolve relative URLs
                            const fullUrl = new URL(href, location.href).href;
                            internal.push(fullUrl);
                        } catch (e) {}
                    }
                    
                    // Deduplicate and limit
                    return [...new Set(internal)];
                }
            """)
            
            if not internal_links:
                return
            
            # Filter to allowed domains
            filtered_links = []
            for link in internal_links:
                try:
                    link_host = urlparse(link).hostname or ''
                    if self._is_allowed_host(link_host, base_host):
                        filtered_links.append(link)
                except Exception:
                    continue
            internal_links = filtered_links
            if not internal_links:
                return
            
            # Prioritize important routes
            priority_keywords = [
                '/pricing', '/features', '/docs', '/api', '/products', 
                '/solutions', '/services', '/dashboard', '/app', '/beta',
                '/demo', '/platform', '/tools', '/resources', '/blog',
                '/case-studies', '/customers'
            ]
            
            # Sort links: priority routes first, then others
            def link_priority(url):
                url_lower = url.lower()
                for idx, keyword in enumerate(priority_keywords):
                    if keyword in url_lower:
                        return idx
                return len(priority_keywords)
            
            sorted_links = sorted(internal_links, key=link_priority)
            
            # Collect all unvisited links (no arbitrary limit)
            links_to_visit = []
            for link in sorted_links:
                if link not in self.visited_urls:
                    links_to_visit.append(link)
                    # Apply limit only if configured
                    if self.max_links_per_page and len(links_to_visit) >= self.max_links_per_page:
                        break
            
            if not links_to_visit:
                return
            
            total_links = len(links_to_visit)
            print(f"    [*] Walking {total_links} internal links from {base_url}...")
            
            # Track JS before navigation
            js_before = set(js_requests)
            
            for idx, link in enumerate(links_to_visit, 1):
                try:
                    print(f"      [{idx}/{total_links}] Visiting {link}...")
                    
                    # Mark as visited
                    self.visited_urls.add(link)
                    
                    # Try SPA navigation first (faster for frameworks like Next.js)
                    spa_navigated = await page.evaluate(f"""
                        async () => {{
                            try {{
                                // Try Next.js router
                                if (window.next?.router?.push) {{
                                    await window.next.router.push('{link}');
                                    return true;
                                }}
                                
                                // Try React Router
                                if (window.__REACT_ROUTER_CONTEXT__) {{
                                    const event = new PopStateEvent('popstate');
                                    window.history.pushState({{}}, '', '{link}');
                                    window.dispatchEvent(event);
                                    return true;
                                }}
                                
                                // Try programmatic click
                                const linkEl = document.querySelector(`a[href="{link}"]`);
                                if (linkEl) {{
                                    linkEl.click();
                                    return true;
                                }}
                            }} catch (e) {{}}
                            return false;
                        }}
                    """)
                    
                    if spa_navigated:
                        # Wait for SPA navigation to complete
                        await asyncio.sleep(1.5)
                        # Wait for any network activity to settle
                        try:
                            await page.wait_for_load_state('networkidle', timeout=5000)
                        except:
                            await asyncio.sleep(1)
                    else:
                        # Fall back to full navigation
                        try:
                            await page.goto(link, wait_until='networkidle', timeout=self.timeout)
                        except PlaywrightTimeout:
                            await page.goto(link, wait_until='domcontentloaded', timeout=self.timeout)
                            await asyncio.sleep(2)
                    
                    # Check for new JS files loaded by this route
                    js_after = set(js_requests)
                    new_js = js_after - js_before
                    if new_js:
                        print(f"      [+] Route {link} loaded {len(new_js)} new JS files")
                        for js_url in new_js:
                            if self._is_allowed_url(js_url, base_host):
                                results['js_files'].add(js_url)
                    
                    js_before = js_after
                    
                except Exception as e:
                    print(f"      [!] Failed to navigate to {link}: {e}")
                    continue
            
            # Try to go back to original page
            try:
                await page.goto(base_url, wait_until='domcontentloaded', timeout=10000)
            except:
                pass
                
        except Exception as e:
            print(f"    [!] Link walker error: {e}")
    
    async def _scroll_page(self, page):
        """Scroll through page to trigger lazy-loaded content and scripts."""
        try:
            await page.evaluate("""
                async () => {
                    // Scroll to bottom in steps
                    const distance = 100;
                    const delay = 100;
                    
                    while (document.scrollingElement.scrollTop + window.innerHeight < document.scrollingElement.scrollHeight) {
                        document.scrollingElement.scrollBy(0, distance);
                        await new Promise(resolve => setTimeout(resolve, delay));
                    }
                    
                    // Scroll back to top
                    window.scrollTo(0, 0);
                }
            """)
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"    [!] Scroll error: {e}")
    
    async def _trigger_hovers(self, page):
        """Hover over interactive elements to trigger dropdowns, tooltips, and modals."""
        try:
            # Find and hover over navigation items, buttons, and menu triggers
            hover_targets = await page.query_selector_all(
                'nav a, nav button, [role="menuitem"], [role="button"], '
                '.nav-item, .menu-item, .dropdown-toggle, [data-toggle], '
                'header a, header button'
            )
            
            # Hover over all interactive elements to trigger all possible JS
            for target in hover_targets:
                try:
                    await target.hover(timeout=1000)
                    await asyncio.sleep(0.3)  # Wait for dropdown/modal to appear
                except:
                    continue
                    
        except Exception as e:
            print(f"    [!] Hover trigger error: {e}")
    
    def _extract_from_content(self, content: str, page_url: str, script_id: str, results: Dict):
        """Extract links, endpoints, modules from JS content with source tracking.
        
        Args:
            content: JS content to extract from
            page_url: The page URL where this script was found
            script_id: Identifier like 'inline#0' or 'webpack-abc123.js'
            results: Results dict to update
        """
        if not content:
            return
        
        # Extract full URLs (links)
        link_matches = list(REGEX_LINKS.finditer(content))
        for match in link_matches:
            url = match.group(0)
            if not should_ignore(url):
                results['links'].add(url)
                # Track source
                if url not in results['link_sources']:
                    results['link_sources'][url] = []
                results['link_sources'][url].append(script_id)
        
        # Extract endpoints and JS files from paths
        endpoint_matches = list(REGEX_ENDPOINTS.finditer(content))
        for match in endpoint_matches:
            path = match.group(0)
            if should_ignore(path):
                continue
            
            if path.endswith('.js') or '.js?' in path:
                # Try to resolve relative paths
                if not path.startswith('http'):
                    try:
                        full_url = urljoin(page_url, path)
                        results['js_files'].add(full_url)
                    except:
                        results['js_files'].add(path)
                else:
                    results['js_files'].add(path)
            else:
                results['endpoints'].add(path)
                # Track source with match count
                if path not in results['endpoint_sources']:
                    results['endpoint_sources'][path] = []
                results['endpoint_sources'][path].append(script_id)
        
        # Extract module imports
        for match in REGEX_IMPORTS.finditer(content):
            module = match.group(1) or match.group(2)
            if module and not should_ignore(module):
                results['modules'].add(module)


def run_jsleuth_enhanced(urls: List[str], allowed_domains: List[str] = None) -> Dict[str, Any]:
    """
    Synchronous wrapper for enhanced JSleuth.
    
    Args:
        urls: List of URLs to crawl
        allowed_domains: List of domains to restrict crawling to (e.g., ['example.com'])
    
    Returns:
        Dict with js_files, endpoints, links, modules, sources
    """
    if not urls:
        return {
            'js_files': [],
            'endpoints': [],
            'links': [],
            'modules': [],
            'raw_files': {},
            'endpoint_sources': {},
            'link_sources': {}
        }
    
    sleuth = JSleuthEnhanced(allowed_domains=allowed_domains)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(sleuth.discover_from_urls(urls))
        loop.close()
        return results
    except Exception as e:
        print(f"JSleuth enhanced error: {e}")
        return {
            'js_files': [],
            'endpoints': [],
            'links': [],
            'modules': [],
            'raw_files': {},
            'endpoint_sources': {},
            'link_sources': {}
        }
