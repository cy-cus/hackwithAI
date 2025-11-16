"""CLI interface for HackwithAI."""

import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import typer
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from reconai.models import AttackSurface, ScanConfig, Subdomain, Endpoint, JSFile
from reconai.recon import (
    run_subfinder, run_crtsh, run_httpx, run_katana, run_waybackurls,
    run_jsleuth, run_jsfetcher, analyze_js_files,
    run_manifest_hunter, SmartURLConstructor, analyze_application_logic
)
from reconai.llm import OllamaBackend
from reconai.analyzer import analyze_attack_surface
from reconai.reporting import (
    print_banner,
    print_scan_progress,
    print_attack_surface_summary,
    write_json_report,
    write_markdown_report
)

app = typer.Typer(help="HackwithAI - Local LLM-powered security reconnaissance")
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or domain (e.g., https://example.com)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory for results"),
    model: str = typer.Option("llama3.1:8b", "--model", "-m", help="Ollama model to use"),
    ollama_url: str = typer.Option("http://localhost:11434", "--ollama-url", help="Ollama API base URL"),
    skip_subfinder: bool = typer.Option(False, "--skip-subfinder", help="Skip subdomain discovery"),
    skip_httpx: bool = typer.Option(False, "--skip-httpx", help="Skip HTTP probing"),
    skip_katana: bool = typer.Option(False, "--skip-katana", help="Skip web crawling"),
    skip_waybackurls: bool = typer.Option(False, "--skip-waybackurls", help="Skip wayback URLs"),
    skip_js: bool = typer.Option(False, "--skip-js", help="Skip JavaScript fetching and analysis"),
    js_size: str = typer.Option(
        "medium",
        "--js-size",
        "-J",
        help="JavaScript analysis size: small (first 100 files), medium (first 1000), large/all (all files)",
    ),
    skip_llm: bool = typer.Option(False, "--skip-llm", help="Skip LLM analysis"),
    no_report: bool = typer.Option(False, "--no-report", help="Don't write reports to disk")
):
    """
    Run reconnaissance and LLM analysis on a target.
    
    Example:
        reconai scan https://example.com
        reconai scan example.com --model mistral-nemo:12b
        reconai scan https://target.com --output ./results
    """
    print_banner()
    
    # Parse target - accept both example.com and https://example.com
    if target.startswith(('http://', 'https://')):
        target_url = target
        parsed = urlparse(target)
        domain = parsed.netloc
    else:
        # Just a domain
        domain = target
        target_url = f"https://{domain}"
    
    # Setup output directory
    if output:
        output_dir = Path(output)
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = Path(f"./output/{domain.replace('.', '_')}_{timestamp}")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    console.print(f"\n🎯 Target: [bold cyan]{domain}[/bold cyan]")
    console.print(f"📁 Output: [bold]{output_dir}[/bold]")
    console.print(f"\nStarting scan: {target_url}")
    console.print(f"Output directory: {output_dir}\n")
    
    # Initialize attack surface
    attack_surface = AttackSurface(
        target_domain=domain,
        scan_start=datetime.now()
    )
    
    all_endpoints = []
    all_parameters = []
    
    # Create progress bar
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    )
    
    # 1. Subdomain Discovery
    if not skip_subfinder:
        with progress:
            task = progress.add_task("[cyan]Subdomain Discovery", total=100)
            progress.update(task, advance=30, description="[cyan]Running subfinder...")
        
        # Run subfinder
            subfinder_subs = run_subfinder(domain)
            progress.update(task, advance=30, description="[cyan]Subfinder complete")
            console.print(f"  [+] Subfinder: {len(subfinder_subs)} subdomains")
            progress.update(task, advance=20, description="[cyan]Running crt.sh...")
        
        # Run crt.sh
            crtsh_subs = run_crtsh(domain)
            progress.update(task, advance=20, description="[cyan]crt.sh complete")
            console.print(f"  [+] crt.sh: {len(crtsh_subs)} subdomains")
        
        # Merge and deduplicate
        all_subs = subfinder_subs + crtsh_subs
        seen = set()
        unique_subs = []
        for sub in all_subs:
            if sub.host not in seen:
                seen.add(sub.host)
                unique_subs.append(sub)
        
        attack_surface.subdomains = unique_subs
        attack_surface.total_subdomains = len(unique_subs)
        console.print(f"  [+] Total unique: {len(unique_subs)} subdomains\n")
    else:
        # If skipping, just use the target domain
        attack_surface.subdomains = [Subdomain(host=domain, source="manual")]
        attack_surface.total_subdomains = 1
    
    # 2. Httpx - HTTP probing
    if not skip_httpx:
        print_scan_progress("Running httpx (HTTP probing)...", "[*]")
        subdomain_hosts = [s.host for s in attack_surface.subdomains]
        if not subdomain_hosts:
            subdomain_hosts = [domain]
        
        httpx_endpoints = run_httpx(subdomain_hosts)
        all_endpoints.extend(httpx_endpoints)
        
        # Count alive hosts
        alive_hosts = set(urlparse(e.url).netloc for e in httpx_endpoints if e.status_code and e.status_code < 500)
        attack_surface.alive_hosts = len(alive_hosts)
        
        console.print(f"  [+] Found {len(httpx_endpoints)} alive endpoints\n")
    
    # 3. Katana - web crawling
    if not skip_katana:
        print_scan_progress("Running katana (web crawling)...", "[*]")
        katana_endpoints, katana_params = run_katana(target_url)
        all_endpoints.extend(katana_endpoints)
        all_parameters.extend(katana_params)
        console.print(f"  [+] Crawled {len(katana_endpoints)} URLs, found {len(katana_params)} parameters\n")
    
    # 4. Waybackurls - ALL historical URLs
    if not skip_waybackurls:
        print_scan_progress("Running waybackurls (historical data)...", "[*]")
        wayback_endpoints, wayback_params = run_waybackurls(domain)
        all_endpoints.extend(wayback_endpoints)
        all_parameters.extend(wayback_params)
        console.print(f"  [+] Found {len(wayback_endpoints)} historical URLs\n")
    
    # 5. JavaScript Discovery and Analysis
    all_js_urls = []
    if not skip_js:
        print_scan_progress("Discovering and analyzing JavaScript files...", "[*]")
        
        # Step 1: JSleuth - Discover JS files by opening alive domains/subdomains
        console.print(f"  [*] JSleuth: Opening domains to discover JS files...")
        alive_urls = list(set([e.url for e in all_endpoints if e.status_code and e.status_code < 500]))[:30]  # Limit to 30 alive URLs
        
        if alive_urls:
            jsleuth_urls = run_jsleuth(alive_urls)
            console.print(f"  [+] JSleuth discovered {len(jsleuth_urls)} JS files")
            all_js_urls.extend(jsleuth_urls)
        
        # Step 2: Extract JS URLs from all discovered endpoints (wayback, katana, httpx)
        console.print(f"  [*] Filtering JS files from all discovered URLs...")
        for endpoint in all_endpoints:
            url = endpoint.url.lower()
            if url.endswith('.js') or '.js?' in url:
                all_js_urls.append(endpoint.url)
        
        # Step 3: Deduplicate JS URLs
        all_js_urls = list(set(all_js_urls))
        console.print(f"  [+] Total unique JS files found: {len(all_js_urls)}")

        # Apply js_size limit
        size_key = (js_size or "medium").lower()
        if size_key == "small":
            max_js = 100
        elif size_key == "medium":
            max_js = 1000
        else:  # "large" or anything else
            max_js = len(all_js_urls)

        limited_js_urls = all_js_urls[:max_js]
        console.print(f"  [*] JS size mode: {size_key} → analyzing up to {max_js} files")
        
        if limited_js_urls:
            console.print(f"  [*] Fetching JS content (max {len(limited_js_urls)} files)...\n")
            
            # Progress callback for file-by-file updates
            def js_progress(current, total, filename):
                console.print(f"  [*] Fetching {filename} ({current}/{total})")
            
            # Step 4: JSFetcher - Fetch actual JS content from limited URLs
            js_files = run_jsfetcher(limited_js_urls, js_progress)
            attack_surface.js_files = [JSFile(**jf) for jf in js_files]
            attack_surface.total_js_files = len(js_files)
            
            if js_files:
                console.print(f"  [+] Successfully fetched {len(js_files)} JS files")
                console.print(f"  [*] JS Analyzer: Scanning content for secrets and endpoints...\n")
                
                # Step 5: JS Analyzer - Scan JS content for secrets/endpoints/patterns
                js_analysis_result = analyze_js_files(js_files)
                from reconai.models import JSAnalysis, Secret as SecretModel
                
                # Convert secrets
                secrets = [SecretModel(**s.__dict__) for s in js_analysis_result.get('secrets', [])]
                
                attack_surface.js_analysis = JSAnalysis(
                    endpoints=js_analysis_result.get('endpoints', []),
                    secrets=secrets,
                    links=js_analysis_result.get('links', []),
                    modules=js_analysis_result.get('modules', []),
                    interesting_vars=js_analysis_result.get('interesting_vars', []),
                    js_files_analyzed=js_analysis_result.get('js_files_analyzed', 0)
                )
                attack_surface.total_secrets = len(secrets)
                
                console.print(f"  [+] Extracted {len(js_analysis_result['endpoints'])} endpoints from JS")
                console.print(f"  [+] Discovered {len(secrets)} potential secrets")
                console.print(f"  [+] Found {len(js_analysis_result['modules'])} NPM modules")
                console.print(f"  [+] Identified {len(js_analysis_result['links'])} links\n")
                
                # Step 6: Manifest Hunter - Find buildManifest and endpoint lists
                console.print(f"  [*] Hunting for manifest files (buildManifest, routes, etc.)...")
                base_urls = SmartURLConstructor.extract_base_urls([e.url for e in all_endpoints[:100]])
                manifest_data = run_manifest_hunter(all_js_urls[:50], base_urls[:10])
                
                if manifest_data['files_found']:
                    console.print(f"  [+] Found {len(manifest_data['files_found'])} manifest files")
                    console.print(f"  [+] Extracted {len(manifest_data['endpoints'])} endpoints from manifests")
                    console.print(f"  [+] Discovered {len(manifest_data['js_files'])} additional JS files")
                    console.print(f"  [+] Found {len(manifest_data['routes'])} routes\n")
                    
                    # Fetch additional JS files found in manifests
                    if manifest_data['js_files']:
                        console.print(f"  [*] Fetching JS files from manifests...")
                        constructed_urls = SmartURLConstructor.construct_urls(
                            manifest_data['js_files'],
                            base_urls
                        )
                        
                        # Progress callback for manifest JS files
                        def manifest_js_progress(current, total, filename):
                            console.print(f"  [*] Fetching manifest JS: {filename} ({current}/{total})")
                        
                        additional_js = run_jsfetcher(constructed_urls[:20], manifest_js_progress)
                        if additional_js:
                            js_files.extend(additional_js)
                            console.print(f"  [+] Fetched {len(additional_js)} additional JS files\n")
                    
                    # Add manifest endpoints to all_endpoints
                    for ep in manifest_data['endpoints']:
                        full_urls = SmartURLConstructor.construct_urls([ep], base_urls)
                        for url in full_urls:
                            all_endpoints.append(EndpointModel(
                                url=url,
                                source="manifest",
                                timestamp=datetime.now()
                            ))
                
                # Step 7: Application Logic Analysis - Understand auth flows, etc.
                console.print(f"  [*] Analyzing application logic (auth flows, password reset, etc.)...")
                app_logic = analyze_application_logic(js_files)
                
                if app_logic['auth_flows']:
                    console.print(f"  [+] Detected authentication patterns:")
                    for flow_type, matches in app_logic['auth_flows'].items():
                        if matches:
                            console.print(f"      - {flow_type}: {len(matches)} occurrences")
                
                if app_logic['api_calls']:
                    console.print(f"  [+] Found {len(app_logic['api_calls'])} API call patterns")
                
                if app_logic['interesting_snippets']:
                    console.print(f"  [+] Extracted {len(app_logic['interesting_snippets'])} interesting code snippets\n")
                
                # Store app logic for LLM
                attack_surface.app_logic = app_logic
                attack_surface.manifest_data = manifest_data
                
                # Add JS endpoints to all_endpoints so LLM sees them
                from reconai.models import Endpoint as EndpointModel
                for ep in js_analysis_result.get('endpoints', [])[:100]:  # Limit
                    all_endpoints.append(EndpointModel(
                        url=ep,
                        source="javascript",
                        timestamp=datetime.now()
                    ))
        else:
            console.print("  [-] No JavaScript files discovered\n")
    
    # Deduplicate and aggregate
    attack_surface.endpoints = deduplicate_endpoints(all_endpoints)
    attack_surface.parameters = merge_parameters(all_parameters)
    attack_surface.total_endpoints = len(attack_surface.endpoints)
    attack_surface.total_parameters = len(attack_surface.parameters)
    
    # Extract technologies
    tech_map = {}
    for endpoint in attack_surface.endpoints:
        if endpoint.technologies:
            host = urlparse(endpoint.url).netloc
            for tech in endpoint.technologies:
                if tech not in tech_map:
                    tech_map[tech] = []
                if host not in tech_map[tech]:
                    tech_map[tech].append(host)
    attack_surface.technologies = tech_map
    
    attack_surface.scan_end = datetime.now()
    
    # LLM Analysis
    if not skip_llm:
        try:
            # Initialize Ollama
            llm = OllamaBackend(model_name=model, base_url=ollama_url)
            
            # Check connection
            print_scan_progress("Checking Ollama connection...", "🔌")
            if not llm.check_connection():
                console.print("❌ Cannot connect to Ollama. Make sure it's running:", style="red")
                console.print("   ollama serve\n", style="yellow")
                console.print(f"   Then pull the model: ollama pull {model}\n", style="yellow")
                sys.exit(1)
            
            # Verify model
            available_models = llm.list_models()
            if model not in available_models:
                console.print(f"⚠️  Model '{model}' not found. Available models:", style="yellow")
                for m in available_models[:10]:
                    console.print(f"   - {m}")
                console.print(f"\nPull the model with: ollama pull {model}\n", style="yellow")
                sys.exit(1)
            
            console.print(f"  ✅ Connected to Ollama, using {model}\n")
            
            # Run analysis
            attack_surface = analyze_attack_surface(attack_surface, llm)
            
        except Exception as e:
            console.print(f"❌ LLM analysis failed: {e}", style="red")
            console.print("Continuing with recon results only...\n", style="yellow")
    
    # Display results
    print_attack_surface_summary(attack_surface)
    
    # Write reports
    if not no_report:
        console.print("\n📝 Writing reports...\n")
        write_json_report(attack_surface, output_dir / "report.json")
        write_markdown_report(attack_surface, output_dir / "report.md")
        
        # Save raw data
        save_raw_data(attack_surface, output_dir)
    
    console.print(f"\n✨ Scan complete! Results saved to: [bold cyan]{output_dir}[/bold cyan]\n")


@app.command()
def web(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Web server host"),
    port: int = typer.Option(8000, "--port", "-p", help="Web server port")
):
    """
    Start the web UI for interactive reconnaissance.
    
    Example:
        reconai web
        reconai web --port 8080
    """
    print_banner()
    console.print(f"🌐 Starting web UI on [bold cyan]http://{host}:{port}[/bold cyan]\n")
    
    try:
        # Import here to avoid loading web deps for CLI-only usage
        from reconai.web.app import create_app
        import uvicorn
        
        app_instance = create_app()
        uvicorn.run(app_instance, host=host, port=port)
        
    except ImportError as e:
        console.print("❌ Web UI dependencies not installed.", style="red")
        console.print("Install with: pip install fastapi uvicorn jinja2\n", style="yellow")
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Failed to start web UI: {e}", style="red")
        sys.exit(1)


@app.command()
def models(
    ollama_url: str = typer.Option("http://localhost:11434", "--ollama-url", help="Ollama API base URL")
):
    """
    List available Ollama models.
    
    Example:
        reconai models
    """
    print_banner()
    
    try:
        llm = OllamaBackend(base_url=ollama_url)
        available_models = llm.list_models()
        
        if not available_models:
            console.print("❌ No models found or cannot connect to Ollama.", style="red")
            console.print("\nMake sure Ollama is running:", style="yellow")
            console.print("  ollama serve\n", style="cyan")
            console.print("Then pull some models:", style="yellow")
            console.print("  ollama pull llama3.1:8b", style="cyan")
            console.print("  ollama pull mistral-nemo:12b", style="cyan")
            console.print("  ollama pull deepseek-coder:6.7b\n", style="cyan")
            sys.exit(1)
        
        console.print(f"✅ Found {len(available_models)} models:\n", style="green")
        
        for model in available_models:
            console.print(f"  • {model}")
        
        console.print(f"\nUse any model with: [cyan]reconai scan <target> --model <model_name>[/cyan]\n")
        
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        sys.exit(1)


def deduplicate_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Remove duplicate endpoints."""
    seen = set()
    unique = []
    
    for endpoint in endpoints:
        key = f"{endpoint.url}:{endpoint.method}"
        if key not in seen:
            seen.add(key)
            unique.append(endpoint)
    
    return unique


def merge_parameters(parameters: list) -> list:
    """Merge parameters from different sources."""
    param_map = {}
    
    for param in parameters:
        if param.name not in param_map:
            param_map[param.name] = param
        else:
            # Merge endpoints
            existing = param_map[param.name]
            for endpoint in param.endpoints:
                if endpoint not in existing.endpoints:
                    existing.endpoints.append(endpoint)
            existing.count = len(existing.endpoints)
    
    return list(param_map.values())


def save_raw_data(attack_surface: AttackSurface, output_dir: Path):
    """Save raw recon data to files."""
    try:
        # Save subdomains
        if attack_surface.subdomains:
            with open(output_dir / "subdomains.txt", 'w') as f:
                for sub in attack_surface.subdomains:
                    f.write(f"{sub.host}\n")
        
        # Save endpoints
        if attack_surface.endpoints:
            with open(output_dir / "endpoints.txt", 'w') as f:
                for endpoint in attack_surface.endpoints:
                    f.write(f"{endpoint.url}\n")
        
        # Save parameters
        if attack_surface.parameters:
            with open(output_dir / "parameters.txt", 'w') as f:
                for param in attack_surface.parameters:
                    f.write(f"{param.name} (count: {param.count})\n")
        
    except Exception as e:
        console.print(f"⚠️  Failed to save raw data: {e}", style="yellow")


if __name__ == "__main__":
    app()
