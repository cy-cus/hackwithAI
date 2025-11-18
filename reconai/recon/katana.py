"""Katana wrapper for web crawling."""

import subprocess
import tempfile
import json
import re
from pathlib import Path
from typing import List
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from reconai.models import Endpoint, Parameter


def run_katana(target_url: str, max_depth: int = 3, timeout: int = 600) -> tuple[List[Endpoint], List[Parameter]]:
    """
    Run katana to crawl and discover URLs.
    
    Args:
        target_url: Target URL to crawl
        max_depth: Maximum crawl depth
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (endpoints, parameters)
    """
    endpoints = []
    param_map = {}  # param_name -> Parameter object
    
    try:
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            output_file = f.name
        
        # Run katana
        cmd = [
            'katana',
            '-u', target_url,
            '-d', str(max_depth),
            '-j',  # JSONL output
            '-o', output_file,
            '-silent',
            '-jc',  # js-crawl
            '-kf', 'all',  # known-files
            '-aff'  # automatic-form-fill (non-headless)
        ]
        
        # Use system PATH, skipping venv to get ProjectDiscovery tools
        import os
        env = os.environ.copy()
        path_parts = env.get('PATH', '').split(':')
        system_path = [p for p in path_parts if 'venv' not in p.lower() and 'virtualenv' not in p.lower()]
        env['PATH'] = ':'.join(system_path)
        
        print(f"  [*] Running katana command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
            env=env
        )
        
        print(f"  [*] katana exit code: {result.returncode}")
        if result.stderr:
            print(f"  [!] katana stderr: {result.stderr[:200]}")
        
        # Parse JSON output
        fallback_performed = False
        fallback_matches = []
        if Path(output_file).exists():
            file_size = Path(output_file).stat().st_size
            print(f"  [*] katana output file size: {file_size} bytes")
            with open(output_file, 'r', errors='ignore') as f:
                raw_content = f.read()
            
            for line in raw_content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as e:
                    fallback_performed = True
                    continue
                url = data.get('request', {}).get('url') or data.get('url', '')
                if not url:
                    continue
                endpoint = Endpoint(
                    url=url,
                    method=data.get('request', {}).get('method', 'GET'),
                    status_code=data.get('response', {}).get('status_code'),
                    source="katana",
                    timestamp=datetime.now()
                )
                endpoints.append(endpoint)
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name, values in params.items():
                        if param_name not in param_map:
                            param_map[param_name] = Parameter(
                                name=param_name,
                                example_value=values[0] if values else None,
                                endpoints=[url],
                                count=1
                            )
                        else:
                            param_map[param_name].count += 1
                            if url not in param_map[param_name].endpoints:
                                param_map[param_name].endpoints.append(url)
            
            if not endpoints:
                # Fallback: treat content as HTML/text and extract absolute URLs
                url_matches = set(re.findall(r'https?://[^\s"\'<>]+', raw_content))
                fallback_matches = list(url_matches)
                for url in fallback_matches:
                    endpoint = Endpoint(
                        url=url,
                        method='GET',
                        status_code=None,
                        source="katana_raw",
                        timestamp=datetime.now()
                    )
                    endpoints.append(endpoint)
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param_name, values in params.items():
                            if param_name not in param_map:
                                param_map[param_name] = Parameter(
                                    name=param_name,
                                    example_value=values[0] if values else None,
                                    endpoints=[url],
                                    count=1
                                )
                            else:
                                param_map[param_name].count += 1
                                if url not in param_map[param_name].endpoints:
                                    param_map[param_name].endpoints.append(url)
                print(f"  [*] katana fallback extracted {len(fallback_matches)} URLs from raw output")
            else:
                print(f"  [*] katana parsed {len(endpoints)} endpoints")
            
            # Clean up
            Path(output_file).unlink()
        else:
            print(f"  [!] katana output file does not exist: {output_file}")
        
        parameters = list(param_map.values())
        if fallback_performed and fallback_matches:
            print("  [!] Katana JSON parsing failed; used fallback URL extraction")
        return endpoints, parameters
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  Katana timed out after {timeout}s")
        return endpoints, list(param_map.values())
    except FileNotFoundError:
        print("❌ Katana not found. Install: go install -v github.com/projectdiscovery/katana/cmd/katana@latest")
        return [], []
    except Exception as e:
        print(f"❌ Katana error: {e}")
        return endpoints, list(param_map.values())
