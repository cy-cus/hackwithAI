"""Katana wrapper for web crawling."""

import subprocess
import tempfile
import json
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
            '-json',
            '-o', output_file,
            '-silent',
            '-js-crawl',
            '-known-files', 'all',
            '-automatic-form-fill'
        ]
        
        result = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True
        )
        
        # Parse JSON output
        if Path(output_file).exists():
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        url = data.get('request', {}).get('url') or data.get('url', '')
                        
                        if not url:
                            continue
                        
                        endpoint = Endpoint(
                            url=url,  # Full URL
                            method=data.get('request', {}).get('method', 'GET'),
                            status_code=data.get('response', {}).get('status_code'),
                            source="katana",
                            timestamp=datetime.now()
                        )
                        endpoints.append(endpoint)
                        
                        # Extract parameters
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
                        
                    except json.JSONDecodeError:
                        continue
            
            # Clean up
            Path(output_file).unlink()
        
        parameters = list(param_map.values())
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
