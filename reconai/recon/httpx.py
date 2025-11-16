"""Httpx wrapper for HTTP probing."""

import subprocess
import tempfile
import json
from pathlib import Path
from typing import List
from datetime import datetime

from reconai.models import Endpoint


def run_httpx(targets: List[str], timeout: int = 300) -> List[Endpoint]:
    """
    Run httpx to probe HTTP endpoints.
    
    Args:
        targets: List of hosts/URLs to probe
        timeout: Command timeout in seconds
        
    Returns:
        List of alive endpoints with metadata
    """
    endpoints = []
    
    if not targets:
        return endpoints
    
    try:
        # Create input file with targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for target in targets:
                f.write(f"{target}\n")
            input_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            output_file = f.name
        
        # Run httpx with better detection
        cmd = [
            'httpx',
            '-l', input_file,
            '-json',
            '-o', output_file,
            '-silent',
            '-title',
            '-tech-detect',
            '-status-code',
            '-content-length',
            '-content-type',
            '-server',
            '-follow-redirects',
            '-random-agent',
            '-retries', '2',
            '-timeout', '10',
            '-probe',  # Test both http and https
            '-threads', '50',  # Faster scanning
            '-follow-host-redirects'
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
                        
                        endpoint = Endpoint(
                            url=data.get('url', ''),  # Full URL
                            method=data.get('method', 'GET'),
                            status_code=data.get('status_code'),
                            title=data.get('title'),
                            content_length=data.get('content_length'),
                            content_type=data.get('content_type'),
                            technologies=data.get('technologies', []),
                            server=data.get('server'),
                            source="httpx",
                            timestamp=datetime.now()
                        )
                        endpoints.append(endpoint)
                        
                    except json.JSONDecodeError:
                        continue
            
            # Clean up
            Path(output_file).unlink()
        
        Path(input_file).unlink()
        return endpoints
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  Httpx timed out after {timeout}s")
        return endpoints
    except FileNotFoundError:
        print("❌ Httpx not found. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return []
    except Exception as e:
        print(f"❌ Httpx error: {e}")
        return endpoints
