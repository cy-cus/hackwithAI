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
            '-threads', '50'  # Faster scanning
        ]
        
        # Use system PATH, skipping venv to get ProjectDiscovery tools
        import os
        env = os.environ.copy()
        path_parts = env.get('PATH', '').split(':')
        # Remove venv bin directories from PATH
        system_path = [p for p in path_parts if 'venv' not in p.lower() and 'virtualenv' not in p.lower()]
        env['PATH'] = ':'.join(system_path)
        
        # Debug: check which httpx binary will be used
        try:
            which_result = subprocess.run(['which', 'httpx'], capture_output=True, text=True, env=env)
            httpx_path = which_result.stdout.strip()
            print(f"  [*] Using httpx binary: {httpx_path}")
        except:
            pass
        
        print(f"  [*] Running command: {' '.join(cmd)}")
        print(f"  [*] Input file: {input_file} (targets: {len(targets)})")
        print(f"  [*] Output file: {output_file}")
        
        result = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
            env=env
        )
        
        print(f"  [*] httpx exit code: {result.returncode}")
        if result.stdout:
            print(f"  [*] httpx stdout: {result.stdout[:500]}")
        
        # Show stderr if there were issues
        if result.stderr:
            print(f"  [!] httpx stderr: {result.stderr[:200]}")
        
        # Parse JSON output
        if Path(output_file).exists():
            file_size = Path(output_file).stat().st_size
            print(f"  [*] httpx output file size: {file_size} bytes")
            
            with open(output_file, 'r') as f:
                lines_read = 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    lines_read += 1
                    try:
                        data = json.loads(line)
                        
                        endpoint = Endpoint(
                            url=data.get('url', ''),  # Full URL
                            method=data.get('method', 'GET'),
                            status_code=data.get('status_code'),
                            title=data.get('title'),
                            content_length=data.get('content_length'),
                            content_type=data.get('content_type'),
                            technologies=data.get('tech', []),
                            server=data.get('webserver'),
                            source="httpx",
                            timestamp=datetime.now()
                        )
                        endpoints.append(endpoint)
                        print(f"  [+] Parsed endpoint: {endpoint.url} [{endpoint.status_code}]")
                        
                    except json.JSONDecodeError as e:
                        print(f"  [!] JSON decode error: {e}")
                        continue
            
            print(f"  [*] Read {lines_read} lines from httpx output")
            
            # Clean up
            Path(output_file).unlink()
        else:
            print(f"  [!] httpx output file does not exist: {output_file}")
        
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
