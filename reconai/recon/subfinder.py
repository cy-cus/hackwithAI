"""Subfinder wrapper for subdomain discovery."""

import subprocess
import tempfile
from pathlib import Path
from typing import List
from datetime import datetime

from reconai.models import Subdomain


def run_subfinder(domain: str, timeout: int = 300) -> List[Subdomain]:
    """
    Run subfinder to discover subdomains.
    
    Args:
        domain: Target domain (e.g., example.com)
        timeout: Command timeout in seconds
        
    Returns:
        List of discovered subdomains
    """
    subdomains = []
    
    try:
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
            output_file = f.name
        
        # Run subfinder
        cmd = [
            'subfinder',
            '-d', domain,
            '-o', output_file,
            '-silent',
            '-all'  # Use all sources
        ]
        
        # Use system PATH, skipping venv to get ProjectDiscovery tools
        import os
        env = os.environ.copy()
        path_parts = env.get('PATH', '').split(':')
        system_path = [p for p in path_parts if 'venv' not in p.lower() and 'virtualenv' not in p.lower()]
        env['PATH'] = ':'.join(system_path)
        
        result = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
            env=env
        )
        
        # Parse output file
        if Path(output_file).exists():
            with open(output_file, 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        subdomains.append(Subdomain(
                            host=subdomain,
                            source="subfinder",
                            timestamp=datetime.now()
                        ))
            
            # Clean up
            Path(output_file).unlink()
        
        return subdomains
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  Subfinder timed out after {timeout}s")
        return subdomains
    except FileNotFoundError:
        print("❌ Subfinder not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return []
    except Exception as e:
        print(f"❌ Subfinder error: {e}")
        return subdomains
