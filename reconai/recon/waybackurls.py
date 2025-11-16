"""Waybackurls wrapper for historical URL discovery."""

import subprocess
from typing import List
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from reconai.models import Endpoint, Parameter


def run_waybackurls(domain: str, timeout: int = 300) -> tuple[List[Endpoint], List[Parameter]]:
    """
    Run waybackurls to discover ALL historical URLs from Wayback Machine.
    
    Args:
        domain: Target domain
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (endpoints, parameters)
    """
    endpoints = []
    parameters = []
    
    try:
        # Run waybackurls
        cmd = ['waybackurls', domain]
        
        result = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Parse URL to keep full URL
                    parsed = urlparse(line)
                    
                    # Extract parameters
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param_name, values in params.items():
                            param = Parameter(
                                name=param_name,
                                example_value=values[0] if values else None,
                                endpoints=[line],
                                count=1
                            )
                            parameters.append(param)
                    
                    # Create endpoint with FULL URL
                    endpoint = Endpoint(
                        url=line,  # Full URL: https://example.com/api/users
                        source="waybackurls",
                        timestamp=datetime.now()
                    )
                    endpoints.append(endpoint)
                
                except Exception:
                    continue
        
        return endpoints, parameters
        
    except subprocess.TimeoutExpired:
        print(f"  Waybackurls timed out after {timeout}s")
        return endpoints, parameters
    except FileNotFoundError:
        print("  Waybackurls not found. Install: go install github.com/tomnomnom/waybackurls@latest")
        return [], []
    except Exception as e:
        print(f"  Waybackurls error: {e}")
        return endpoints, parameters
