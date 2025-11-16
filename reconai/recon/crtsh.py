"""crt.sh wrapper for certificate transparency subdomain discovery."""

import json
from typing import List
from datetime import datetime
import httpx

from reconai.models import Subdomain


def run_crtsh(domain: str, timeout: int = 30) -> List[Subdomain]:
    """
    Query crt.sh for subdomains via certificate transparency logs.
    
    Args:
        domain: Target domain (e.g., example.com)
        timeout: Request timeout in seconds
        
    Returns:
        List of discovered subdomains
    """
    subdomains = []
    seen = set()
    
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        
                        # Handle multiple domains in name_value (newline separated)
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            
                            # Skip wildcards and invalid entries
                            if not subdomain or '*' in subdomain:
                                continue
                            
                            # Only include subdomains of target domain
                            if subdomain.endswith(domain) and subdomain not in seen:
                                seen.add(subdomain)
                                subdomains.append(Subdomain(
                                    host=subdomain,
                                    source="crtsh",
                                    timestamp=datetime.now()
                                ))
                
                except json.JSONDecodeError:
                    print("Warning: crt.sh returned invalid JSON")
        
        return subdomains
        
    except httpx.TimeoutException:
        print(f"Warning: crt.sh query timed out after {timeout}s")
        return subdomains
    except Exception as e:
        print(f"Warning: crt.sh query failed: {e}")
        return subdomains
