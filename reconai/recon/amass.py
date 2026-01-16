"""
Amass - Advanced subdomain enumeration
OWASP's most comprehensive subdomain discovery tool
"""

import subprocess
import logging
from typing import List, Set
from pathlib import Path

logger = logging.getLogger(__name__)


def run_amass(domain: str, output_dir: str = None, passive_only: bool = True) -> List[str]:
    """
    Run Amass for subdomain enumeration.
    
    Args:
        domain: Target domain
        output_dir: Directory to save results
        passive_only: If True, only use passive sources (no active DNS)
        
    Returns:
        List of discovered subdomains
    """
    subdomains = []
    
    try:
        # Prepare output directory
        if output_dir:
            output_path = Path(output_dir) / "amass_output.txt"
            output_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            output_path = Path(f"/tmp/amass_{domain}.txt")
        
        # Build amass command
        # Using 'enum' for enumeration, passive mode for speed and stealth
        cmd = ["amass", "enum"]
        
        if passive_only:
            cmd.append("-passive")
        
        cmd.extend([
            "-d", domain,
            "-o", str(output_path),
            "-timeout", "10",  # 10 minutes max
        ])
        
        logger.info(f"Running Amass: {' '.join(cmd)}")
        
        # Run amass
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes
        )
        
        # Read results
        if output_path.exists():
            with open(output_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Amass found {len(subdomains)} subdomains")
        else:
            logger.warning("Amass output file not found")
        
        # Log any errors
        if process.stderr:
            logger.debug(f"Amass stderr: {process.stderr}")
            
    except subprocess.TimeoutExpired:
        logger.warning("Amass timed out after 10 minutes")
    except FileNotFoundError:
        logger.error("Amass not found. Install with: go install -v github.com/owasp-amass/amass/v4/...@master")
    except Exception as e:
        logger.error(f"Amass error: {e}")
    
    return subdomains


def run_amass_passive(domain: str) -> List[str]:
    """
    Run Amass in passive mode (no active DNS queries).
    Faster and stealthier.
    """
    return run_amass(domain, passive_only=True)


def run_amass_active(domain: str, output_dir: str = None) -> List[str]:
    """
    Run Amass in active mode (includes DNS brute forcing).
    More thorough but slower and noisier.
    """
    return run_amass(domain, output_dir=output_dir, passive_only=False)
