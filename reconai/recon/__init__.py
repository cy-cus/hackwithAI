"""Recon tool wrappers for passive reconnaissance."""

from .subfinder import run_subfinder
from .crtsh import run_crtsh
from .httpx import run_httpx
from .katana import run_katana
from .waybackurls import run_waybackurls
from .jsleuth import run_jsleuth
from .jsleuth_enhanced import run_jsleuth_enhanced
from .jsfetcher import run_jsfetcher
from .jsanalyzer import analyze_js_files
from .manifest_hunter import run_manifest_hunter, SmartURLConstructor
from .app_logic_analyzer import analyze_application_logic
from .nuclei import run_nuclei

# Advanced bug hunting modules
from .advanced_subdomain_enum import run_advanced_subdomain_enum, AdvancedSubdomainEnumerator
from .vuln_scanner import scan_endpoints_for_vulnerabilities, VulnerabilityScanner
from .enhanced_js_analyzer import analyze_js_for_bugs, EnhancedJSAnalyzer
from .parameter_fuzzer import fuzz_all_parameters, ParameterFuzzer

# ULTIMATE modules
from .ultimate_subdomain_enum import run_ultimate_subdomain_enum_sync

__all__ = [
    "run_subfinder", 
    "run_crtsh", 
    "run_httpx", 
    "run_katana", 
    "run_waybackurls",
    "run_jsleuth",
    "run_jsleuth_enhanced",
    "run_jsfetcher",
    "analyze_js_files",
    "run_manifest_hunter",
    "SmartURLConstructor",
    "analyze_application_logic",
    "run_nuclei",
    # Advanced modules
    "run_advanced_subdomain_enum",
    "AdvancedSubdomainEnumerator",
    "scan_endpoints_for_vulnerabilities",
    "VulnerabilityScanner",
    "analyze_js_for_bugs",
    "EnhancedJSAnalyzer",
    "fuzz_all_parameters",
    "ParameterFuzzer",
    # ULTIMATE modules
    "run_ultimate_subdomain_enum_sync",
]


