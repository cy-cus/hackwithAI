"""Data models for reconnaissance and analysis results."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, HttpUrl, ConfigDict


class Subdomain(BaseModel):
    """A discovered subdomain."""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    host: str
    source: str = "subfinder"
    timestamp: datetime = Field(default_factory=datetime.now)


class Technology(BaseModel):
    """Detected web technology."""
    name: str
    version: Optional[str] = None
    categories: List[str] = Field(default_factory=list)


class Endpoint(BaseModel):
    """An HTTP endpoint discovered during recon."""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    title: Optional[str] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    server: Optional[str] = None
    source: str  # katana, httpx, waybackurls
    timestamp: datetime = Field(default_factory=datetime.now)


class Parameter(BaseModel):
    """A URL parameter extracted from endpoints."""
    name: str
    example_value: Optional[str] = None
    endpoints: List[str] = Field(default_factory=list)
    count: int = 0
    suspicious: bool = False
    risk_indicators: List[str] = Field(default_factory=list)


class JSFile(BaseModel):
    """A JavaScript file discovered during recon."""
    url: str
    content: str
    size: int
    source: str  # jsleuth, endpoint_scan, user_provided
    timestamp: str
    raw_content: Optional[str] = None  # Full JS content for later analysis


class Secret(BaseModel):
    """A discovered secret or credential."""
    type: str
    value: str
    context: str
    severity: str = "HIGH"
    source_url: Optional[str] = None
    js_file: Optional[str] = None  # JS file URL where this secret was found
    line_number: Optional[int] = None  # Line number in the JS file


class JSAnalysis(BaseModel):
    """Results from JavaScript analysis."""
    endpoints: List[str] = Field(default_factory=list)
    secrets: List[Secret] = Field(default_factory=list)
    links: List[str] = Field(default_factory=list)
    modules: List[str] = Field(default_factory=list)
    interesting_vars: List[str] = Field(default_factory=list)
    js_files_analyzed: int = 0
    # Source tracking - maps item to the JS files it was found in
    endpoint_sources: Dict[str, List[str]] = Field(default_factory=dict)  # {endpoint_url: [js_file_url,...]}
    link_sources: Dict[str, List[str]] = Field(default_factory=dict)  # {link_url: [js_file_url,...]}


class Finding(BaseModel):
    """A security finding from AI analysis."""
    severity: str  # critical, high, medium, low, info
    category: str  # e.g., "SSRF", "SQLi", "Path Traversal", "Info Disclosure"
    title: str
    description: str
    evidence: List[str] = Field(default_factory=list)
    affected_endpoints: List[str] = Field(default_factory=list)
    affected_parameters: List[str] = Field(default_factory=list)
    exploitation_notes: Optional[str] = None  # How to exploit this vulnerability
    poc: Optional[str] = None  # Proof of concept code/steps
    confidence: str = "medium"  # high, medium, low


class AttackSurface(BaseModel):
    """Aggregated attack surface data."""
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()}, protected_namespaces=())
    
    target_domain: str
    scan_start: datetime
    scan_end: Optional[datetime] = None
    
    # Recon results
    subdomains: List[Subdomain] = Field(default_factory=list)
    urls: List[Endpoint] = Field(default_factory=list)  # Full URLs from waybackurls, katana, httpx
    api_endpoints: List[str] = Field(default_factory=list)  # Extracted API paths from URLs and JS
    endpoints: List[Endpoint] = Field(default_factory=list)  # Deprecated: for backward compatibility
    parameters: List[Parameter] = Field(default_factory=list)
    technologies: Dict[str, List[str]] = Field(default_factory=dict)
    
    # JavaScript analysis
    js_urls: List[str] = Field(default_factory=list)  # Discovered JS URLs
    js_files: List[JSFile] = Field(default_factory=list)  # Fetched JS file contents
    js_analysis: Optional[JSAnalysis] = None
    
    # Application logic
    app_logic: Optional[Dict] = None
    
    # Counts
    total_subdomains: int = 0
    total_urls: int = 0  # Count of full URLs
    total_api_endpoints: int = 0  # Count of extracted API paths
    total_endpoints: int = 0  # Deprecated: for backward compatibility
    total_parameters: int = 0
    alive_hosts: int = 0
    total_js_files: int = 0
    total_secrets: int = 0
    total_nuclei_findings: int = 0
    
    # Nuclei results
    nuclei_findings: List[Dict[str, Any]] = Field(default_factory=list)
    nuclei_by_severity: Dict[str, int] = Field(default_factory=dict)
    
    # Analysis results
    findings: List[Finding] = Field(default_factory=list)
    summary: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    """Configuration for a reconnaissance scan."""
    target_url: str
    output_dir: str
    model_name: str = "llama3.1:8b"
    ollama_base_url: str = "http://localhost:11434"
    
    # Tool toggles
    run_subfinder: bool = True
    run_httpx: bool = True
    run_katana: bool = True
    run_waybackurls: bool = True
    run_nuclei: bool = False
    
    # Tool options
    subfinder_timeout: int = 300
    httpx_timeout: int = 300
    katana_max_depth: int = 3
    katana_timeout: int = 600
    waybackurls_timeout: int = 300
    
    # Nuclei options
    nuclei_templates: List[str] = Field(default_factory=list)
    nuclei_severity: List[str] = Field(default_factory=lambda: ["critical", "high", "medium"])
    nuclei_rate_limit: int = 150
    nuclei_concurrency: int = 25
    
    # AI options
    llm_temperature: float = 0.3
    llm_max_tokens: int = 4096
    
    # Analysis options
    max_endpoints_for_analysis: int = 5000
    include_low_priority: bool = False
