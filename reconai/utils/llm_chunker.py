"""LLM Chunker - Breaks large content into manageable chunks for LLM analysis."""

from typing import List, Dict, Any
import math


class LLMChunker:
    """Chunks large datasets for LLM processing to avoid timeouts."""
    
    def __init__(self, chunk_size: int = 50):
        """
        Initialize chunker.
        
        Args:
            chunk_size: Number of items per chunk
        """
        self.chunk_size = chunk_size
    
    def chunk_js_files(self, js_files: List[Dict], max_content_length: int = 5000) -> List[List[Dict]]:
        """
        Chunk JS files for analysis.
        
        Args:
            js_files: List of JS file dictionaries
            max_content_length: Max characters of content per file
            
        Returns:
            List of chunks
        """
        # Truncate content if too large
        processed_files = []
        for js_file in js_files:
            truncated = js_file.copy()
            if 'content' in truncated and len(truncated['content']) > max_content_length:
                truncated['content'] = truncated['content'][:max_content_length] + "\n... [truncated]"
                truncated['truncated'] = True
            processed_files.append(truncated)
        
        # Split into chunks
        return self._chunk_list(processed_files, self.chunk_size)
    
    def chunk_endpoints(self, endpoints: List[Dict]) -> List[List[Dict]]:
        """Chunk endpoints for analysis."""
        return self._chunk_list(endpoints, 100)  # 100 endpoints per chunk
    
    def chunk_secrets(self, secrets: List[Dict]) -> List[List[Dict]]:
        """Chunk secrets for analysis."""
        # Secrets are critical, smaller chunks for detailed analysis
        return self._chunk_list(secrets, 20)
    
    def prioritize_js_files(self, js_files: List[Dict], size_filter: str = 'medium') -> List[Dict]:
        """
        Filter JS files by count.
        
        Args:
            js_files: List of JS files
            size_filter: 'small' (first 100), 'medium' (100-1000), 'large' (all)
            
        Returns:
            Filtered list based on count
        """
        if size_filter == 'small':
            # Small: Analyze first 100 files only
            return js_files[:100]
        elif size_filter == 'medium':
            # Medium: Analyze 100-1000 files
            return js_files[:1000]
        elif size_filter == 'large' or size_filter == 'all':
            # Large/All: Analyze everything
            return js_files
        else:
            # Default to medium
            return js_files[:1000]
    
    def create_analysis_batches(self, attack_surface: Dict) -> List[Dict]:
        """
        Create batches for incremental LLM analysis.
        
        Args:
            attack_surface: Complete attack surface data
            
        Returns:
            List of analysis batches
        """
        batches = []
        
        # Batch 1: High-priority items (secrets, suspicious params)
        # Batch 1: High-priority items (secrets, suspicious params)
        js_analysis = attack_surface.get('js_analysis') or {}
        
        batch_1 = {
            'priority': 'CRITICAL',
            'secrets': js_analysis.get('secrets', [])[:20],
            'suspicious_params': [p for p in (attack_surface.get('parameters') or []) 
                                 if p.get('suspicious')][:30],
            'suspicious_endpoints': self._get_suspicious_endpoints(
                attack_surface.get('endpoints') or [])[:30]
        }
        if batch_1['secrets'] or batch_1['suspicious_params']:
            batches.append(batch_1)
        
        # Batch 2: JS files analysis (small chunks)
        js_files = attack_surface.get('js_files', [])
        if js_files:
            js_chunks = self.chunk_js_files(js_files, max_content_length=3000)
            for i, chunk in enumerate(js_chunks[:5]):  # Max 5 JS batches
                batches.append({
                    'priority': 'HIGH',
                    'type': 'js_analysis',
                    'chunk': i + 1,
                    'js_files': chunk
                })
        
        # Batch 3: Endpoints and parameters
        endpoints = attack_surface.get('endpoints', [])
        if endpoints:
            endpoint_chunks = self.chunk_endpoints(endpoints)
            for i, chunk in enumerate(endpoint_chunks[:3]):  # Max 3 endpoint batches
                batches.append({
                    'priority': 'MEDIUM',
                    'type': 'endpoint_analysis',
                    'chunk': i + 1,
                    'endpoints': chunk,
                    'parameters': attack_surface.get('parameters', [])
                })
        
        return batches
    
    def _chunk_list(self, items: List[Any], chunk_size: int) -> List[List[Any]]:
        """Split list into chunks."""
        if not items:
            return []
        
        chunks = []
        for i in range(0, len(items), chunk_size):
            chunks.append(items[i:i + chunk_size])
        
        return chunks
    
    def _get_suspicious_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Filter suspicious endpoints."""
        suspicious_patterns = [
            'admin', 'debug', 'test', 'backup', 'config',
            'api/internal', 'api/admin', '.env', '.git',
            'phpinfo', 'upload', 'delete', 'sql'
        ]
        
        suspicious = []
        for endpoint in endpoints:
            url = endpoint.get('url', '').lower()
            if any(pattern in url for pattern in suspicious_patterns):
                suspicious.append(endpoint)
        
        return suspicious
