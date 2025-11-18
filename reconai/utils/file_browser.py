"""File browsing utilities for LLM-driven output exploration."""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import os


class FileBrowser:
    """Controlled file browser for LLM agents to explore scan outputs."""
    
    def __init__(self, base_output_dir: str = "./output"):
        """
        Initialize file browser with base output directory.
        
        Args:
            base_output_dir: Root output directory (e.g., "./output")
        """
        self.base_output_dir = Path(base_output_dir).resolve()
    
    def _is_safe_path(self, requested_path: str) -> bool:
        """
        Check if requested path is within allowed output directory.
        
        Args:
            requested_path: Path requested by LLM
            
        Returns:
            True if path is safe, False otherwise
        """
        try:
            resolved = Path(requested_path).resolve()
            return resolved.is_relative_to(self.base_output_dir)
        except Exception:
            return False
    
    def list_dir(self, path: str) -> Dict[str, Any]:
        """
        List contents of a directory.
        
        Args:
            path: Directory path to list
            
        Returns:
            Dict with files, directories, and metadata
        """
        if not self._is_safe_path(path):
            return {
                "error": "Access denied - path outside output folder",
                "allowed_base": str(self.base_output_dir)
            }
        
        try:
            target_path = Path(path).resolve()
            
            if not target_path.exists():
                return {"error": f"Path does not exist: {path}"}
            
            if not target_path.is_dir():
                return {"error": f"Not a directory: {path}"}
            
            files = []
            directories = []
            
            for item in sorted(target_path.iterdir()):
                if item.is_file():
                    files.append({
                        "name": item.name,
                        "size": item.stat().st_size,
                        "path": str(item)
                    })
                elif item.is_dir():
                    item_count = sum(1 for _ in item.iterdir())
                    directories.append({
                        "name": item.name,
                        "items": item_count,
                        "path": str(item)
                    })
            
            return {
                "path": str(target_path),
                "files": files,
                "directories": directories,
                "total_files": len(files),
                "total_directories": len(directories)
            }
            
        except Exception as e:
            return {"error": f"Failed to list directory: {str(e)}"}
    
    def read_file(self, path: str, offset: int = 0, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Read file contents with optional line range.
        
        Args:
            path: File path to read
            offset: Starting line (0-indexed)
            limit: Number of lines to read (None = all)
            
        Returns:
            Dict with file contents and metadata
        """
        if not self._is_safe_path(path):
            return {
                "error": "Access denied - path outside output folder",
                "allowed_base": str(self.base_output_dir)
            }
        
        try:
            target_path = Path(path).resolve()
            
            if not target_path.exists():
                return {"error": f"File does not exist: {path}"}
            
            if not target_path.is_file():
                return {"error": f"Not a file: {path}"}
            
            file_size = target_path.stat().st_size
            
            # Handle JSON files specially
            if target_path.suffix == '.json':
                try:
                    with open(target_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    return {
                        "path": str(target_path),
                        "type": "json",
                        "size": file_size,
                        "content": data
                    }
                except json.JSONDecodeError:
                    pass  # Fall through to text reading
            
            # Read as text
            with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            total_lines = len(lines)
            
            # Apply offset and limit
            if limit is not None:
                selected_lines = lines[offset:offset + limit]
            else:
                selected_lines = lines[offset:]
            
            return {
                "path": str(target_path),
                "type": "text",
                "size": file_size,
                "total_lines": total_lines,
                "offset": offset,
                "lines_returned": len(selected_lines),
                "content": "".join(selected_lines)
            }
            
        except Exception as e:
            return {"error": f"Failed to read file: {str(e)}"}
    
    def search_content(self, path: str, query: str, case_sensitive: bool = False) -> Dict[str, Any]:
        """
        Search for content within a file or directory.
        
        Args:
            path: File or directory path to search
            query: Search query string
            case_sensitive: Whether to match case
            
        Returns:
            Dict with search results
        """
        if not self._is_safe_path(path):
            return {
                "error": "Access denied - path outside output folder",
                "allowed_base": str(self.base_output_dir)
            }
        
        try:
            target_path = Path(path).resolve()
            
            if not target_path.exists():
                return {"error": f"Path does not exist: {path}"}
            
            results = []
            
            if target_path.is_file():
                # Search single file
                matches = self._search_file(target_path, query, case_sensitive)
                if matches:
                    results.append({
                        "file": str(target_path),
                        "matches": matches
                    })
            elif target_path.is_dir():
                # Search directory recursively
                for file_path in target_path.rglob('*'):
                    if file_path.is_file() and file_path.suffix in ['.txt', '.json', '.js', '.log']:
                        matches = self._search_file(file_path, query, case_sensitive)
                        if matches:
                            results.append({
                                "file": str(file_path),
                                "matches": matches
                            })
            
            return {
                "query": query,
                "case_sensitive": case_sensitive,
                "files_searched": len(results),
                "results": results
            }
            
        except Exception as e:
            return {"error": f"Search failed: {str(e)}"}
    
    def _search_file(self, file_path: Path, query: str, case_sensitive: bool) -> List[Dict[str, Any]]:
        """
        Search within a single file.
        
        Args:
            file_path: Path to file
            query: Search query
            case_sensitive: Case sensitivity flag
            
        Returns:
            List of matches with line numbers and context
        """
        matches = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    search_line = line if case_sensitive else line.lower()
                    search_query = query if case_sensitive else query.lower()
                    
                    if search_query in search_line:
                        matches.append({
                            "line_number": line_num,
                            "content": line.strip()
                        })
        except Exception:
            pass
        
        return matches
    
    def get_scan_summary(self, scan_id: str) -> Dict[str, Any]:
        """
        Get high-level summary of a scan's output.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Dict with scan summary
        """
        scan_path = self.base_output_dir / scan_id
        
        if not scan_path.exists():
            return {"error": f"Scan not found: {scan_id}"}
        
        summary = {
            "scan_id": scan_id,
            "path": str(scan_path),
            "folders": {}
        }
        
        # Check standard folders
        for folder in ['subdomains', 'endpoints', 'js_files', 'secrets', 'findings', 'raw']:
            folder_path = scan_path / folder
            if folder_path.exists() and folder_path.is_dir():
                file_count = sum(1 for f in folder_path.rglob('*') if f.is_file())
                summary['folders'][folder] = {
                    "exists": True,
                    "file_count": file_count,
                    "path": str(folder_path)
                }
        
        # Load attack surface if available
        attack_surface_path = scan_path / 'raw' / 'attack_surface.json'
        if attack_surface_path.exists():
            try:
                with open(attack_surface_path, 'r') as f:
                    data = json.load(f)
                summary['stats'] = {
                    "target_domain": data.get('target_domain'),
                    "total_subdomains": data.get('total_subdomains', 0),
                    "total_urls": data.get('total_urls', 0),
                    "total_api_endpoints": data.get('total_api_endpoints', 0),
                    "total_js_files": data.get('total_js_files', 0),
                    "total_secrets": data.get('total_secrets', 0),
                    "scan_start": data.get('scan_start'),
                    "scan_end": data.get('scan_end')
                }
            except Exception:
                pass
        
        return summary


def create_tool_spec() -> str:
    """
    Create tool specification for LLM to understand available commands.
    
    Returns:
        String describing available tools
    """
    return """
AVAILABLE FILE BROWSING TOOLS:

You can request to explore scan output files using these commands. Format your requests as JSON:

1. LIST_DIR
   List contents of a directory
   Example: {"tool": "list_dir", "path": "output/example.com_20251118_013036"}
   
2. READ_FILE
   Read file contents (supports JSON and text)
   Example: {"tool": "read_file", "path": "output/example.com_20251118_013036/secrets/secrets.json"}
   Optional: Add "offset": 0, "limit": 100 to read specific line ranges
   
3. SEARCH_CONTENT
   Search for text within files or directories
   Example: {"tool": "search_content", "path": "output/example.com_20251118_013036/js_files", "query": "api_key"}
   Optional: Add "case_sensitive": true for case-sensitive search
   
4. GET_SCAN_SUMMARY
   Get high-level summary of scan results
   Example: {"tool": "get_scan_summary", "scan_id": "example.com_20251118_013036"}

When you need detailed information from files, output your tool request as JSON on a single line prefixed with "TOOL_REQUEST:".
After receiving results, continue with your analysis or request more data if needed.
When you have enough information, provide your final answer prefixed with "FINAL_ANSWER:".
"""
