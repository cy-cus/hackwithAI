"""Ollama backend client for local LLM inference."""

import json
from typing import Optional, Dict, Any
import httpx


class OllamaBackend:
    """Client for Ollama API."""
    
    def __init__(
        self,
        model_name: str = "llama3.1:8b",
        base_url: str = "http://localhost:11434",
        timeout: int = 1200  # 20 minutes for large targeted scans
    ):
        """
        Initialize Ollama backend.
        
        Args:
            model_name: Name of the model (e.g., llama3.1:8b, mistral-nemo:12b)
            base_url: Ollama API base URL
            timeout: Request timeout in seconds (default: 1200s = 20 minutes)
        """
        self.model_name = model_name
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
    
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        timeout: Optional[int] = None,
    ) -> str:
        """
        Generate text using Ollama.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate
            
        Returns:
            Generated text
        """
        url = f"{self.base_url}/api/generate"
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        # Use per-call timeout if provided, otherwise fall back to instance default
        effective_timeout = timeout or self.timeout

        try:
            with httpx.Client(timeout=effective_timeout) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                
                result = response.json()
                return result.get("response", "")
                
        except httpx.ConnectError:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Make sure Ollama is running: ollama serve"
            )
        except httpx.TimeoutException:
            raise TimeoutError(f"Ollama request timed out after {effective_timeout}s")
        except Exception as e:
            raise RuntimeError(f"Ollama error: {e}")
    
    def chat(
        self,
        messages: list[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 4096,
        timeout: Optional[int] = None,
    ) -> str:
        """
        Chat completion using Ollama.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            Assistant response
        """
        url = f"{self.base_url}/api/chat"
        
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        
        # Use per-call timeout if provided, otherwise fall back to instance default
        effective_timeout = timeout or self.timeout
        
        try:
            with httpx.Client(timeout=effective_timeout) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                
                result = response.json()
                return result.get("message", {}).get("content", "")
                
        except httpx.ConnectError:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Make sure Ollama is running: ollama serve"
            )
        except httpx.TimeoutException:
            raise TimeoutError(f"Ollama request timed out after {effective_timeout}s")
        except Exception as e:
            raise RuntimeError(f"Ollama error: {e}")
    
    def list_models(self) -> list[str]:
        """
        List available models.
        
        Returns:
            List of model names
        """
        url = f"{self.base_url}/api/tags"
        
        try:
            with httpx.Client(timeout=30) as client:
                response = client.get(url)
                response.raise_for_status()
                
                result = response.json()
                models = result.get("models", [])
                return [m.get("name", "") for m in models]
                
        except Exception as e:
            print(f"⚠️  Could not list models: {e}")
            return []
    
    def check_connection(self) -> bool:
        """
        Check if Ollama is accessible.
        
        Returns:
            True if connected, False otherwise
        """
        try:
            models = self.list_models()
            return len(models) > 0
        except:
            return False
