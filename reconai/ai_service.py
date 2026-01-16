"""
AI Service - Multi-Provider LLM Integration

Supports: Google Gemini, OpenAI, Anthropic Claude, Groq, and more
Uses API keys (no local Ollama dependency)
"""

import os
import logging
import asyncio
from typing import Optional, Dict, Any, List
from enum import Enum

logger = logging.getLogger(__name__)


class AIProvider(str, Enum):
    """Supported AI providers"""
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"


class AIService:
    """
    Universal AI Service supporting multiple LLM providers.
    Handles API key management and provider switching.
    """
    
    # Default models for each provider
    DEFAULT_MODELS = {
        AIProvider.GEMINI: {
            "default": "gemini-2.0-flash-exp",
            "fast": "gemini-2.0-flash-exp",
            "smart": "gemini-1.5-pro"
        },
        AIProvider.OPENAI: {
            "default": "gpt-4o-mini",
            "fast": "gpt-4o-mini",
            "smart": "gpt-4o"
        },
        AIProvider.ANTHROPIC: {
            "default": "claude-3-5-sonnet-20241022",
            "fast": "claude-3-5-haiku-20241022",
            "smart": "claude-3-5-sonnet-20241022"
        },
        AIProvider.GROQ: {
            "default": "llama-3.3-70b-versatile",
            "fast": "llama-3.3-70b-versatile",
            "smart": "llama-3.3-70b-versatile"
        }
    }
    
    def __init__(
        self,
        provider: str = None,
        api_key: str = None,
        model: str = None,
        config: Dict[str, Any] = None
    ):
        """
        Initialize AI Service
        
        Args:
            provider: AI provider name (gemini, openai, anthropic, groq)
            api_key: API key for the provider
            model: Specific model to use (optional, uses defaults)
            config: Additional configuration
        """
        self.config = config or {}
        
        # Determine provider (priority: param > config > env > default)
        self.provider = AIProvider(
            provider or 
            self.config.get('provider') or 
            os.getenv('AI_PROVIDER', 'gemini')
        )
        
        # Get API key
        self.api_key = self._resolve_api_key(api_key)
        
        # Get model
        self.model = model or self._get_default_model('default')
        
        # Initialize provider client
        self._init_provider()
        
        logger.info(f"AI Service initialized: {self.provider} / {self.model}")
    
    def _resolve_api_key(self, provided_key: str = None) -> Optional[str]:
        """Resolve API key from multiple sources"""
        # Priority: provided > config > env
        if provided_key:
            return provided_key
            
        if self.provider == AIProvider.GEMINI:
            return (
                self.config.get('gemini_api_key') or
                os.getenv('GEMINI_API_KEY') or
                os.getenv('GOOGLE_API_KEY')
            )
        elif self.provider == AIProvider.OPENAI:
            return (
                self.config.get('openai_api_key') or
                os.getenv('OPENAI_API_KEY')
            )
        elif self.provider == AIProvider.ANTHROPIC:
            return (
                self.config.get('anthropic_api_key') or
                os.getenv('ANTHROPIC_API_KEY')
            )
        elif self.provider == AIProvider.GROQ:
            return (
                self.config.get('groq_api_key') or
                os.getenv('GROQ_API_KEY')
            )
        
        return None
    
    def _get_default_model(self, tier: str = 'default') -> str:
        """Get default model for provider and tier"""
        return self.DEFAULT_MODELS.get(self.provider, {}).get(tier, 'default')
    
    def _init_provider(self):
        """Initialize the specific provider"""
        if self.provider == AIProvider.GEMINI:
            self._init_gemini()
        elif self.provider == AIProvider.OPENAI:
            self._init_openai()
        elif self.provider == AIProvider.ANTHROPIC:
            self._init_anthropic()
        elif self.provider == AIProvider.GROQ:
            self._init_groq()
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _init_gemini(self):
        """Initialize Google Gemini"""
        try:
            import google.generativeai as genai
            
            if not self.api_key:
                logger.warning("No Gemini API key provided")
                return
                
            genai.configure(api_key=self.api_key)
            self.client = genai.GenerativeModel(self.model)
            logger.info(f"Gemini configured: {self.model}")
            
        except ImportError:
            raise ImportError("google-generativeai package required. Install: pip install google-generativeai")
    
    def _init_openai(self):
        """Initialize OpenAI"""
        try:
            import openai
            
            if not self.api_key:
                logger.warning("No OpenAI API key provided")
                return
                
            openai.api_key = self.api_key
            self.client = openai
            logger.info(f"OpenAI configured: {self.model}")
            
        except ImportError:
            raise ImportError("openai package required. Install: pip install openai")
    
    def _init_anthropic(self):
        """Initialize Anthropic Claude"""
        try:
            import anthropic
            
            if not self.api_key:
                logger.warning("No Anthropic API key provided")
                return
                
            self.client = anthropic.Anthropic(api_key=self.api_key)
            logger.info(f"Anthropic configured: {self.model}")
            
        except ImportError:
            raise ImportError("anthropic package required. Install: pip install anthropic")
    
    def _init_groq(self):
        """Initialize Groq"""
        try:
            import openai  # Groq uses OpenAI client
            
            if not self.api_key:
                logger.warning("No Groq API key provided")
                return
            
            # Groq uses OpenAI-compatible API
            self.client = openai.OpenAI(
                api_key=self.api_key,
                base_url="https://api.groq.com/openai/v1"
            )
            logger.info(f"Groq configured: {self.model}")
            
        except ImportError:
            raise ImportError("openai package required for Groq. Install: pip install openai")
    
    async def generate(
        self,
        prompt: str,
        system: str = None,
        max_tokens: int = 2000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """
        Universal generation method across all providers
        
        Args:
            prompt: User prompt
            system: System instruction (optional)
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Provider-specific arguments
        
        Returns:
            Generated text
        """
        try:
            if self.provider == AIProvider.GEMINI:
                return await self._generate_gemini(prompt, system, **kwargs)
            elif self.provider == AIProvider.OPENAI:
                return await self._generate_openai(prompt, system, max_tokens, temperature, **kwargs)
            elif self.provider == AIProvider.ANTHROPIC:
                return await self._generate_anthropic(prompt, system, max_tokens, temperature, **kwargs)
            elif self.provider == AIProvider.GROQ:
                return await self._generate_groq(prompt, system, max_tokens, temperature, **kwargs)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
                
        except Exception as e:
            logger.error(f"AI generation error ({self.provider}): {e}")
            raise
    
    async def _generate_gemini(self, prompt: str, system: str = None, **kwargs) -> str:
        """Generate with Gemini"""
        full_prompt = prompt
        if system:
            full_prompt = f"{system}\n\n{prompt}"
        
        response = await self.client.generate_content_async(full_prompt)
        return response.text
    
    async def _generate_openai(
        self,
        prompt: str,
        system: str = None,
        max_tokens: int = 2000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate with OpenAI"""
        messages = []
        
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        response = await self.client.ChatCompletion.acreate(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )
        
        return response.choices[0].message.content
    
    async def _generate_anthropic(
        self,
        prompt: str,
        system: str = None,
        max_tokens: int = 2000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate with Anthropic"""
        message = await asyncio.to_thread(
            self.client.messages.create,
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system or "You are a helpful AI assistant.",
            messages=[{"role": "user", "content": prompt}],
            **kwargs
        )
        
        return message.content[0].text
    
    async def _generate_groq(
        self,
        prompt: str,
        system: str = None,
        max_tokens: int = 2000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate with Groq"""
        messages = []
        
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )
        
        return response.choices[0].message.content
    
    def get_available_models(self) -> List[str]:
        """Get list of available models for current provider"""
        return list(self.DEFAULT_MODELS.get(self.provider, {}).values())
    
    @staticmethod
    def get_all_providers() -> List[Dict[str, Any]]:
        """Get list of all supported providers with metadata"""
        return [
            {
                "id": "gemini",
                "name": "Google Gemini",
                "free_tier": True,
                "models": ["gemini-2.0-flash-exp", "gemini-1.5-pro", "gemini-1.5-flash"]
            },
            {
                "id": "openai",
                "name": "OpenAI",
                "free_tier": False,
                "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"]
            },
            {
                "id": "anthropic",
                "name": "Anthropic Claude",
                "free_tier": False,
                "models": ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"]
            },
            {
                "id": "groq",
                "name": "Groq",
                "free_tier": True,
                "models": ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"]
            }
        ]


# Global AI service instance (can be reconfigured)
_ai_service: Optional[AIService] = None


def get_ai_service(
    provider: str = None,
    api_key: str = None,
    model: str = None,
    config: Dict[str, Any] = None
) -> AIService:
    """
    Get or create AI service instance
    
    If no parameters provided, returns existing instance or creates default.
    If parameters provided, creates new instance with those settings.
    """
    global _ai_service
    
    # If specific config provided, create new instance
    if any([provider, api_key, model, config]):
        return AIService(provider, api_key, model, config)
    
    # Otherwise return or create default instance
    if _ai_service is None:
        _ai_service = AIService()
    
    return _ai_service


def set_ai_service(service: AIService):
    """Set global AI service instance"""
    global _ai_service
    _ai_service = service
