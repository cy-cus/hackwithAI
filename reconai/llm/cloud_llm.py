"""Cloud LLM Client for OpenAI and Gemini."""

import requests
import json
import logging

logger = logging.getLogger("hackwithai.llm")

class CloudLLM:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.provider = "openai" if api_key.startswith("sk-") else "google" if api_key.startswith("AIza") else "generic"

    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        """Analyze text using the detected provider."""
        if self.provider == "google":
            return self._call_gemini(system_prompt, user_prompt)
        else:
            return self._call_openai(system_prompt, user_prompt)

    def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "gpt-4-turbo-preview", # Default to capable model
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.4
            }
            resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=60)
            if resp.status_code != 200:
                # Try fallback model if 404/400? or just error
                return f"OpenAI Error: {resp.text}"
            
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"OpenAI Exception: {str(e)}"

    def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        """
        Gemini implementation with fallback logic similar to Kay Agent.
        Tries Pro model first for depth, falls back to Flash for speed/quota.
        """
        import time
        
        models = [
            "gemini-1.5-pro",   # Strongest reasoning
            "gemini-1.5-flash", # Fast fallback
            "gemini-pro"        # Legacy fallback
        ]
        
        last_error = ""
        
        for model in models:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
                headers = {"Content-Type": "application/json"}
                
                # Combine system and user prompt as Gemini REST API is stateless/simple
                full_prompt = f"System Instruction: {system_prompt}\n\nTask: {user_prompt}"
                
                payload = {
                    "contents": [{
                        "parts": [{"text": full_prompt}]
                    }],
                    "generationConfig": {
                        "temperature": 0.4,
                        "maxOutputTokens": 4096
                    }
                }
                
                resp = requests.post(url, headers=headers, json=payload, timeout=90)
                
                if resp.status_code == 200:
                    data = resp.json()
                    if "candidates" in data and data["candidates"]:
                        return data["candidates"][0]["content"]["parts"][0]["text"]
                    else:
                        # Safety block or empty
                        return "AI returned no content (Safety Filter likely triggered)"
                
                elif resp.status_code == 429: # Rate limit
                    logger.warning(f"Gemini {model} rate limited, switching model...")
                    time.sleep(1) # Brief pause
                    last_error = f"429 Rate Limit on {model}"
                    continue # Try next model
                else:
                    last_error = f"Gemini Error {resp.status_code}: {resp.text}"
                    continue
                    
            except Exception as e:
                last_error = f"Exception: {str(e)}"
                continue
        
        return f"Gemini Analysis Failed after trying all models. Last Error: {last_error}"
