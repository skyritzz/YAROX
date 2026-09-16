import httpx
import json
from core.config import settings

class LLMService:
    def __init__(self, model: str, base_url: str):
        self.model = model
        self.base_url = base_url.rstrip("/")

    async def generate(self, prompt: str, context: str = "", json_format: bool = False) -> str:
        async with httpx.AsyncClient(timeout=120.0) as client:
            payload = {
                "model": self.model,
                "prompt": f"Context: {context}\n\nTask: {prompt}",
                "stream": False
            }
            if json_format:
                payload["format"] = "json"
                
            try:
                response = await client.post(f"{self.base_url}/api/generate", json=payload)
                response.raise_for_status()
                return response.json().get("response", "")
            except Exception as e:
                print(f"LLM Error: {e}")
                return ""

llm_service = LLMService(model=settings.OLLAMA_MODEL, base_url=settings.OLLAMA_BASE_URL)
