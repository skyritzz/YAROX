import httpx
import json

class LLMService:
    def __init__(self, model="llama3.1", base_url="http://host.docker.internal:11434"):
        self.model = model
        self.base_url = base_url

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

llm_service = LLMService()
