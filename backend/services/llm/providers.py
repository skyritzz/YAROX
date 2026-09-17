"""
LLM provider abstraction.

Local inference is the default deployment model for security telemetry (see
docs/YAROX_ARCHITECTURAL_RECONSTRUCTION.md section 11: telemetry must not leave the
enterprise boundary). External providers exist behind an explicit opt-in
(``LLM_ALLOW_EXTERNAL_PROVIDERS``) and are never selected implicitly.

Every provider takes its model, endpoint and credentials from application settings.
"""
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("yarox.llm")


class LLMError(Exception):
    """Base class for LLM failures."""


class LLMUnavailable(LLMError):
    """The provider could not be reached, timed out, or returned a transport error."""


class LLMInvalidOutput(LLMError):
    """The provider responded, but the content could not be parsed or validated."""


class LLMConfigurationError(LLMError):
    """The configured provider cannot be used with the current settings."""


@dataclass
class ProviderAvailability:
    reachable: bool
    model_present: bool
    detail: str = ""


class LLMProvider(ABC):
    name: str

    def __init__(self, model: str, base_url: str, timeout_seconds: float):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    async def generate(self, prompt: str, *, json_output: bool = False, context_tokens: Optional[int] = None) -> str:
        """Returns the raw text the model produced. Raises LLMUnavailable on transport failures."""

    @abstractmethod
    async def availability(self) -> "ProviderAvailability":
        """Reachability and model presence, reported separately for /health."""

    async def is_available(self) -> bool:
        status = await self.availability()
        return status.reachable and status.model_present

    def describe(self) -> Dict[str, Any]:
        return {"provider": self.name, "model": self.model, "base_url": self.base_url}


class OllamaProvider(LLMProvider):
    """Local Ollama (default). No data leaves the host running Ollama."""

    name = "ollama"

    async def generate(self, prompt: str, *, json_output: bool = False, context_tokens: Optional[int] = None) -> str:
        payload: Dict[str, Any] = {"model": self.model, "prompt": prompt, "stream": False}
        if json_output:
            payload["format"] = "json"
        if context_tokens:
            # Ollama silently truncates prompts longer than the context window
            payload["options"] = {"num_ctx": context_tokens}
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(f"{self.base_url}/api/generate", json=payload)
                response.raise_for_status()
                return response.json().get("response", "")
        except httpx.HTTPStatusError as e:
            raise LLMUnavailable(f"Ollama returned HTTP {e.response.status_code}: {e.response.text[:200]}") from e
        except Exception as e:
            raise LLMUnavailable(f"Ollama request failed: {type(e).__name__}: {e}") from e

    async def availability(self) -> ProviderAvailability:
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout_seconds, 5.0)) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()
                names = {m.get("name", "") for m in response.json().get("models", [])}
        except Exception as e:
            return ProviderAvailability(False, False, f"unreachable: {type(e).__name__}")
        present = self.model in names or (":" not in self.model and f"{self.model}:latest" in names)
        return ProviderAvailability(True, present, "model installed" if present else f"model '{self.model}' is not installed")


class VLLMProvider(LLMProvider):
    """Local vLLM through its OpenAI-compatible API. Also local-only."""

    name = "vllm"

    async def generate(self, prompt: str, *, json_output: bool = False, context_tokens: Optional[int] = None) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
        }
        if json_output:
            payload["response_format"] = {"type": "json_object"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(f"{self.base_url}/v1/chat/completions", json=payload)
                response.raise_for_status()
                data = response.json()
            return data["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as e:
            raise LLMUnavailable(f"vLLM returned HTTP {e.response.status_code}: {e.response.text[:200]}") from e
        except (KeyError, IndexError) as e:
            raise LLMInvalidOutput(f"Unexpected vLLM response shape: {e}") from e
        except Exception as e:
            raise LLMUnavailable(f"vLLM request failed: {type(e).__name__}: {e}") from e

    async def availability(self) -> ProviderAvailability:
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout_seconds, 5.0)) as client:
                response = await client.get(f"{self.base_url}/v1/models")
                response.raise_for_status()
                present = any(m.get("id") == self.model for m in response.json().get("data", []))
        except Exception as e:
            return ProviderAvailability(False, False, f"unreachable: {type(e).__name__}")
        return ProviderAvailability(True, present, "model served" if present else f"model '{self.model}' is not served")


class AnthropicProvider(LLMProvider):
    """
    External provider. Sending security telemetry outside the enterprise boundary is a
    deliberate decision: this provider is only constructed when
    ``LLM_ALLOW_EXTERNAL_PROVIDERS`` is true and an API key is configured.
    """

    name = "anthropic"

    def __init__(self, model: str, base_url: str, timeout_seconds: float, api_key: str):
        super().__init__(model, base_url, timeout_seconds)
        if not api_key:
            raise LLMConfigurationError("ANTHROPIC_API_KEY is required for the anthropic provider")
        self.api_key = api_key

    def _headers(self) -> Dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    async def generate(self, prompt: str, *, json_output: bool = False, context_tokens: Optional[int] = None) -> str:
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "temperature": 0.0,
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(f"{self.base_url}/v1/messages", json=payload, headers=self._headers())
                response.raise_for_status()
                data = response.json()
            return "".join(block.get("text", "") for block in data.get("content", []))
        except httpx.HTTPStatusError as e:
            raise LLMUnavailable(f"Anthropic returned HTTP {e.response.status_code}") from e
        except Exception as e:
            raise LLMUnavailable(f"Anthropic request failed: {type(e).__name__}: {e}") from e

    async def availability(self) -> ProviderAvailability:
        # No network probe: an external provider is not contacted just to report health
        return ProviderAvailability(bool(self.api_key), bool(self.api_key), "API key configured" if self.api_key else "no API key")


PROVIDERS = {
    OllamaProvider.name: OllamaProvider,
    VLLMProvider.name: VLLMProvider,
    AnthropicProvider.name: AnthropicProvider,
}
EXTERNAL_PROVIDERS = {AnthropicProvider.name}


def build_provider(settings) -> LLMProvider:
    """Builds the provider named by ``settings.LLM_PROVIDER``."""
    name = (settings.LLM_PROVIDER or "ollama").strip().lower()
    if name not in PROVIDERS:
        raise LLMConfigurationError(f"Unknown LLM provider '{name}'. Available: {sorted(PROVIDERS)}")
    if name in EXTERNAL_PROVIDERS and not settings.LLM_ALLOW_EXTERNAL_PROVIDERS:
        raise LLMConfigurationError(
            f"Provider '{name}' sends telemetry outside the deployment. Set LLM_ALLOW_EXTERNAL_PROVIDERS=true "
            f"to allow it explicitly."
        )
    if name == AnthropicProvider.name:
        return AnthropicProvider(
            model=settings.LLM_MODEL, base_url=settings.ANTHROPIC_BASE_URL,
            timeout_seconds=settings.LLM_TIMEOUT_SECONDS, api_key=settings.ANTHROPIC_API_KEY,
        )
    base_url = settings.LLM_BASE_URL or (settings.OLLAMA_BASE_URL if name == "ollama" else settings.VLLM_BASE_URL)
    return PROVIDERS[name](
        model=settings.LLM_MODEL, base_url=base_url, timeout_seconds=settings.LLM_TIMEOUT_SECONDS,
    )
