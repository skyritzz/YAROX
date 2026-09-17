"""
Structured LLM generation: parsing, schema validation, retries, typed failures,
bounded concurrency and provider selection.
"""
import asyncio
import json

import pytest
from pydantic import BaseModel, Field

from core.config import settings
from services.llm.providers import (
    AnthropicProvider,
    ProviderAvailability,
    LLMConfigurationError,
    LLMInvalidOutput,
    LLMProvider,
    LLMUnavailable,
    OllamaProvider,
    VLLMProvider,
    build_provider,
)
from services.llm.service import LLMService, extract_json_object, strip_code_fences


class Answer(BaseModel):
    severity: str
    score: float = Field(..., ge=0.0, le=1.0)


class ScriptedProvider(LLMProvider):
    """Returns queued responses; an exception in the queue is raised instead."""

    name = "scripted"

    def __init__(self, responses, delay: float = 0.0):
        super().__init__(model="scripted-model", base_url="http://scripted", timeout_seconds=5)
        self.responses = list(responses)
        self.prompts = []
        self.delay = delay
        self.in_flight = 0
        self.max_in_flight = 0

    async def generate(self, prompt: str, *, json_output: bool = False, context_tokens=None) -> str:
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            self.prompts.append(prompt)
            if self.delay:
                await asyncio.sleep(self.delay)
            item = self.responses.pop(0) if self.responses else '{"severity": "LOW", "score": 0.1}'
            if isinstance(item, Exception):
                raise item
            return item
        finally:
            self.in_flight -= 1

    async def availability(self) -> ProviderAvailability:
        return ProviderAvailability(True, True, "scripted")


@pytest.fixture(autouse=True)
def fast_retries():
    original = settings.LLM_RETRY_BASE_DELAY_SECONDS
    object.__setattr__(settings, "LLM_RETRY_BASE_DELAY_SECONDS", 0.01)
    yield
    object.__setattr__(settings, "LLM_RETRY_BASE_DELAY_SECONDS", original)


# ---------------------------------------------------------------- parsing

@pytest.mark.parametrize("raw,expected", [
    ('```json\n{"a": 1}\n```', '{"a": 1}'),
    ('```\n{"a": 1}\n```', '{"a": 1}'),
    ('{"a": 1}', '{"a": 1}'),
    ('  {"a": 1}  ', '{"a": 1}'),
])
def test_strip_code_fences(raw, expected):
    assert strip_code_fences(raw) == expected


@pytest.mark.parametrize("raw", [
    'Here is the JSON you asked for:\n```json\n{"severity": "HIGH", "score": 0.9}\n```\nHope that helps!',
    'Sure! {"severity": "HIGH", "score": 0.9}',
    '{"severity": "HIGH", "score": 0.9}\n\nLet me know if you need more.',
    '{"severity": "HIGH", "score": 0.9}',
])
def test_extract_json_object_handles_prose_and_fences(raw):
    assert json.loads(extract_json_object(raw)) == {"severity": "HIGH", "score": 0.9}


def test_extract_json_object_keeps_nested_braces_and_strings():
    raw = '{"summary": "contains } brace", "nested": {"k": [1, 2]}}'
    assert json.loads(extract_json_object(raw))["nested"] == {"k": [1, 2]}


# ---------------------------------------------------------------- validation and retries

@pytest.mark.asyncio
async def test_valid_output_is_returned_as_a_model():
    provider = ScriptedProvider(['{"severity": "HIGH", "score": 0.8}'])
    result = await LLMService(provider=provider).generate_structured("prompt", Answer)
    assert isinstance(result, Answer)
    assert result.severity == "HIGH" and result.score == 0.8


@pytest.mark.asyncio
async def test_invalid_json_is_retried_and_the_model_is_told_why():
    provider = ScriptedProvider(["not json at all", '{"severity": "HIGH", "score": 0.8}'])
    result = await LLMService(provider=provider).generate_structured("original prompt", Answer)
    assert result.severity == "HIGH"
    assert len(provider.prompts) == 2
    assert "previous_attempt_rejected" in provider.prompts[1]
    assert "not valid JSON" in provider.prompts[1]


@pytest.mark.asyncio
async def test_schema_violation_is_retried_with_the_validation_error():
    provider = ScriptedProvider([
        '{"severity": "HIGH"}',                      # missing score
        '{"severity": "HIGH", "score": 7}',          # out of range
        '{"severity": "HIGH", "score": 0.7}',
    ])
    result = await LLMService(provider=provider).generate_structured("prompt", Answer)
    assert result.score == 0.7
    assert "score" in provider.prompts[1]
    assert "less than or equal to 1" in provider.prompts[2]


@pytest.mark.asyncio
async def test_persistent_schema_violation_raises_typed_error_and_never_fabricates():
    provider = ScriptedProvider(['{"severity": "HIGH"}'] * 5)
    with pytest.raises(LLMInvalidOutput) as excinfo:
        await LLMService(provider=provider).generate_structured("prompt", Answer)
    assert "no schema-valid output after 3 attempts" in str(excinfo.value)
    assert len(provider.prompts) == 3


@pytest.mark.asyncio
async def test_transport_failure_is_retried_then_raises_unavailable():
    provider = ScriptedProvider([LLMUnavailable("connection refused")] * 5)
    with pytest.raises(LLMUnavailable) as excinfo:
        await LLMService(provider=provider).generate_structured("prompt", Answer)
    assert "no response after 3 attempts" in str(excinfo.value)
    assert len(provider.prompts) == 3


@pytest.mark.asyncio
async def test_transient_failure_then_success():
    provider = ScriptedProvider([LLMUnavailable("timeout"), '{"severity": "LOW", "score": 0.2}'])
    result = await LLMService(provider=provider).generate_structured("prompt", Answer)
    assert result.severity == "LOW"


@pytest.mark.asyncio
async def test_timeout_is_converted_to_a_typed_unavailable_error():
    class SlowProvider(ScriptedProvider):
        async def generate(self, prompt, *, json_output=False, context_tokens=None):
            await asyncio.sleep(5)
            return "{}"

    original = settings.LLM_TIMEOUT_SECONDS
    object.__setattr__(settings, "LLM_TIMEOUT_SECONDS", 0.1)
    try:
        with pytest.raises(LLMUnavailable, match="timed out"):
            await LLMService(provider=SlowProvider([])).generate_structured("prompt", Answer, max_attempts=1)
    finally:
        object.__setattr__(settings, "LLM_TIMEOUT_SECONDS", original)


# ---------------------------------------------------------------- concurrency

@pytest.mark.asyncio
async def test_concurrency_is_bounded():
    provider = ScriptedProvider(['{"severity": "LOW", "score": 0.1}'] * 8, delay=0.1)
    service = LLMService(provider=provider, max_concurrency=2)
    await asyncio.gather(*(service.generate_structured("p", Answer) for _ in range(6)))
    assert provider.max_in_flight <= 2


# ---------------------------------------------------------------- provider selection

class _Settings:
    LLM_PROVIDER = "ollama"
    LLM_MODEL = "llama3.1"
    LLM_BASE_URL = ""
    OLLAMA_BASE_URL = "http://ollama:11434"
    VLLM_BASE_URL = "http://vllm:8000"
    ANTHROPIC_BASE_URL = "https://api.anthropic.com"
    ANTHROPIC_API_KEY = ""
    LLM_ALLOW_EXTERNAL_PROVIDERS = False
    LLM_TIMEOUT_SECONDS = 30.0


def test_default_provider_is_local_ollama():
    provider = build_provider(_Settings())
    assert isinstance(provider, OllamaProvider)
    assert provider.base_url == "http://ollama:11434"


def test_vllm_provider_selected_from_settings():
    cfg = _Settings()
    cfg.LLM_PROVIDER = "vllm"
    provider = build_provider(cfg)
    assert isinstance(provider, VLLMProvider)
    assert provider.base_url == "http://vllm:8000"


def test_external_provider_requires_explicit_opt_in():
    cfg = _Settings()
    cfg.LLM_PROVIDER = "anthropic"
    cfg.ANTHROPIC_API_KEY = "test-key"
    with pytest.raises(LLMConfigurationError, match="outside the deployment"):
        build_provider(cfg)

    cfg.LLM_ALLOW_EXTERNAL_PROVIDERS = True
    assert isinstance(build_provider(cfg), AnthropicProvider)


def test_external_provider_requires_credentials():
    cfg = _Settings()
    cfg.LLM_PROVIDER = "anthropic"
    cfg.LLM_ALLOW_EXTERNAL_PROVIDERS = True
    with pytest.raises(LLMConfigurationError, match="ANTHROPIC_API_KEY"):
        build_provider(cfg)


def test_unknown_provider_is_rejected():
    cfg = _Settings()
    cfg.LLM_PROVIDER = "definitely-not-a-provider"
    with pytest.raises(LLMConfigurationError, match="Unknown LLM provider"):
        build_provider(cfg)


def test_configured_provider_is_local_by_default_in_this_deployment():
    assert settings.LLM_PROVIDER == "ollama"
    assert settings.LLM_ALLOW_EXTERNAL_PROVIDERS is False
