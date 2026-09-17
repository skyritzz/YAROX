"""
Backwards-compatible entry point for the LLM service.

The implementation lives in ``services/llm/``: provider abstraction (providers.py) and
structured, validated, retrying generation (service.py).
"""
from services.llm.providers import (  # noqa: F401
    LLMConfigurationError,
    LLMError,
    LLMInvalidOutput,
    LLMProvider,
    LLMUnavailable,
    build_provider,
)
from services.llm.service import LLMService, llm_service  # noqa: F401
