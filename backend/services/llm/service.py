"""
Structured LLM generation.

Guarantees for callers:
  * every agent call is validated against a Pydantic schema before it is returned
  * malformed output is retried with the validation error fed back to the model
  * transport failures and timeouts are retried with exponential backoff and jitter
  * concurrency is bounded per process, because a local model server serves a small
    number of requests at a time and unbounded fan-out produced timeouts
  * exhausted retries raise a typed error; a caller never receives fabricated content
"""
import asyncio
import json
import logging
import random
import re
import time
from typing import Any, Dict, Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

from core.config import settings
from services.llm.providers import (
    LLMError,
    LLMInvalidOutput,
    LLMProvider,
    LLMUnavailable,
    build_provider,
)

logger = logging.getLogger("yarox.llm")

T = TypeVar("T", bound=BaseModel)

CODE_FENCE = re.compile(r"^\s*```(?:json|JSON)?\s*(.*?)\s*```\s*$", re.DOTALL)


def strip_code_fences(text: str) -> str:
    """Removes ```json ... ``` wrappers that models add around JSON."""
    if not isinstance(text, str):
        return ""
    match = CODE_FENCE.match(text.strip())
    return match.group(1).strip() if match else text.strip()


def extract_json_object(text: str) -> str:
    """
    Returns the JSON document in ``text``. Handles fenced blocks and prose before or
    after the object by taking the outermost balanced {...} span.
    """
    cleaned = strip_code_fences(text)
    if cleaned.startswith("{") and cleaned.endswith("}"):
        return cleaned
    start = cleaned.find("{")
    if start == -1:
        return cleaned
    depth, in_string, escaped = 0, False, False
    for index in range(start, len(cleaned)):
        char = cleaned[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return cleaned[start:index + 1]
    return cleaned


class LLMService:
    def __init__(self, provider: Optional[LLMProvider] = None, max_concurrency: Optional[int] = None):
        self._provider = provider
        self._semaphore = asyncio.Semaphore(max_concurrency or settings.LLM_MAX_CONCURRENCY)
        self._semaphore_limit = max_concurrency or settings.LLM_MAX_CONCURRENCY

    @property
    def provider(self) -> LLMProvider:
        if self._provider is None:
            self._provider = build_provider(settings)
        return self._provider

    async def generate(self, prompt: str, context: str = "", json_format: bool = False) -> str:
        """
        Single raw generation: bounded concurrency plus a hard timeout, no validation.
        ``generate_structured`` builds on this, so a caller (or test) that substitutes
        ``generate`` substitutes the model for the whole stack.
        """
        full_prompt = f"Context: {context}\n\nTask: {prompt}" if context else prompt
        async with self._semaphore:
            started = time.perf_counter()
            try:
                return await asyncio.wait_for(
                    self.provider.generate(full_prompt, json_output=json_format, context_tokens=settings.LLM_CONTEXT_TOKENS),
                    timeout=settings.LLM_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError as e:
                raise LLMUnavailable(f"LLM request timed out after {settings.LLM_TIMEOUT_SECONDS:.0f}s") from e
            finally:
                logger.debug("LLM call took %.1f ms", (time.perf_counter() - started) * 1000)

    async def generate_structured(
        self,
        prompt: str,
        schema: Type[T],
        *,
        max_attempts: Optional[int] = None,
    ) -> T:
        """
        Generates output validated against ``schema``.

        Raises LLMUnavailable if the provider never produced a response, or
        LLMInvalidOutput if it responded but never produced schema-valid content.
        """
        attempts = max_attempts or settings.LLM_MAX_ATTEMPTS
        current_prompt = prompt
        last_error: Optional[Exception] = None

        for attempt in range(1, attempts + 1):
            try:
                raw = await self.generate(current_prompt, json_format=True)
            except LLMUnavailable as e:
                last_error = e
                logger.warning("LLM attempt %d/%d failed: %s", attempt, attempts, e)
                await self._backoff(attempt, attempts)
                continue

            try:
                payload = json.loads(extract_json_object(raw))
            except json.JSONDecodeError as e:
                last_error = LLMInvalidOutput(f"response was not valid JSON: {e}")
                current_prompt = self._correction_prompt(prompt, raw, str(last_error))
                logger.warning("LLM attempt %d/%d returned invalid JSON", attempt, attempts)
                await self._backoff(attempt, attempts)
                continue

            try:
                return schema.model_validate(payload)
            except ValidationError as e:
                summary = "; ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()[:5])
                last_error = LLMInvalidOutput(f"response did not match {schema.__name__}: {summary}")
                current_prompt = self._correction_prompt(prompt, raw, summary)
                logger.warning("LLM attempt %d/%d failed schema validation: %s", attempt, attempts, summary)
                await self._backoff(attempt, attempts)

        if isinstance(last_error, LLMInvalidOutput):
            raise LLMInvalidOutput(f"LLM produced no schema-valid output after {attempts} attempts: {last_error}")
        raise LLMUnavailable(f"LLM produced no response after {attempts} attempts: {last_error}")

    @staticmethod
    def _correction_prompt(original_prompt: str, previous_output: str, problem: str) -> str:
        return (
            f"{original_prompt}\n\n"
            f"<previous_attempt_rejected>\n"
            f"Your previous response was rejected: {problem}\n"
            f"Previous response (truncated): {previous_output[:800]}\n"
            f"Return ONLY a corrected JSON object that satisfies the required format.\n"
            f"</previous_attempt_rejected>"
        )

    @staticmethod
    async def _backoff(attempt: int, attempts: int) -> None:
        if attempt >= attempts:
            return
        delay = min(settings.LLM_RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), settings.LLM_RETRY_MAX_DELAY_SECONDS)
        await asyncio.sleep(delay * (0.5 + random.random() / 2))  # jitter

    def describe(self) -> Dict[str, Any]:
        info = self.provider.describe()
        info.update({
            "max_attempts": settings.LLM_MAX_ATTEMPTS,
            "timeout_seconds": settings.LLM_TIMEOUT_SECONDS,
            "max_concurrency": self._semaphore_limit,
            "context_tokens": settings.LLM_CONTEXT_TOKENS,
        })
        return info


llm_service = LLMService()
