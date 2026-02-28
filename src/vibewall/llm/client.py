from __future__ import annotations

import asyncio

import anthropic
import openai
import structlog

from vibewall.config import LlmConfig
from vibewall.exceptions import LlmError

logger = structlog.get_logger()


class LlmClient:
    def __init__(self, config: LlmConfig) -> None:
        self._config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent)

        if config.provider == "anthropic":
            self._anthropic = anthropic.AsyncAnthropic(
                api_key=config.api_key,
                base_url=config.base_url,
                timeout=float(config.timeout),
            )
            self._openai: openai.AsyncOpenAI | None = None
        else:
            self._anthropic = None  # type: ignore[assignment]
            self._openai = openai.AsyncOpenAI(
                api_key=config.api_key,
                base_url=config.base_url,
                timeout=float(config.timeout),
            )

    async def ask(self, system_prompt: str, user_prompt: str) -> str:
        async with self._semaphore:
            if self._config.provider == "anthropic":
                return await self._ask_anthropic(system_prompt, user_prompt)
            return await self._ask_openai(system_prompt, user_prompt)

    async def _ask_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = await self._anthropic.messages.create(
                model=self._config.model,
                max_tokens=self._config.max_tokens,
                temperature=self._config.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except anthropic.APIError as e:
            raise LlmError(f"Anthropic API error: {e}") from e

        if not response.content:
            raise LlmError(f"unexpected Anthropic response: no content blocks")
        block = response.content[0]
        if block.type != "text":
            raise LlmError(f"unexpected Anthropic content block type: {block.type}")
        return block.text

    async def _ask_openai(self, system_prompt: str, user_prompt: str) -> str:
        assert self._openai is not None
        try:
            response = await self._openai.chat.completions.create(
                model=self._config.model,
                max_tokens=self._config.max_tokens,
                temperature=self._config.temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
        except openai.APIError as e:
            raise LlmError(f"OpenAI API error: {e}") from e

        if not response.choices:
            raise LlmError(f"unexpected OpenAI response: no choices")
        text = response.choices[0].message.content
        if text is None:
            raise LlmError(f"missing content in OpenAI response message")
        return text
