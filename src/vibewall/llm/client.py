from __future__ import annotations

import asyncio
import random

import aiohttp
import structlog

from vibewall.config import LlmConfig

logger = structlog.get_logger()

_DEFAULT_ANTHROPIC_URL = "https://api.anthropic.com"
_DEFAULT_OPENAI_URL = "https://api.openai.com"
_TIMEOUT = aiohttp.ClientTimeout(total=30)

_RETRYABLE_STATUSES = {429, 500, 502, 503, 529}
_MAX_RETRIES = 3


class LlmClient:
    def __init__(self, config: LlmConfig, session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = session
        self._semaphore = asyncio.Semaphore(config.max_concurrent)

    async def ask(self, system_prompt: str, user_prompt: str) -> str:
        async with self._semaphore:
            if self._config.provider == "anthropic":
                return await self._ask_anthropic(system_prompt, user_prompt)
            return await self._ask_openai(system_prompt, user_prompt)

    async def _request_with_retry(
        self, url: str, headers: dict, payload: dict
    ) -> dict:
        last_exc: BaseException | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                async with self._session.post(
                    url, json=payload, headers=headers, timeout=_TIMEOUT
                ) as resp:
                    if resp.status in _RETRYABLE_STATUSES:
                        body = await resp.text()
                        logger.warning(
                            "llm_request_retryable_status",
                            status=resp.status,
                            attempt=attempt + 1,
                            url=url,
                            body=body[:200],
                        )
                        last_exc = aiohttp.ClientResponseError(
                            resp.request_info,
                            resp.history,
                            status=resp.status,
                            message=f"HTTP {resp.status}",
                        )
                    else:
                        resp.raise_for_status()
                        return await resp.json()
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(
                    "llm_request_error",
                    error=str(e),
                    attempt=attempt + 1,
                    url=url,
                )
                last_exc = e

            if attempt < _MAX_RETRIES - 1:
                backoff = 0.5 * (2 ** attempt) + random.uniform(0, 0.5)
                logger.info(
                    "llm_request_retry_backoff",
                    backoff_s=round(backoff, 2),
                    attempt=attempt + 1,
                )
                await asyncio.sleep(backoff)

        logger.error(
            "llm_request_failed_all_retries",
            url=url,
            retries=_MAX_RETRIES,
        )
        raise last_exc  # type: ignore[misc]

    async def _ask_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        base = self._config.base_url or _DEFAULT_ANTHROPIC_URL
        url = f"{base}/v1/messages"
        headers = {
            "x-api-key": self._config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self._config.model,
            "max_tokens": self._config.max_tokens,
            "temperature": self._config.temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        data = await self._request_with_retry(url, headers, payload)
        content = data.get("content")
        if not content or not isinstance(content, list):
            raise ValueError(f"unexpected Anthropic response structure: {data!r}")
        text = content[0].get("text")
        if text is None:
            raise ValueError(f"missing 'text' in Anthropic response content: {content!r}")
        return text

    async def _ask_openai(self, system_prompt: str, user_prompt: str) -> str:
        base = self._config.base_url or _DEFAULT_OPENAI_URL
        url = f"{base}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "content-type": "application/json",
        }
        payload = {
            "model": self._config.model,
            "max_tokens": self._config.max_tokens,
            "temperature": self._config.temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        data = await self._request_with_retry(url, headers, payload)
        choices = data.get("choices")
        if not choices or not isinstance(choices, list):
            raise ValueError(f"unexpected OpenAI response structure: {data!r}")
        message = choices[0].get("message", {})
        text = message.get("content")
        if text is None:
            raise ValueError(f"missing 'content' in OpenAI response message: {message!r}")
        return text
