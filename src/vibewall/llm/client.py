from __future__ import annotations

import aiohttp
import structlog

from vibewall.config import LlmConfig

logger = structlog.get_logger()

_DEFAULT_ANTHROPIC_URL = "https://api.anthropic.com"
_DEFAULT_OPENAI_URL = "https://api.openai.com"
_TIMEOUT = aiohttp.ClientTimeout(total=30)


class LlmClient:
    def __init__(self, config: LlmConfig, session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = session

    async def ask(self, system_prompt: str, user_prompt: str) -> str:
        if self._config.provider == "anthropic":
            return await self._ask_anthropic(system_prompt, user_prompt)
        return await self._ask_openai(system_prompt, user_prompt)

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
        async with self._session.post(
            url, json=payload, headers=headers, timeout=_TIMEOUT
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data["content"][0]["text"]

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
        async with self._session.post(
            url, json=payload, headers=headers, timeout=_TIMEOUT
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data["choices"][0]["message"]["content"]
