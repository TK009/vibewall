"""Shared test helpers used across multiple test files."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.base import BaseCheck


class StubCheck(BaseCheck):
    abbrev = "STB"

    def __init__(
        self,
        name: str,
        scope: str,
        depends_on: tuple[str, ...] | None = None,
        result: CheckResult | None = None,
        delay: float = 0,
    ):
        self.name = name
        self.scope = scope
        self.depends_on = depends_on or ()
        self._result = result or CheckResult.ok("stub ok")
        self._delay = delay
        self.call_count = 0

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        self.call_count += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        return self._result


class ExplodingCheck(StubCheck):
    """StubCheck that raises an exception instead of returning a result."""

    def __init__(self, *args, error: Exception | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._error = error or RuntimeError("boom")

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        self.call_count += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        raise self._error


class CustomTTLCheck(StubCheck):
    """StubCheck with a custom get_result_ttl."""

    def __init__(self, *args, ttl_map: dict[CheckStatus, int] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._ttl_map = ttl_map or {}

    def get_result_ttl(self, result: CheckResult, default_ttl: int) -> int:
        return self._ttl_map.get(result.status, default_ttl)


def _simple_response(status, json_data=None):
    resp = AsyncMock()
    resp.status = status
    if json_data is not None:
        resp.json = AsyncMock(return_value=json_data)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def _make_session(status=200, json_data=None):
    session = MagicMock()
    session.post = MagicMock(return_value=_simple_response(status, json_data))
    return session
