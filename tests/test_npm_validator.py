from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from vibewall.cache.store import TTLCache
from vibewall.config import NpmConfig, CacheConfig
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.npm import NpmValidator


@pytest.fixture
def validator(npm_config: NpmConfig, cache_config: CacheConfig, cache: TTLCache, npm_lists: AllowBlockList) -> NpmValidator:
    return NpmValidator(npm_config, cache_config, cache, npm_lists)


def _mock_session_with(get_side_effect):
    """Create a mock aiohttp session with a given side_effect for .get()."""
    session = AsyncMock()
    session.get = MagicMock(side_effect=get_side_effect)
    session.closed = False
    return session


def _simple_response(status, json_data=None):
    """Create a mock response context manager."""
    resp = AsyncMock()
    resp.status = status
    if json_data is not None:
        resp.json = AsyncMock(return_value=json_data)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


@pytest.mark.asyncio
async def test_blocklisted_package(validator: NpmValidator) -> None:
    result = await validator.validate("evil-package")
    assert not result.allowed
    assert "blocklisted" in result.reason


@pytest.mark.asyncio
async def test_allowlisted_package(validator: NpmValidator) -> None:
    result = await validator.validate("lodash")
    assert result.allowed
    assert "allowlisted" in result.reason


@pytest.mark.asyncio
async def test_nonexistent_package_blocked(validator: NpmValidator) -> None:
    """A package that returns 404 from registry should be blocked."""
    validator._session = _mock_session_with(
        lambda url, **kw: _simple_response(404)
    )
    result = await validator.validate("nonexistent-pkg-xyz123")
    assert not result.allowed
    assert "does not exist" in result.reason or "hallucinated" in result.reason


@pytest.mark.asyncio
async def test_typosquat_blocked(validator: NpmValidator) -> None:
    """A package name close to an allowlisted package should be blocked as typosquat.

    Uses "expresx" (edit distance 1 from "express", length >= 6).
    """
    validator._session = _mock_session_with(
        lambda url, **kw: _simple_response(200, {"time": {"created": "2020-01-01T00:00:00Z"}})
    )
    result = await validator.validate("expresx")
    assert not result.allowed
    assert "typosquat" in result.reason


@pytest.mark.asyncio
async def test_short_name_skips_typosquat(validator: NpmValidator) -> None:
    """Short package names should not trigger typosquatting (too many false positives)."""
    def respond(url, **kw):
        if "downloads" in url:
            return _simple_response(200, {"downloads": 100000})
        return _simple_response(200, {"time": {"created": "2020-01-01T00:00:00Z"}})

    validator._session = _mock_session_with(respond)
    # "ract" is edit distance 1 from "react" but only 4 chars — should not flag
    result = await validator.validate("ract")
    assert result.allowed


@pytest.mark.asyncio
async def test_low_downloads_blocked(validator: NpmValidator) -> None:
    """A package with very few downloads should be blocked."""
    def respond(url, **kw):
        if "downloads" in url:
            return _simple_response(200, {"downloads": 2})
        return _simple_response(200, {"time": {"created": "2020-01-01T00:00:00Z"}})

    validator._session = _mock_session_with(respond)
    # Use a name far from any allowlisted name and long enough to pass typosquat filter
    result = await validator.validate("zzz-obscure-package-name")
    assert not result.allowed
    assert "downloads" in result.reason


@pytest.mark.asyncio
async def test_popular_package_allowed(validator: NpmValidator) -> None:
    """A package that passes all checks should be allowed."""
    def respond(url, **kw):
        if "downloads" in url:
            return _simple_response(200, {"downloads": 100000})
        return _simple_response(200, {"time": {"created": "2020-01-01T00:00:00Z"}})

    validator._session = _mock_session_with(respond)
    result = await validator.validate("zzz-some-legit-package")
    assert result.allowed
    assert "passed all checks" in result.reason


@pytest.mark.asyncio
async def test_cache_hit(validator: NpmValidator, cache: TTLCache) -> None:
    """Second validation should hit cache."""
    from vibewall.models import ValidationResult

    cached = ValidationResult.allow("cached result")
    cache.set("npm:some-pkg", cached, 3600)
    result = await validator.validate("some-pkg")
    assert result.allowed
    assert result.reason == "cached result"
