from __future__ import annotations

import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from vibewall.cache.store import TTLCache
from vibewall.config import UrlConfig, CacheConfig
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.url import UrlValidator


@pytest.fixture
def url_lists(tmp_path) -> AllowBlockList:
    allowlist = tmp_path / "url_allowlist.txt"
    allowlist.write_text("github.com\nnpmjs.org\n")
    blocklist = tmp_path / "url_blocklist.txt"
    blocklist.write_text("evil.example.com\n")
    return AllowBlockList(allowlist, blocklist)


@pytest.fixture
def validator(url_config: UrlConfig, cache_config: CacheConfig, cache: TTLCache, url_lists: AllowBlockList) -> UrlValidator:
    return UrlValidator(url_config, cache_config, cache, url_lists)


@pytest.mark.asyncio
async def test_blocklisted_domain(validator: UrlValidator) -> None:
    result = await validator.validate("https://evil.example.com/payload")
    assert not result.allowed
    assert "blocklisted" in result.reason


@pytest.mark.asyncio
async def test_allowlisted_domain(validator: UrlValidator) -> None:
    result = await validator.validate("https://github.com/some/repo")
    assert result.allowed
    assert "allowlisted" in result.reason


@pytest.mark.asyncio
async def test_dns_failure_blocked(validator: UrlValidator) -> None:
    """A domain that fails DNS should be blocked."""
    async def fake_getaddrinfo(*args):
        raise socket.gaierror("Name resolution failed")

    loop_mock = MagicMock()
    loop_mock.getaddrinfo = fake_getaddrinfo

    with patch("asyncio.get_running_loop", return_value=loop_mock):
        result = await validator.validate("https://definitely-not-real.example.test/page")
    assert not result.allowed
    assert "DNS" in result.reason


@pytest.mark.asyncio
async def test_young_domain_blocked(validator: UrlValidator) -> None:
    """A domain registered very recently should be blocked."""
    # Mock DNS to succeed
    async def fake_getaddrinfo(*args):
        return [("AF_INET", None, None, None, ("1.2.3.4", 0))]

    loop_mock = MagicMock()
    loop_mock.getaddrinfo = fake_getaddrinfo

    # Mock HEAD to succeed (inject session directly on validator)
    mock_head_resp = AsyncMock()
    mock_head_resp.status = 200
    mock_head_resp.__aenter__ = AsyncMock(return_value=mock_head_resp)
    mock_head_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.head = MagicMock(return_value=mock_head_resp)
    mock_session.closed = False
    validator._session = mock_session

    # Mock WHOIS to return young domain
    young_date = datetime.now(timezone.utc) - timedelta(days=5)
    mock_whois = MagicMock()
    mock_whois.creation_date = young_date

    async def fake_run_in_executor(executor, fn, *args):
        return mock_whois

    loop_mock.run_in_executor = fake_run_in_executor

    with patch("asyncio.get_running_loop", return_value=loop_mock):
        result = await validator.validate("https://brand-new-suspicious-domain.xyz/malware")
    assert not result.allowed
    assert "days old" in result.reason


@pytest.mark.asyncio
async def test_head_client_error_fails_open(validator: UrlValidator) -> None:
    """A transient connection error on HEAD should fail open, not block."""
    import aiohttp

    # Mock DNS to succeed
    async def fake_getaddrinfo(*args):
        return [("AF_INET", None, None, None, ("1.2.3.4", 0))]

    loop_mock = MagicMock()
    loop_mock.getaddrinfo = fake_getaddrinfo

    # Mock HEAD to raise ClientError
    mock_session = AsyncMock()
    mock_session.head = MagicMock(side_effect=aiohttp.ClientError("connection reset"))
    mock_session.closed = False
    validator._session = mock_session

    # Mock WHOIS to return old domain
    old_date = datetime.now(timezone.utc) - timedelta(days=365)
    mock_whois = MagicMock()
    mock_whois.creation_date = old_date

    async def fake_run_in_executor(executor, fn, *args):
        return mock_whois

    loop_mock.run_in_executor = fake_run_in_executor

    with patch("asyncio.get_running_loop", return_value=loop_mock):
        result = await validator.validate("https://flaky-but-legit-site.com/page")
    # Key assertion: the request is allowed despite the HEAD error
    assert result.allowed
