from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from vibewall.cache.store import SQLiteCache
from vibewall.config import VibewallConfig
from vibewall.validators.allowlist import AllowBlockList


@pytest.fixture
async def cache() -> SQLiteCache:
    c = SQLiteCache(db_path=":memory:")
    await c.open()
    yield c
    await c.close()


@pytest.fixture
def config() -> VibewallConfig:
    return VibewallConfig.load(None)


@pytest.fixture
def npm_lists(tmp_path: Path) -> AllowBlockList:
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("lodash\nexpress\nreact\n@babel/core\n")
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("evil-package\n")
    return AllowBlockList(allowlist, blocklist)


@pytest.fixture
def pypi_lists(tmp_path: Path) -> AllowBlockList:
    allowlist = tmp_path / "pypi_allowlist.txt"
    allowlist.write_text("requests\nflask\ndjango\nnumpy\npandas\n")
    blocklist = tmp_path / "pypi_blocklist.txt"
    blocklist.write_text("evil-package\n")
    return AllowBlockList(allowlist, blocklist)


@pytest.fixture
def url_lists(tmp_path: Path) -> AllowBlockList:
    allowlist = tmp_path / "url_allowlist.txt"
    allowlist.write_text("github.com\nnpmjs.org\n")
    blocklist = tmp_path / "url_blocklist.txt"
    blocklist.write_text("evil.example.com\n")
    return AllowBlockList(allowlist, blocklist)


@pytest.fixture
def mock_session() -> AsyncMock:
    session = AsyncMock()
    session.closed = False
    return session
