from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from vibewall.cache.store import SQLiteCache
from vibewall.config import VibewallConfig
from vibewall.validators.rules import RuleSet


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
def ruleset(tmp_path: Path) -> RuleSet:
    # Create list files
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("lodash\nexpress\nreact\n@babel/core\n")
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("evil-package\n")
    pypi_allowlist = tmp_path / "pypi_allowlist.txt"
    pypi_allowlist.write_text("requests\nflask\ndjango\nnumpy\npandas\n")
    pypi_blocklist = tmp_path / "pypi_blocklist.txt"
    pypi_blocklist.write_text("evil-package\n")
    url_allowlist = tmp_path / "url_allowlist.txt"
    url_allowlist.write_text("github.com\nnpmjs.org\n")
    url_blocklist = tmp_path / "url_blocklist.txt"
    url_blocklist.write_text("evil.example.com\n")

    # Create rules file that imports them
    rules = tmp_path / "rules.txt"
    rules.write_text(
        "@import blocklist.txt [block scope=npm]\n"
        "@import allowlist.txt [allow scope=npm]\n"
        "@import pypi_blocklist.txt [block scope=pypi]\n"
        "@import pypi_allowlist.txt [allow scope=pypi]\n"
        "@import url_blocklist.txt [block scope=url]\n"
        "@import url_allowlist.txt [allow scope=url]\n"
    )
    return RuleSet.load(rules, tmp_path)


@pytest.fixture
def mock_session() -> AsyncMock:
    session = AsyncMock()
    session.closed = False
    return session
