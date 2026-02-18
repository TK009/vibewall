from __future__ import annotations

from pathlib import Path

import pytest

from vibewall.cache.store import TTLCache
from vibewall.config import NpmConfig, UrlConfig, CacheConfig
from vibewall.validators.allowlist import AllowBlockList


@pytest.fixture
def cache() -> TTLCache:
    return TTLCache()


@pytest.fixture
def npm_config() -> NpmConfig:
    return NpmConfig()


@pytest.fixture
def url_config() -> UrlConfig:
    return UrlConfig()


@pytest.fixture
def cache_config() -> CacheConfig:
    return CacheConfig()


@pytest.fixture
def npm_lists(tmp_path: Path) -> AllowBlockList:
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("lodash\nexpress\nreact\n@babel/core\n")
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("evil-package\n")
    return AllowBlockList(allowlist, blocklist)
