from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from vibewall.config import VibewallConfig
from vibewall.models import ValidationResult
from vibewall.proxy.addon import VibewallAddon


class TestExtractPackageName:
    def test_simple_package(self) -> None:
        assert VibewallAddon._extract_package_name("/lodash") == "lodash"

    def test_scoped_package(self) -> None:
        assert VibewallAddon._extract_package_name("/@babel/core") == "@babel/core"

    def test_scoped_with_subpath(self) -> None:
        assert VibewallAddon._extract_package_name("/@scope/name/-/name-1.0.0.tgz") == "@scope/name"

    def test_package_with_version(self) -> None:
        assert VibewallAddon._extract_package_name("/lodash/4.17.21") == "lodash"

    def test_empty_path(self) -> None:
        assert VibewallAddon._extract_package_name("/") is None

    def test_root(self) -> None:
        assert VibewallAddon._extract_package_name("") is None


@pytest.mark.asyncio
async def test_npm_request_blocked() -> None:
    config = VibewallConfig()
    npm_validator = AsyncMock()
    npm_validator.validate = AsyncMock(return_value=ValidationResult.block("hallucinated package"))
    url_validator = AsyncMock()

    addon = VibewallAddon(config, npm_validator, url_validator)

    flow = MagicMock()
    flow.request.pretty_host = "registry.npmjs.org"
    flow.request.pretty_url = "https://registry.npmjs.org/fake-pkg"
    flow.request.path = "/fake-pkg"
    flow.response = None

    await addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403
    body = json.loads(flow.response.content)
    assert body["error"] == "blocked by vibewall"


@pytest.mark.asyncio
async def test_npm_request_allowed() -> None:
    config = VibewallConfig()
    npm_validator = AsyncMock()
    npm_validator.validate = AsyncMock(return_value=ValidationResult.allow("ok"))
    url_validator = AsyncMock()

    addon = VibewallAddon(config, npm_validator, url_validator)

    flow = MagicMock()
    flow.request.pretty_host = "registry.npmjs.org"
    flow.request.pretty_url = "https://registry.npmjs.org/lodash"
    flow.request.path = "/lodash"
    flow.response = None

    await addon.request(flow)
    # Response should not be set (request passes through)
    assert flow.response is None


@pytest.mark.asyncio
async def test_url_validation_for_non_npm() -> None:
    config = VibewallConfig()
    npm_validator = AsyncMock()
    url_validator = AsyncMock()
    url_validator.validate = AsyncMock(return_value=ValidationResult.block("DNS failed"))

    addon = VibewallAddon(config, npm_validator, url_validator)

    flow = MagicMock()
    flow.request.pretty_host = "malicious.example.test"
    flow.request.pretty_url = "https://malicious.example.test/payload"
    flow.request.path = "/payload"
    flow.response = None

    await addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403


@pytest.mark.asyncio
async def test_warn_mode_does_not_block() -> None:
    config = VibewallConfig()
    config.npm.mode = "warn"
    npm_validator = AsyncMock()
    npm_validator.validate = AsyncMock(return_value=ValidationResult.block("suspicious"))
    url_validator = AsyncMock()

    addon = VibewallAddon(config, npm_validator, url_validator)

    flow = MagicMock()
    flow.request.pretty_host = "registry.npmjs.org"
    flow.request.pretty_url = "https://registry.npmjs.org/sus-pkg"
    flow.request.path = "/sus-pkg"
    flow.response = None

    await addon.request(flow)
    # In warn mode, response should not be set (request passes through)
    assert flow.response is None
