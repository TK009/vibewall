from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from vibewall.config import VibewallConfig
from vibewall.models import RunResult, CheckResult
from vibewall.proxy.addon import VibewallAddon
from vibewall.validators.runner import CheckRunner


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

    def test_api_endpoint_dash(self) -> None:
        assert VibewallAddon._extract_package_name("/-/v1/search") is None

    def test_api_endpoint_npm(self) -> None:
        assert VibewallAddon._extract_package_name("/-/npm/v1/security/advisories") is None


@pytest.mark.asyncio
async def test_npm_request_blocked() -> None:
    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)
    runner.run = AsyncMock(return_value=RunResult(
        allowed=False,
        reason="hallucinated package",
        results=[("npm_existence", CheckResult.fail("hallucinated"))],
    ))

    addon = VibewallAddon(config, runner)

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
    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)
    runner.run = AsyncMock(return_value=RunResult(
        allowed=True, reason="all checks passed", results=[]
    ))

    addon = VibewallAddon(config, runner)

    flow = MagicMock()
    flow.request.pretty_host = "registry.npmjs.org"
    flow.request.pretty_url = "https://registry.npmjs.org/lodash"
    flow.request.path = "/lodash"
    flow.response = None

    await addon.request(flow)
    assert flow.response is None


@pytest.mark.asyncio
async def test_url_validation_for_non_npm() -> None:
    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)
    runner.run = AsyncMock(return_value=RunResult(
        allowed=False,
        reason="DNS failed",
        results=[("url_dns", CheckResult.fail("DNS failed"))],
    ))

    addon = VibewallAddon(config, runner)

    flow = MagicMock()
    flow.request.pretty_host = "malicious.example.test"
    flow.request.pretty_url = "https://malicious.example.test/payload"
    flow.request.path = "/payload"
    flow.response = None

    await addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403
