from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from vibewall.config import VibewallConfig
from vibewall.models import PipelineResult, RunResult, CheckResult
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


class TestExtractNpmTarballInfo:
    def test_simple_tarball(self) -> None:
        assert VibewallAddon._extract_npm_tarball_info(
            "/lodash/-/lodash-4.17.21.tgz"
        ) == ("lodash", "4.17.21")

    def test_scoped_tarball(self) -> None:
        assert VibewallAddon._extract_npm_tarball_info(
            "/@babel/core/-/core-7.24.0.tgz"
        ) == ("@babel/core", "7.24.0")

    def test_prerelease_version(self) -> None:
        result = VibewallAddon._extract_npm_tarball_info(
            "/pkg/-/pkg-1.0.0-beta.1.tgz"
        )
        assert result is not None
        assert result[0] == "pkg"
        assert result[1] == "1.0.0-beta.1"

    def test_metadata_path_returns_none(self) -> None:
        assert VibewallAddon._extract_npm_tarball_info("/lodash") is None

    def test_api_endpoint_returns_none(self) -> None:
        assert VibewallAddon._extract_npm_tarball_info("/-/v1/search") is None


class TestExtractPypiDownloadInfo:
    def test_sdist(self) -> None:
        result = VibewallAddon._extract_pypi_download_info(
            "/packages/ab/cd/requests-2.28.0.tar.gz"
        )
        assert result == ("requests", "2.28.0")

    def test_wheel(self) -> None:
        result = VibewallAddon._extract_pypi_download_info(
            "/packages/ab/cd/requests-2.28.0-py3-none-any.whl"
        )
        assert result is not None
        assert result[0] == "requests"
        assert result[1] == "2.28.0"

    def test_normalized_name(self) -> None:
        result = VibewallAddon._extract_pypi_download_info(
            "/packages/ab/cd/My_Package-1.0.0.tar.gz"
        )
        assert result is not None
        assert result[0] == "my-package"

    def test_hyphenated_package_name(self) -> None:
        result = VibewallAddon._extract_pypi_download_info(
            "/packages/ab/cd/my-cool-package-1.0.0.tar.gz"
        )
        assert result == ("my-cool-package", "1.0.0")

    def test_multi_hyphen_package_name(self) -> None:
        result = VibewallAddon._extract_pypi_download_info(
            "/packages/ab/cd/azure-storage-blob-12.19.0.tar.gz"
        )
        assert result == ("azure-storage-blob", "12.19.0")

    def test_empty_path(self) -> None:
        assert VibewallAddon._extract_pypi_download_info("") is None


@pytest.mark.asyncio
async def test_pypi_download_runs_advisory_checks() -> None:
    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)
    runner.get_enabled_check_names = MagicMock(return_value=["pypi_advisories"])
    runner.run = AsyncMock(return_value=PipelineResult(
        run_result=RunResult(allowed=True, reason="no advisories", results=[]),
    ))

    addon = VibewallAddon(config, runner)

    flow = MagicMock()
    flow.request.pretty_host = "files.pythonhosted.org"
    flow.request.pretty_url = "https://files.pythonhosted.org/packages/ab/cd/requests-2.28.0.tar.gz"
    flow.request.path = "/packages/ab/cd/requests-2.28.0.tar.gz"
    flow.response = None

    await addon.request(flow)

    runner.run.assert_called_once()
    call_kwargs = runner.run.call_args
    assert call_kwargs.kwargs["version"] == "2.28.0"
    assert call_kwargs.kwargs["check_names"] == {"pypi_advisories"}


@pytest.mark.asyncio
async def test_npm_metadata_excludes_advisories() -> None:
    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)
    runner.get_enabled_check_names = MagicMock(
        return_value=["npm_rules", "npm_registry", "npm_advisories"]
    )
    runner.run = AsyncMock(return_value=PipelineResult(
        run_result=RunResult(allowed=True, reason="all checks passed", results=[]),
    ))

    addon = VibewallAddon(config, runner)

    flow = MagicMock()
    flow.request.pretty_host = "registry.npmjs.org"
    flow.request.pretty_url = "https://registry.npmjs.org/lodash"
    flow.request.path = "/lodash"
    flow.response = None

    await addon.request(flow)

    runner.run.assert_called_once()
    call_kwargs = runner.run.call_args
    # advisories should be excluded from metadata requests
    assert "npm_advisories" not in call_kwargs.kwargs["check_names"]
    assert "npm_rules" in call_kwargs.kwargs["check_names"]
    assert "npm_registry" in call_kwargs.kwargs["check_names"]


@pytest.mark.asyncio
async def test_npm_tarball_runs_advisory_checks() -> None:
    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)
    runner.get_enabled_check_names = MagicMock(return_value=["npm_advisories"])
    runner.run = AsyncMock(return_value=PipelineResult(
        run_result=RunResult(allowed=True, reason="no advisories", results=[]),
    ))

    addon = VibewallAddon(config, runner)

    flow = MagicMock()
    flow.request.pretty_host = "registry.npmjs.org"
    flow.request.pretty_url = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    flow.request.path = "/lodash/-/lodash-4.17.21.tgz"
    flow.response = None

    await addon.request(flow)

    runner.run.assert_called_once()
    call_kwargs = runner.run.call_args
    assert call_kwargs.kwargs["version"] == "4.17.21"
    assert call_kwargs.kwargs["check_names"] == {"npm_advisories"}


@pytest.mark.asyncio
async def test_npm_request_blocked() -> None:
    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)
    runner.run = AsyncMock(return_value=PipelineResult(
        run_result=RunResult(
            allowed=False,
            reason="hallucinated package",
            results=[("npm_existence", CheckResult.fail("hallucinated"))],
        ),
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
    runner.run = AsyncMock(return_value=PipelineResult(
        run_result=RunResult(allowed=True, reason="all checks passed", results=[]),
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
async def test_stale_flow_cleanup() -> None:
    """Stale entries in _flow_to_req are cleaned up."""
    import time as _time
    from vibewall.proxy.addon import _FLOW_TTL

    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)

    addon = VibewallAddon(config, runner)

    # Manually insert stale and fresh entries
    now = _time.monotonic()
    addon._flow_to_req["stale-1"] = ("req-1", now - _FLOW_TTL - 100)
    addon._flow_to_req["stale-2"] = ("req-2", now - _FLOW_TTL - 1)
    addon._flow_to_req["fresh-1"] = ("req-3", now - 10)
    addon._flow_to_bg["stale-1"] = MagicMock()

    addon._cleanup_stale_flows()

    assert "stale-1" not in addon._flow_to_req
    assert "stale-2" not in addon._flow_to_req
    assert "stale-1" not in addon._flow_to_bg
    assert "fresh-1" in addon._flow_to_req


@pytest.mark.asyncio
async def test_url_validation_for_non_npm() -> None:
    config = VibewallConfig.load(None)
    runner = AsyncMock(spec=CheckRunner)
    runner.run = AsyncMock(return_value=PipelineResult(
        run_result=RunResult(
            allowed=False,
            reason="DNS failed",
            results=[("url_dns", CheckResult.fail("DNS failed"))],
        ),
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
