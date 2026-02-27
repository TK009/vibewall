from __future__ import annotations

import asyncio
import json
import re
import time
from typing import TYPE_CHECKING

import structlog
from mitmproxy import http

from vibewall.config import VibewallConfig
from vibewall.models import PipelineResult, RunResult
from vibewall.notifications import Notifier
from vibewall.validators.runner import CheckRunner

if TYPE_CHECKING:
    from vibewall.console import ConsoleDisplay

logger = structlog.get_logger()

# Matches: /lodash, /@babel/core, /@scope/name/-/name-1.0.0.tgz
_NPM_PACKAGE_RE = re.compile(r"^/(@[^/]+/[^/]+|[^@/][^/]*)(?:/|$)")
# Matches: /simple/requests/, /pypi/requests/json
_PYPI_PACKAGE_RE = re.compile(r"^/(?:simple|pypi)/([^/]+)")

# npm tarball: /@scope/name/-/name-1.2.3.tgz or /lodash/-/lodash-4.17.21.tgz
_NPM_TARBALL_RE = re.compile(
    r"^/(@[^/]+/[^/]+|[^@/][^/]*)/-/[^/]+-(\d+\.\d+\.\d+[^/]*)\.tgz$"
)
# PyPI download filename: requests-2.28.0.tar.gz, requests-2.28.0-py3-none-any.whl
# Use greedy name capture so the *last* `-<version>` boundary is matched,
# handling hyphenated package names like my-cool-package-1.0.0.tar.gz.
_PYPI_DOWNLOAD_RE = re.compile(
    r"/([A-Za-z0-9][\w.-]*)-(\d+(?:\.\d+)+[\w.]*?)(?:\.tar\.gz|\.zip|\.whl|-)"
)


_FLOW_TTL = 600  # seconds — stale flow entries older than this are cleaned up
_CLEANUP_INTERVAL = 60  # seconds between cleanup sweeps


class VibewallAddon:
    def __init__(
        self,
        config: VibewallConfig,
        runner: CheckRunner,
        display: ConsoleDisplay | None = None,
        notifier: Notifier | None = None,
    ) -> None:
        self._config = config
        self._runner = runner
        self._display = display
        self._notifier = notifier
        # flow.id → (req_id, monotonic_time)
        self._flow_to_req: dict[str, tuple[str, float]] = {}
        self._flow_to_bg: dict[str, asyncio.Event] = {}  # flow.id → background event
        self._cleanup_task: asyncio.Task[None] | None = None

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        # Route npm registry requests
        if host == "registry.npmjs.org":
            # Check for tarball download first (has version info)
            tarball_info = self._extract_npm_tarball_info(flow.request.path)
            if tarball_info:
                name, version = tarball_info
                display_target = f"{name}@{version}"
                result = await self._run_with_display(
                    flow, "npm", display_target,
                    version=version, method=flow.request.method,
                    check_names={"npm_advisories"},
                )
                self._handle_result(flow, result, "npm", display_target)
                return

            # Metadata request — run all checks except advisories
            package_name = self._extract_package_name(flow.request.path)
            if package_name:
                result = await self._run_with_display(
                    flow, "npm", package_name,
                    method=flow.request.method,
                    check_names_exclude={"npm_advisories"},
                )
                self._handle_result(flow, result, "npm", package_name)
                return

        # Route PyPI download requests (files.pythonhosted.org)
        if host == "files.pythonhosted.org":
            download_info = self._extract_pypi_download_info(flow.request.path)
            if download_info:
                name, version = download_info
                display_target = f"{name}@{version}"
                result = await self._run_with_display(
                    flow, "pypi", display_target,
                    version=version, method=flow.request.method,
                    check_names={"pypi_advisories"},
                )
                self._handle_result(flow, result, "pypi", display_target)
                return

        # Route PyPI registry requests
        if host == "pypi.org":
            package_name = self._extract_pypi_package_name(flow.request.path)
            if package_name:
                result = await self._run_with_display(
                    flow, "pypi", package_name,
                    method=flow.request.method,
                    check_names_exclude={"pypi_advisories"},
                )
                self._handle_result(flow, result, "pypi", package_name)
                return

        # Route other URLs through URL checks
        has_url_checks = bool(self._runner.get_enabled_check_names("url"))
        if has_url_checks:
            result = await self._run_with_display(flow, "url", url, method=flow.request.method)
            self._handle_result(flow, result, "url", url)

    def response(self, flow: http.HTTPFlow) -> None:
        if self._display is None:
            return
        entry = self._flow_to_req.pop(flow.id, None)
        if entry is None:
            return
        req_id = entry[0]
        if flow.response is not None:
            self._display.update_status_code(req_id, flow.response.status_code)
        bg_event = self._flow_to_bg.pop(flow.id, None)
        if bg_event is not None and not bg_event.is_set():
            asyncio.create_task(self._deferred_finish(req_id, bg_event))
        else:
            self._display.finish_request(req_id)

    def error(self, flow: http.HTTPFlow) -> None:
        if self._display is None:
            return
        entry = self._flow_to_req.pop(flow.id, None)
        if entry is None:
            return
        req_id = entry[0]
        bg_event = self._flow_to_bg.pop(flow.id, None)
        if bg_event is not None and not bg_event.is_set():
            asyncio.create_task(self._deferred_finish(req_id, bg_event))
        else:
            self._display.finish_request(req_id)

    async def _run_with_display(
        self,
        flow: http.HTTPFlow,
        scope: str,
        target: str,
        *,
        version: str | None = None,
        method: str | None = None,
        check_names: set[str] | None = None,
        check_names_exclude: set[str] | None = None,
    ) -> RunResult:
        """Run checks, updating the console display if available."""
        # Resolve exclusion set into an inclusion set
        effective_names = check_names
        if check_names_exclude is not None:
            all_names = set(self._runner.get_enabled_check_names(scope))
            effective_names = all_names - check_names_exclude

        if self._display is None:
            pipeline = await self._runner.run(
                scope, target, version=version, method=method,
                check_names=effective_names,
            )
            return pipeline.run_result

        req_id = self._display.begin_request(scope, target)
        self._flow_to_req[flow.id] = (req_id, time.monotonic())
        self._ensure_cleanup_task()
        pipeline = await self._runner.run(
            scope,
            target,
            on_check_done=lambda name, r: self._display.update_check(req_id, name, r),
            on_ask=self._display.prompt_ask,
            version=version,
            method=method,
            check_names=effective_names,
        )
        result = pipeline.run_result
        self._display.set_run_result(req_id, result)

        # Track background event for deferred finish_request
        if pipeline.background is not None:
            self._flow_to_bg[flow.id] = pipeline.background

        # Fire-and-forget desktop notifications (gated per type)
        if self._notifier is not None:
            if result.blocked and self._config.notifications.blocked:
                asyncio.create_task(
                    self._notifier.notify_blocked(
                        scope, target, result.reason, results=result.results,
                    )
                )
            elif result.warnings and self._config.notifications.warned:
                asyncio.create_task(
                    self._notifier.notify_warned(
                        scope, target, result.warnings, results=result.results,
                    )
                )

        if result.blocked:
            # Blocked requests won't get a response() hook from upstream,
            # so finalize immediately with the 403 we're about to set.
            self._display.update_status_code(req_id, 403)
            bg_event = self._flow_to_bg.pop(flow.id, None)
            if bg_event is not None:
                # Background checks still running — defer finish_request
                asyncio.create_task(self._deferred_finish(req_id, bg_event))
            else:
                self._display.finish_request(req_id)
            self._flow_to_req.pop(flow.id, None)

        return result

    async def _deferred_finish(self, req_id: str, bg_event: asyncio.Event) -> None:
        """Wait for background checks to complete, then finalize the display line."""
        try:
            await asyncio.wait_for(bg_event.wait(), timeout=self._config.pipeline_timeout)
        except (asyncio.TimeoutError, Exception):
            pass
        if self._display is not None:
            self._display.finish_request(req_id)

    def _ensure_cleanup_task(self) -> None:
        """Start the periodic cleanup task if not already running."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

    async def _periodic_cleanup(self) -> None:
        """Periodically remove stale flow entries from tracking dicts."""
        while True:
            await asyncio.sleep(_CLEANUP_INTERVAL)
            self._cleanup_stale_flows()

    def _cleanup_stale_flows(self) -> None:
        """Remove flow entries older than _FLOW_TTL seconds."""
        now = time.monotonic()
        stale_ids = [
            flow_id
            for flow_id, (_, created) in self._flow_to_req.items()
            if now - created > _FLOW_TTL
        ]
        for flow_id in stale_ids:
            self._flow_to_req.pop(flow_id, None)
            self._flow_to_bg.pop(flow_id, None)
            logger.warning("cleaned_stale_flow", flow_id=flow_id)

    def _handle_result(
        self, flow: http.HTTPFlow, result: RunResult, check_type: str, target: str
    ) -> None:
        if result.blocked:
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": "blocked by vibewall",
                    "reason": result.reason,
                    "target": target,
                }),
                {"Content-Type": "application/json"},
            )
        else:
            logger.debug(
                "request_allowed",
                type=check_type,
                target=target,
                reason=result.reason,
            )

    @staticmethod
    def _extract_package_name(path: str) -> str | None:
        match = _NPM_PACKAGE_RE.match(path)
        if match:
            name = match.group(1)
            # "/-/..." paths are npm API endpoints, not packages
            if name == "-":
                return None
            return name
        return None

    @staticmethod
    def _extract_pypi_package_name(path: str) -> str | None:
        match = _PYPI_PACKAGE_RE.match(path)
        if match:
            # PEP 503: normalize name (lowercase, replace [-_.] with -)
            name = match.group(1).lower()
            name = re.sub(r"[-_.]+", "-", name)
            return name
        return None

    @staticmethod
    def _extract_npm_tarball_info(path: str) -> tuple[str, str] | None:
        """Extract (package_name, version) from an npm tarball URL path."""
        match = _NPM_TARBALL_RE.match(path)
        if match:
            return match.group(1), match.group(2)
        return None

    @staticmethod
    def _extract_pypi_download_info(path: str) -> tuple[str, str] | None:
        """Extract (package_name, version) from a PyPI download URL path."""
        if not path:
            return None

        match = _PYPI_DOWNLOAD_RE.search(path)
        if match:
            name = re.sub(r"[-_.]+", "-", match.group(1).lower())
            return name, match.group(2)
        return None
