from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING

import structlog
from mitmproxy import http

from vibewall.config import VibewallConfig
from vibewall.models import RunResult
from vibewall.notifications import Notifier
from vibewall.validators.runner import CheckRunner

if TYPE_CHECKING:
    from vibewall.console import ConsoleDisplay

logger = structlog.get_logger()

# Matches: /lodash, /@babel/core, /@scope/name/-/name-1.0.0.tgz
_NPM_PACKAGE_RE = re.compile(r"^/(@[^/]+/[^/]+|[^@/][^/]*)(?:/|$)")
# Matches: /simple/requests/, /pypi/requests/json
_PYPI_PACKAGE_RE = re.compile(r"^/(?:simple|pypi)/([^/]+)")


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
        self._flow_to_req: dict[str, str] = {}  # flow.id → req_id

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        # Route npm registry requests
        if host == "registry.npmjs.org":
            package_name = self._extract_package_name(flow.request.path)
            if package_name:
                result = await self._run_with_display(flow, "npm", package_name)
                self._handle_result(flow, result, "npm", package_name)
                return

        # Route PyPI registry requests
        if host == "pypi.org":
            package_name = self._extract_pypi_package_name(flow.request.path)
            if package_name:
                result = await self._run_with_display(flow, "pypi", package_name)
                self._handle_result(flow, result, "pypi", package_name)
                return

        # Route other URLs through URL checks
        has_url_checks = bool(self._runner.get_enabled_check_names("url"))
        if has_url_checks:
            result = await self._run_with_display(flow, "url", url)
            self._handle_result(flow, result, "url", url)

    def response(self, flow: http.HTTPFlow) -> None:
        if self._display is None:
            return
        req_id = self._flow_to_req.pop(flow.id, None)
        if req_id is None:
            return
        if flow.response is not None:
            self._display.update_status_code(req_id, flow.response.status_code)
        self._display.finish_request(req_id)

    def error(self, flow: http.HTTPFlow) -> None:
        if self._display is None:
            return
        req_id = self._flow_to_req.pop(flow.id, None)
        if req_id is None:
            return
        self._display.finish_request(req_id)

    async def _run_with_display(self, flow: http.HTTPFlow, scope: str, target: str) -> RunResult:
        """Run checks, updating the console display if available."""
        if self._display is None:
            return await self._runner.run(scope, target)

        req_id = self._display.begin_request(scope, target)
        self._flow_to_req[flow.id] = req_id
        result = await self._runner.run(
            scope,
            target,
            on_check_done=lambda name, r: self._display.update_check(req_id, name, r),
            on_ask=self._display.prompt_ask,
        )
        self._display.set_run_result(req_id, result)

        # Fire-and-forget desktop notifications
        if self._notifier is not None:
            if result.blocked:
                asyncio.create_task(
                    self._notifier.notify_blocked(scope, target, result.reason)
                )
            elif result.warnings:
                asyncio.create_task(
                    self._notifier.notify_warned(scope, target, result.warnings)
                )

        if result.blocked:
            # Blocked requests won't get a response() hook from upstream,
            # so finalize immediately with the 403 we're about to set.
            self._display.update_status_code(req_id, 403)
            self._display.finish_request(req_id)
            del self._flow_to_req[flow.id]

        return result

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
