from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import structlog
from mitmproxy import http

from vibewall.config import VibewallConfig
from vibewall.models import RunResult
from vibewall.validators.runner import CheckRunner

if TYPE_CHECKING:
    from vibewall.console import ConsoleDisplay

logger = structlog.get_logger()

# Matches: /lodash, /@babel/core, /@scope/name/-/name-1.0.0.tgz
_NPM_PACKAGE_RE = re.compile(r"^/(@[^/]+/[^/]+|[^@/][^/]*)(?:/|$)")


class VibewallAddon:
    def __init__(
        self,
        config: VibewallConfig,
        runner: CheckRunner,
        display: ConsoleDisplay | None = None,
    ) -> None:
        self._config = config
        self._runner = runner
        self._display = display

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        # Route npm registry requests
        if host == "registry.npmjs.org":
            package_name = self._extract_package_name(flow.request.path)
            if package_name:
                result = await self._run_with_display("npm", package_name)
                self._handle_result(flow, result, "npm", package_name)
                return

        # Route other URLs through URL checks
        has_url_checks = any(
            self._config.is_enabled(n)
            for n in ("url_blocklist", "url_allowlist", "url_dns", "url_domain_age")
        )
        if has_url_checks:
            result = await self._run_with_display("url", url)
            self._handle_result(flow, result, "url", url)

    async def _run_with_display(self, scope: str, target: str) -> RunResult:
        """Run checks, updating the console display if available."""
        if self._display is None:
            return await self._runner.run(scope, target)

        req_id = self._display.begin_request(scope, target)
        result = await self._runner.run(
            scope,
            target,
            on_check_done=lambda name, r: self._display.update_check(req_id, name, r),
        )
        self._display.finish_request(req_id, result)
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
