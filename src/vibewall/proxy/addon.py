from __future__ import annotations

import json
import re

import structlog
from mitmproxy import http

from vibewall.config import VibewallConfig
from vibewall.models import ValidationResult
from vibewall.validators.npm import NpmValidator
from vibewall.validators.url import UrlValidator

logger = structlog.get_logger()

# Matches: /lodash, /@babel/core, /@scope/name/-/name-1.0.0.tgz
_NPM_PACKAGE_RE = re.compile(r"^/(@[^/]+/[^/]+|[^@/][^/]*)(?:/|$)")


class VibewallAddon:
    def __init__(
        self,
        config: VibewallConfig,
        npm_validator: NpmValidator,
        url_validator: UrlValidator,
    ) -> None:
        self._config = config
        self._npm = npm_validator
        self._url = url_validator

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        # Route npm registry requests
        if host == "registry.npmjs.org":
            package_name = self._extract_package_name(flow.request.path)
            if package_name:
                result = await self._npm.validate(package_name)
                self._handle_result(flow, result, "npm", package_name)
                return

        # Route other URLs through URL validator
        if self._config.url.enabled:
            result = await self._url.validate(url)
            self._handle_result(flow, result, "url", url)

    def _handle_result(
        self, flow: http.HTTPFlow, result: ValidationResult, check_type: str, target: str
    ) -> None:
        mode = self._config.npm.mode if check_type == "npm" else self._config.url.mode

        if not result.allowed:
            logger.warning(
                "request_blocked" if mode == "block" else "request_warned",
                type=check_type,
                target=target,
                reason=result.reason,
                mode=mode,
            )
            if mode == "block":
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
            logger.debug("request_allowed", type=check_type, target=target, reason=result.reason)

    @staticmethod
    def _extract_package_name(path: str) -> str | None:
        match = _NPM_PACKAGE_RE.match(path)
        if match:
            return match.group(1)
        return None
