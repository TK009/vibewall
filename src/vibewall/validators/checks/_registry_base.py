"""Scope-parameterized base classes for npm/pypi check pairs.

Each concrete npm/pypi check becomes a thin subclass that sets class
attributes only.  The shared logic lives here.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import quote

import aiohttp
import structlog

from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.base import BaseCheck
from vibewall.validators.checks._osv import (
    ACTION_ORDER,
    OSV_API_URL,
    SEVERITY_ORDER,
    affects_version,
    has_fix,
    extract_severity,
)

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# 1. RegistryCheckBase — fetches package metadata from a registry
# ---------------------------------------------------------------------------

class RegistryCheckBase(BaseCheck):
    abbrev = "REG"
    depends_on: tuple[str, ...] = ()
    default_action = "warn"
    default_cache_ttl = 86400

    # Subclass must set:
    registry_url_template: str  # e.g. "https://registry.npmjs.org/{encoded}"
    safe_chars: str = ""  # passed to urllib.parse.quote
    log_prefix: str = ""  # e.g. "npm" or "pypi"

    def __init__(self, session: aiohttp.ClientSession, **kwargs: Any) -> None:
        self._session = session

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        encoded = quote(target, safe=self.safe_chars)
        url = self.registry_url_template.format(encoded=encoded)
        try:
            async with self._session.get(
                url, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json() if resp.status == 200 else {}
                return CheckResult.ok(
                    f"registry returned {resp.status}",
                    registry_data=data,
                    status_code=resp.status,
                )
        except asyncio.TimeoutError:
            logger.warning("registry_timeout", ecosystem=self.log_prefix, package=target)
            return CheckResult.err("registry request timed out")
        except aiohttp.ClientError as e:
            logger.warning("registry_error", ecosystem=self.log_prefix, package=target, error=str(e))
            return CheckResult.err(f"registry request failed: {e}")


# ---------------------------------------------------------------------------
# 2. ExistenceCheckBase — checks if a package exists based on registry status
# ---------------------------------------------------------------------------

class ExistenceCheckBase(BaseCheck):
    abbrev = "EXI"

    # Subclass must set:
    registry_check_name: str  # e.g. "npm_registry"
    registry_label: str  # e.g. "npm registry" or "PyPI"

    def __init__(self, **kwargs: Any) -> None:
        pass

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        registry_data = context.data(self.registry_check_name)
        status_code = registry_data.get("status_code")

        if status_code == 404:
            return CheckResult.fail(
                f"package '{target}' does not exist on {self.registry_label} (hallucinated)"
            )
        return CheckResult.ok(f"package '{target}' exists on {self.registry_label}")


# ---------------------------------------------------------------------------
# 3. RulesCheckBase — matches target against allowlist/blocklist rules
# ---------------------------------------------------------------------------

class RulesCheckBase(BaseCheck):
    abbrev = "RUL"
    depends_on: tuple[str, ...] = ()

    def __init__(self, ruleset: Any, **kwargs: Any) -> None:
        self._ruleset = ruleset

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        match = self._ruleset.match(self.scope, target, method=context.method)
        if match is None:
            return CheckResult.ok(f"no rule matched for '{target}'", allowlisted=False)
        rule = match.rule
        source = f"{rule.source_file}:{rule.source_line}"
        if rule.action == "allow":
            return CheckResult.ok(
                f"allowed by rule: {rule.pattern} ({source})",
                allowlisted=True,
                rule_source=rule.source_file,
                rule_line=rule.source_line,
                rule_pattern=rule.pattern,
            )
        return CheckResult.fail(
            f"matched {rule.action} rule: {rule.pattern} ({source})",
            action_override=rule.action,
            rule_source=rule.source_file,
            rule_line=rule.source_line,
            rule_pattern=rule.pattern,
        )


# ---------------------------------------------------------------------------
# 4. TyposquatCheckBase — edit-distance check against known package names
# ---------------------------------------------------------------------------

_MIN_TYPOSQUAT_NAME_LEN = 6


class TyposquatCheckBase(BaseCheck):
    abbrev = "TYP"
    default_action = "warn"

    # Subclass must set:
    rules_check_name: str  # e.g. "npm_rules"

    def __init__(self, ruleset: Any, max_distance: int = 2, **kwargs: Any) -> None:
        self._ruleset = ruleset
        self._max_distance = max_distance

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        from rapidfuzz.distance import Levenshtein

        rules_data = context.data(self.rules_check_name)
        if rules_data.get("allowlisted"):
            return CheckResult.ok("allowlisted, skipping typosquat check")

        if len(target) < _MIN_TYPOSQUAT_NAME_LEN:
            return CheckResult.ok(
                f"name too short ({len(target)} chars) for typosquat check"
            )

        for known in self._ruleset.allowlisted_names(self.scope):
            if known == target:
                continue
            dist = Levenshtein.distance(
                target, known, score_cutoff=self._max_distance
            )
            if dist <= self._max_distance:
                return CheckResult.fail(
                    f"package '{target}' looks like a typosquat of '{known}' "
                    f"(edit distance: {dist})",
                    similar_to=known,
                    edit_distance=dist,
                )

        return CheckResult.ok(f"package '{target}' is not a typosquat")


# ---------------------------------------------------------------------------
# 5. DownloadsCheckBase — checks weekly download counts
# ---------------------------------------------------------------------------

class DownloadsCheckBase(BaseCheck):
    abbrev = " DL"
    depends_on: tuple[str, ...] = ()
    default_action = "warn"
    default_cache_ttl = 86400

    # Subclass must set:
    api_url_template: str  # e.g. "https://api.npmjs.org/downloads/point/last-week/{encoded}"
    safe_chars: str = ""
    downloads_extractor: Callable[[dict], int]  # extracts download count from response
    log_prefix: str = ""

    def __init__(
        self, session: aiohttp.ClientSession, min_weekly: int = 10, **kwargs: Any
    ) -> None:
        self._session = session
        self._min_weekly = min_weekly

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        encoded = quote(target, safe=self.safe_chars)
        url = self.api_url_template.format(encoded=encoded)
        try:
            async with self._session.get(
                url, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return CheckResult.err(
                        f"downloads API returned {resp.status}, failing open"
                    )
                data = await resp.json()
                downloads = self.downloads_extractor(data)

                if downloads < self._min_weekly:
                    return CheckResult.fail(
                        f"package '{target}' has only {downloads} weekly downloads "
                        f"(minimum: {self._min_weekly})",
                        downloads=downloads,
                    )

                return CheckResult.ok(
                    f"package '{target}' has {downloads} weekly downloads",
                    downloads=downloads,
                )
        except asyncio.TimeoutError:
            logger.warning("downloads_timeout", ecosystem=self.log_prefix, package=target)
            return CheckResult.err("downloads request timed out")
        except aiohttp.ClientError as e:
            logger.warning("downloads_error", ecosystem=self.log_prefix, package=target, error=str(e))
            return CheckResult.err(f"downloads request failed: {e}")


# ---------------------------------------------------------------------------
# 6. AdvisoriesCheckBase — OSV advisory lookup
# ---------------------------------------------------------------------------

class AdvisoriesCheckBase(BaseCheck):
    abbrev = "ADV"
    depends_on: tuple[str, ...] = ()
    default_cache_ttl = 3600
    default_ignore_allowlist = True

    # Subclass must set:
    ecosystem: str  # "npm" or "PyPI" (used in OSV payload)

    def __init__(
        self,
        session: aiohttp.ClientSession,
        severity_low: str = "allow",
        severity_medium: str = "warn",
        severity_high: str = "warn",
        severity_critical: str = "block",
        **kwargs: object,
    ) -> None:
        self._session = session
        self._severity_actions = {
            "LOW": severity_low,
            "MODERATE": severity_medium,
            "HIGH": severity_high,
            "CRITICAL": severity_critical,
        }

    def get_result_ttl(self, result: CheckResult, default_ttl: int) -> int:
        if result.status == CheckStatus.OK:
            return max(300, default_ttl // 4)
        advisories = result.data.get("advisories", [])
        if advisories and any(not a.get("has_fix", False) for a in advisories):
            return default_ttl
        return default_ttl * 2

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        version = context.version
        pkg_name = target
        if version and target.endswith(f"@{version}"):
            pkg_name = target[: -len(version) - 1]
        payload: dict = {"package": {"name": pkg_name, "ecosystem": self.ecosystem}}
        if version is not None:
            payload["version"] = version
        try:
            async with self._session.post(
                OSV_API_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return CheckResult.err(
                        f"OSV API returned {resp.status}, failing open"
                    )
                data = await resp.json()
        except asyncio.TimeoutError:
            return CheckResult.err("advisory lookup timed out")
        except aiohttp.ClientError as e:
            return CheckResult.err(f"advisory lookup failed: {e}")

        vulns = data.get("vulns", [])
        if version is not None:
            vulns = [v for v in vulns if affects_version(v, version)]
        if not vulns:
            return CheckResult.ok(f"no known advisories for '{target}'")

        advisories: list[dict] = []
        effective_action = "allow"

        for vuln in vulns:
            severity = extract_severity(vuln)
            action = self._severity_actions.get(severity, "block")
            vuln_id = vuln.get("id", "unknown")
            summary = vuln.get("summary", "no description")
            details = vuln.get("details", "")

            advisories.append({
                "id": vuln_id,
                "severity": severity,
                "action": action,
                "summary": summary,
                "details": details,
                "has_fix": has_fix(vuln),
            })

            if ACTION_ORDER.get(action, 2) > ACTION_ORDER.get(effective_action, 0):
                effective_action = action

        non_allowed = [a for a in advisories if a["action"] != "allow"]

        if not non_allowed:
            return CheckResult.ok(
                f"'{target}' has {len(vulns)} advisory(ies), all below threshold",
                advisories=advisories,
            )

        severity_counts: dict[str, int] = {}
        for a in advisories:
            severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1

        counts_str = ", ".join(
            f"{count} {sev.lower()}"
            for sev, count in sorted(
                severity_counts.items(),
                key=lambda x: SEVERITY_ORDER.get(x[0], 0),
                reverse=True,
            )
        )

        return CheckResult.fail(
            f"'{target}' has {len(non_allowed)} actionable advisory(ies) ({counts_str})",
            action_override=effective_action,
            advisories=advisories,
        )


# ---------------------------------------------------------------------------
# 7. AgeCheckBase — checks package age from registry data
# ---------------------------------------------------------------------------

class AgeCheckBase(BaseCheck):
    abbrev = "AGE"

    # Subclass must set:
    registry_check_name: str  # e.g. "npm_registry"
    date_extractor: Callable[[dict], str | None]  # extracts creation date string

    def __init__(self, min_days: int = 7, missing_date: str = "fail", **kwargs: Any) -> None:
        self._min_days = min_days
        self._missing_date = missing_date

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        registry_data = context.data(self.registry_check_name).get("registry_data", {})
        created_str = self.date_extractor(registry_data)

        if not created_str:
            if self._missing_date == "pass":
                return CheckResult.ok("no creation date available, passing")
            return CheckResult.err("no creation date in registry data")

        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - created).days

        if age_days < self._min_days:
            return CheckResult.fail(
                f"package '{target}' is only {age_days} days old "
                f"(minimum: {self._min_days})",
                age_days=age_days,
                min_days=self._min_days,
            )

        return CheckResult.ok(f"package '{target}' is {age_days} days old")
