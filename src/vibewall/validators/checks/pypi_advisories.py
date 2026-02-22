from __future__ import annotations

import asyncio

import aiohttp

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck
from vibewall.models import CheckStatus
from vibewall.validators.checks._osv import (
    ACTION_ORDER,
    OSV_API_URL,
    SEVERITY_ORDER,
    affects_version,
    cvss_to_severity,
    extract_severity,
    has_fix,
)


class PypiAdvisoriesCheck(BaseCheck):
    name = "pypi_advisories"
    abbrev = "ADV"
    depends_on: list[str] = []
    scope = "pypi"
    default_cache_ttl = 3600
    default_ignore_allowlist = True

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
        if result.status == CheckStatus.ERR:
            return default_ttl
        if result.status == CheckStatus.OK:
            return max(300, default_ttl // 4)
        # FAIL: if all advisories have a fix, the info is stable
        advisories = result.data.get("advisories", [])
        if advisories and any(not a.get("has_fix", False) for a in advisories):
            return default_ttl  # fix may appear, re-check sooner
        return default_ttl * 2  # all fixed or no advisories detail — stable

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        version = context.version
        # Strip @version suffix — download requests use "pkg@1.0.0" as target
        # for cache isolation, but the OSV API needs the bare package name.
        pkg_name = target
        if version and target.endswith(f"@{version}"):
            pkg_name = target[: -len(version) - 1]
        payload: dict = {"package": {"name": pkg_name, "ecosystem": "PyPI"}}
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

        # Process each vulnerability
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

            # Track the most restrictive action
            if ACTION_ORDER.get(action, 2) > ACTION_ORDER.get(effective_action, 0):
                effective_action = action

        non_allowed = [a for a in advisories if a["action"] != "allow"]

        if not non_allowed:
            return CheckResult.ok(
                f"'{target}' has {len(vulns)} advisory(ies), all below threshold",
                advisories=advisories,
            )

        severity_counts = {}
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
