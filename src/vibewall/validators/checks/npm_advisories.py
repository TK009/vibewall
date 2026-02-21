from __future__ import annotations

import asyncio

import aiohttp

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck

# Severity levels in ascending order of restrictiveness
_SEVERITY_ORDER = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}
_ACTION_ORDER = {"allow": 0, "warn": 1, "ask": 2, "block": 3}

_OSV_API_URL = "https://api.osv.dev/v1/query"


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    return "LOW"


def _extract_severity(vuln: dict) -> str:
    """Extract severity from an OSV vulnerability entry."""
    # Try database_specific.severity first (GitHub advisories use this)
    db_specific = vuln.get("database_specific", {})
    if "severity" in db_specific:
        raw = db_specific["severity"].upper()
        if raw in _SEVERITY_ORDER:
            return raw

    # Try CVSS score from severity array
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS vector strings: extract base score from "CVSS:3.1/AV:N/.../S:U"
        # or it might be a plain numeric score
        if sev.get("type") == "CVSS_V3":
            try:
                score = float(score_str.split("/")[0].split(":")[-1])
                return _cvss_to_severity(score)
            except (ValueError, IndexError):
                pass

    # Fallback: treat unknown severity as HIGH to be safe
    return "HIGH"


def _affects_version(vuln: dict, version: str) -> bool:
    """Check if a vulnerability affects the given version.

    Uses the ``affected[].versions`` list from OSV responses.  If the
    vulnerability has no ``affected`` data we conservatively assume it
    applies.
    """
    affected = vuln.get("affected", [])
    if not affected:
        return True  # no data → assume affected

    for entry in affected:
        # Exact version match in the explicitly listed versions
        if version in entry.get("versions", []):
            return True

    return False


class NpmAdvisoriesCheck(BaseCheck):
    name = "npm_advisories"
    abbrev = "ADV"
    depends_on: list[str] = []
    scope = "npm"
    default_cache_ttl = 3600

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

    async def run(
        self, target: str, context: CheckContext, *, version: str | None = None, **_kw: object,
    ) -> CheckResult:
        payload: dict = {"package": {"name": target, "ecosystem": "npm"}}
        if version is not None:
            payload["version"] = version
        try:
            async with self._session.post(
                _OSV_API_URL,
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
        # Client-side version filtering as a safety net
        if version is not None:
            vulns = [v for v in vulns if _affects_version(v, version)]
        if not vulns:
            return CheckResult.ok(f"no known advisories for '{target}'")

        # Process each vulnerability
        advisories: list[dict] = []
        effective_action = "allow"

        for vuln in vulns:
            severity = _extract_severity(vuln)
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
            })

            # Track the most restrictive action
            if _ACTION_ORDER.get(action, 2) > _ACTION_ORDER.get(effective_action, 0):
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
                key=lambda x: _SEVERITY_ORDER.get(x[0], 0),
                reverse=True,
            )
        )

        return CheckResult.fail(
            f"'{target}' has {len(non_allowed)} actionable advisory(ies) ({counts_str})",
            action_override=effective_action,
            advisories=advisories,
        )
