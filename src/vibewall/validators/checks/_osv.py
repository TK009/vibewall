"""Shared helpers for OSV-based advisory checks (npm + PyPI)."""

from __future__ import annotations

# Severity levels in ascending order of restrictiveness
SEVERITY_ORDER = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}
ACTION_ORDER = {"allow": 0, "warn": 1, "ask-allow": 2, "ask-block": 3, "block": 4}

OSV_API_URL = "https://api.osv.dev/v1/query"


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    return "LOW"


def extract_severity(vuln: dict) -> str:
    """Extract severity from an OSV vulnerability entry."""
    # Try database_specific.severity first (GitHub advisories use this)
    db_specific = vuln.get("database_specific", {})
    if "severity" in db_specific:
        raw = db_specific["severity"].upper()
        if raw in SEVERITY_ORDER:
            return raw

    # Try CVSS score from severity array
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        if sev.get("type") == "CVSS_V3":
            # OSV returns CVSS vector strings (e.g. "CVSS:3.1/AV:N/..."),
            # not numeric scores.  Skip vectors — they encode metrics,
            # not a pre-computed base score, and the "3.1" after "CVSS:"
            # is the spec version, not the severity score.
            if score_str.startswith("CVSS:"):
                continue
            try:
                return cvss_to_severity(float(score_str))
            except (ValueError, IndexError):
                pass

    # Fallback: treat unknown severity as HIGH to be safe
    return "HIGH"


def affects_version(vuln: dict, version: str) -> bool:
    """Check if a vulnerability affects the given version.

    Uses the ``affected[].versions`` list and ``affected[].ranges``
    from OSV responses.  If the vulnerability has no ``affected`` data
    we conservatively assume it applies.
    """
    affected = vuln.get("affected", [])
    if not affected:
        return True  # no data → assume affected

    for entry in affected:
        # Exact version match in the explicitly listed versions
        if version in entry.get("versions", []):
            return True

        # If ranges exist, conservatively assume the vulnerability
        # applies — we cannot reliably evaluate semver/ecosystem range
        # expressions client-side.  The explicit versions list is often
        # an incomplete enumeration alongside ranges, so we must not
        # skip a range just because a versions list is also present.
        if entry.get("ranges"):
            return True

    return False
