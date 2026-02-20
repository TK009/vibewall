from __future__ import annotations

from typing import Any

from vibewall.validators.base import BaseCheck
from vibewall.validators.checks.npm_blocklist import NpmBlocklistCheck
from vibewall.validators.checks.npm_allowlist import NpmAllowlistCheck
from vibewall.validators.checks.npm_registry import NpmRegistryCheck
from vibewall.validators.checks.npm_existence import NpmExistenceCheck
from vibewall.validators.checks.npm_typosquat import NpmTyposquatCheck
from vibewall.validators.checks.npm_age import NpmAgeCheck
from vibewall.validators.checks.npm_downloads import NpmDownloadsCheck
from vibewall.validators.checks.npm_advisories import NpmAdvisoriesCheck
from vibewall.validators.checks.url_blocklist import UrlBlocklistCheck
from vibewall.validators.checks.url_allowlist import UrlAllowlistCheck
from vibewall.validators.checks.url_dns import UrlDnsCheck
from vibewall.validators.checks.url_domain_age import UrlDomainAgeCheck

ALL_CHECKS: list[type[BaseCheck]] = [
    NpmBlocklistCheck,
    NpmAllowlistCheck,
    NpmRegistryCheck,
    NpmExistenceCheck,
    NpmTyposquatCheck,
    NpmAgeCheck,
    NpmDownloadsCheck,
    NpmAdvisoriesCheck,
    UrlBlocklistCheck,
    UrlAllowlistCheck,
    UrlDnsCheck,
    UrlDomainAgeCheck,
]

# Canonical check ordering per scope (single source of truth)
SCOPE_ORDER: dict[str, list[str]] = {}
for _cls in ALL_CHECKS:
    SCOPE_ORDER.setdefault(_cls.scope, []).append(_cls.name)

# Maps check name → abbreviation (from class attributes)
CHECK_ABBREVS: dict[str, str] = {_cls.name: _cls.abbrev for _cls in ALL_CHECKS}

# Default action/cache_ttl per validator (derived from class attributes)
VALIDATOR_DEFAULTS: dict[str, dict[str, Any]] = {}
for _cls in ALL_CHECKS:
    _entry: dict[str, Any] = {"action": _cls.default_action}
    if _cls.default_cache_ttl is not None:
        _entry["cache_ttl"] = _cls.default_cache_ttl
    VALIDATOR_DEFAULTS[_cls.name] = _entry

__all__ = ["ALL_CHECKS", "SCOPE_ORDER", "CHECK_ABBREVS", "VALIDATOR_DEFAULTS"]
