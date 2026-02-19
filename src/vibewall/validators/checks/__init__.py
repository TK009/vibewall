from __future__ import annotations

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

__all__ = ["ALL_CHECKS", "SCOPE_ORDER", "CHECK_ABBREVS"]
