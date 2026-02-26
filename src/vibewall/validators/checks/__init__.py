from __future__ import annotations

from typing import Any

from vibewall.validators.base import BaseCheck
from vibewall.validators.checks.npm_rules import NpmRulesCheck
from vibewall.validators.checks.npm_registry import NpmRegistryCheck
from vibewall.validators.checks.npm_existence import NpmExistenceCheck
from vibewall.validators.checks.npm_typosquat import NpmTyposquatCheck
from vibewall.validators.checks.npm_age import NpmAgeCheck
from vibewall.validators.checks.npm_downloads import NpmDownloadsCheck
from vibewall.validators.checks.npm_advisories import NpmAdvisoriesCheck
from vibewall.validators.checks.url_rules import UrlRulesCheck
from vibewall.validators.checks.url_dns import UrlDnsCheck
from vibewall.validators.checks.url_domain_age import UrlDomainAgeCheck
from vibewall.validators.checks.pypi_rules import PypiRulesCheck
from vibewall.validators.checks.pypi_registry import PypiRegistryCheck
from vibewall.validators.checks.pypi_existence import PypiExistenceCheck
from vibewall.validators.checks.pypi_typosquat import PypiTyposquatCheck
from vibewall.validators.checks.pypi_age import PypiAgeCheck
from vibewall.validators.checks.pypi_downloads import PypiDownloadsCheck
from vibewall.validators.checks.pypi_advisories import PypiAdvisoriesCheck

ALL_CHECKS: list[type[BaseCheck]] = [
    NpmRulesCheck,
    NpmRegistryCheck,
    NpmExistenceCheck,
    NpmTyposquatCheck,
    NpmAgeCheck,
    NpmDownloadsCheck,
    NpmAdvisoriesCheck,
    UrlRulesCheck,
    UrlDnsCheck,
    UrlDomainAgeCheck,
    PypiRulesCheck,
    PypiRegistryCheck,
    PypiExistenceCheck,
    PypiTyposquatCheck,
    PypiAgeCheck,
    PypiDownloadsCheck,
    PypiAdvisoriesCheck,
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
    if _cls.default_ignore_allowlist:
        _entry["ignore_allowlist"] = True
    VALIDATOR_DEFAULTS[_cls.name] = _entry

__all__ = ["ALL_CHECKS", "SCOPE_ORDER", "CHECK_ABBREVS", "VALIDATOR_DEFAULTS"]
