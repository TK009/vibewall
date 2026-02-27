from __future__ import annotations

from vibewall.validators.checks._registry_base import RulesCheckBase


class PypiRulesCheck(RulesCheckBase):
    name = "pypi_rules"
    scope = "pypi"
