from __future__ import annotations

from vibewall.validators.checks._registry_base import TyposquatCheckBase


class PypiTyposquatCheck(TyposquatCheckBase):
    name = "pypi_typosquat"
    depends_on = ("pypi_registry", "pypi_rules")
    scope = "pypi"
    rules_check_name = "pypi_rules"
