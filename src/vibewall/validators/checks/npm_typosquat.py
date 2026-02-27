from __future__ import annotations

from vibewall.validators.checks._registry_base import TyposquatCheckBase


class NpmTyposquatCheck(TyposquatCheckBase):
    name = "npm_typosquat"
    depends_on = ("npm_registry", "npm_rules")
    scope = "npm"
    rules_check_name = "npm_rules"
