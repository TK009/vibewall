from __future__ import annotations

from vibewall.validators.checks._registry_base import RulesCheckBase


class NpmRulesCheck(RulesCheckBase):
    name = "npm_rules"
    scope = "npm"
