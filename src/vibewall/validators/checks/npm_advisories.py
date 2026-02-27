from __future__ import annotations

from vibewall.validators.checks._registry_base import AdvisoriesCheckBase


class NpmAdvisoriesCheck(AdvisoriesCheckBase):
    name = "npm_advisories"
    scope = "npm"
    ecosystem = "npm"
