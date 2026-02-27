from __future__ import annotations

from vibewall.validators.checks._registry_base import AdvisoriesCheckBase


class PypiAdvisoriesCheck(AdvisoriesCheckBase):
    name = "pypi_advisories"
    scope = "pypi"
    ecosystem = "PyPI"
