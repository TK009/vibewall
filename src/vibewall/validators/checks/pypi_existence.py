from __future__ import annotations

from vibewall.validators.checks._registry_base import ExistenceCheckBase


class PypiExistenceCheck(ExistenceCheckBase):
    name = "pypi_existence"
    depends_on = ("pypi_registry",)
    scope = "pypi"
    registry_check_name = "pypi_registry"
    registry_label = "PyPI"
