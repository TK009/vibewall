from __future__ import annotations

from vibewall.validators.checks._registry_base import ExistenceCheckBase


class NpmExistenceCheck(ExistenceCheckBase):
    name = "npm_existence"
    depends_on = ("npm_registry",)
    scope = "npm"
    registry_check_name = "npm_registry"
    registry_label = "npm registry"
