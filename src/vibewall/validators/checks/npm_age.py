from __future__ import annotations

from vibewall.validators.checks._registry_base import AgeCheckBase


class NpmAgeCheck(AgeCheckBase):
    name = "npm_age"
    depends_on = ("npm_registry",)
    scope = "npm"
    registry_check_name = "npm_registry"

    @staticmethod
    def date_extractor(registry_data: dict) -> str | None:
        return registry_data.get("time", {}).get("created")
