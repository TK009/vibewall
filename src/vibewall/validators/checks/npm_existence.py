from __future__ import annotations

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck


class NpmExistenceCheck(BaseCheck):
    name = "npm_existence"
    abbrev = "EXI"
    depends_on = ["npm_registry"]
    scope = "npm"

    def __init__(self, **kwargs) -> None:
        pass

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        registry_data = context.data("npm_registry")
        status_code = registry_data.get("status_code")

        if status_code == 404:
            return CheckResult.fail(
                f"package '{target}' does not exist on npm registry (hallucinated)"
            )
        return CheckResult.ok(f"package '{target}' exists on npm registry")
