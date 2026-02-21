from __future__ import annotations

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck


class PypiExistenceCheck(BaseCheck):
    name = "pypi_existence"
    abbrev = "EXI"
    depends_on = ["pypi_registry"]
    scope = "pypi"

    def __init__(self, **kwargs) -> None:
        pass

    async def run(self, target: str, context: CheckContext, **_kw: object) -> CheckResult:
        registry_data = context.data("pypi_registry")
        status_code = registry_data.get("status_code")

        if status_code == 404:
            return CheckResult.fail(
                f"package '{target}' does not exist on PyPI (hallucinated)"
            )
        return CheckResult.ok(f"package '{target}' exists on PyPI")
