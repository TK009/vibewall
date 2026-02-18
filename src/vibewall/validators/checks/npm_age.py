from __future__ import annotations

from datetime import datetime, timezone

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck


class NpmAgeCheck(BaseCheck):
    name = "npm_age"
    depends_on = ["npm_registry"]
    scope = "npm"

    def __init__(self, min_days: int = 7, **kwargs) -> None:
        self._min_days = min_days

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        registry_data = context.data("npm_registry").get("registry_data", {})
        time_data = registry_data.get("time", {})
        created_str = time_data.get("created")

        if not created_str:
            return CheckResult.ok("no creation date available, passing")

        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - created).days

        if age_days < self._min_days:
            return CheckResult.fail(
                f"package '{target}' is only {age_days} days old "
                f"(minimum: {self._min_days})"
            )

        return CheckResult.ok(f"package '{target}' is {age_days} days old")
