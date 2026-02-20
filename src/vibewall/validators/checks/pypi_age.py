from __future__ import annotations

from datetime import datetime, timezone

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck


class PypiAgeCheck(BaseCheck):
    name = "pypi_age"
    abbrev = "AGE"
    depends_on = ["pypi_registry"]
    scope = "pypi"

    def __init__(self, min_days: int = 7, missing_date: str = "fail", **kwargs) -> None:
        self._min_days = min_days
        self._missing_date = missing_date  # "pass" or "fail"

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        registry_data = context.data("pypi_registry").get("registry_data", {})
        releases = registry_data.get("releases", {})

        # Find the earliest upload time across all releases
        earliest: datetime | None = None
        for version_files in releases.values():
            for file_info in version_files:
                upload_str = file_info.get("upload_time_iso_8601")
                if not upload_str:
                    continue
                uploaded = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                if earliest is None or uploaded < earliest:
                    earliest = uploaded

        if earliest is None:
            if self._missing_date == "pass":
                return CheckResult.ok("no upload date available, passing")
            return CheckResult.err("no upload date in registry data")

        age_days = (datetime.now(timezone.utc) - earliest).days

        if age_days < self._min_days:
            return CheckResult.fail(
                f"package '{target}' is only {age_days} days old "
                f"(minimum: {self._min_days})"
            )

        return CheckResult.ok(f"package '{target}' is {age_days} days old")
