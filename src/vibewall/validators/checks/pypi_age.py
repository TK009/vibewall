from __future__ import annotations

from datetime import datetime

from vibewall.validators.checks._registry_base import AgeCheckBase


class PypiAgeCheck(AgeCheckBase):
    name = "pypi_age"
    depends_on = ("pypi_registry",)
    scope = "pypi"
    registry_check_name = "pypi_registry"

    @staticmethod
    def date_extractor(registry_data: dict) -> str | None:
        releases = registry_data.get("releases", {})
        earliest: datetime | None = None
        earliest_str: str | None = None
        for version_files in releases.values():
            for file_info in version_files:
                upload_str = file_info.get("upload_time_iso_8601")
                if not upload_str:
                    continue
                uploaded = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                if earliest is None or uploaded < earliest:
                    earliest = uploaded
                    earliest_str = upload_str
        return earliest_str
