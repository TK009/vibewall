from __future__ import annotations

from vibewall.validators.checks._registry_base import DownloadsCheckBase


class PypiDownloadsCheck(DownloadsCheckBase):
    name = "pypi_downloads"
    scope = "pypi"
    api_url_template = "https://pypistats.org/api/packages/{encoded}/recent"
    safe_chars = ""
    log_prefix = "pypi"

    @staticmethod
    def downloads_extractor(data: dict) -> int:
        return data.get("data", {}).get("last_week", 0)
