from __future__ import annotations

from vibewall.validators.checks._registry_base import DownloadsCheckBase


class NpmDownloadsCheck(DownloadsCheckBase):
    name = "npm_downloads"
    scope = "npm"
    api_url_template = "https://api.npmjs.org/downloads/point/last-week/{encoded}"
    safe_chars = "@"
    log_prefix = "npm"

    @staticmethod
    def downloads_extractor(data: dict) -> int:
        return data.get("downloads", 0)
