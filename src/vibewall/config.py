from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_VALID_MODES = {"block", "warn"}


def _validate_mode(mode: str) -> str:
    if mode not in _VALID_MODES:
        raise ValueError(
            f"invalid mode '{mode}', must be one of: {', '.join(sorted(_VALID_MODES))}"
        )
    return mode


@dataclass
class NpmConfig:
    min_weekly_downloads: int = 10
    min_package_age_days: int = 7
    max_typosquat_distance: int = 2
    mode: str = "block"  # "block" or "warn"

    def __post_init__(self) -> None:
        _validate_mode(self.mode)


@dataclass
class UrlConfig:
    min_domain_age_days: int = 30
    mode: str = "block"  # "block" or "warn"
    enabled: bool = True

    def __post_init__(self) -> None:
        _validate_mode(self.mode)


@dataclass
class CacheConfig:
    npm_positive_ttl: int = 86400  # 24h
    npm_negative_ttl: int = 3600  # 1h
    url_ttl: int = 3600  # 1h
    whois_ttl: int = 604800  # 7d
    max_entries: int = 50000


@dataclass
class VibewallConfig:
    port: int = 8888
    host: str = "0.0.0.0"
    npm: NpmConfig = field(default_factory=NpmConfig)
    url: UrlConfig = field(default_factory=UrlConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    config_dir: Path = field(default_factory=lambda: Path("config"))

    @staticmethod
    def load(path: Path | None = None) -> VibewallConfig:
        if path is None:
            return VibewallConfig()
        if not path.exists():
            log.warning("config file '%s' not found, using defaults", path)
            return VibewallConfig()

        with open(path, "rb") as f:
            data = tomllib.load(f)

        cfg = VibewallConfig()
        cfg.port = data.get("port", cfg.port)
        cfg.host = data.get("host", cfg.host)

        if "npm" in data:
            npm = data["npm"]
            cfg.npm.min_weekly_downloads = npm.get(
                "min_weekly_downloads", cfg.npm.min_weekly_downloads
            )
            cfg.npm.min_package_age_days = npm.get(
                "min_package_age_days", cfg.npm.min_package_age_days
            )
            cfg.npm.max_typosquat_distance = npm.get(
                "max_typosquat_distance", cfg.npm.max_typosquat_distance
            )
            cfg.npm.mode = _validate_mode(npm.get("mode", cfg.npm.mode))

        if "url" in data:
            url = data["url"]
            cfg.url.min_domain_age_days = url.get(
                "min_domain_age_days", cfg.url.min_domain_age_days
            )
            cfg.url.mode = _validate_mode(url.get("mode", cfg.url.mode))
            cfg.url.enabled = url.get("enabled", cfg.url.enabled)

        if "cache" in data:
            cache = data["cache"]
            cfg.cache.npm_positive_ttl = cache.get(
                "npm_positive_ttl", cfg.cache.npm_positive_ttl
            )
            cfg.cache.npm_negative_ttl = cache.get(
                "npm_negative_ttl", cfg.cache.npm_negative_ttl
            )
            cfg.cache.url_ttl = cache.get("url_ttl", cfg.cache.url_ttl)
            cfg.cache.whois_ttl = cache.get("whois_ttl", cfg.cache.whois_ttl)
            cfg.cache.max_entries = cache.get("max_entries", cfg.cache.max_entries)

        if "config_dir" in data:
            cfg.config_dir = Path(data["config_dir"])

        return cfg
