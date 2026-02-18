from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_VALID_ACTIONS = {"block", "warn", "ask"}


def _validate_action(action: str) -> str:
    if action not in _VALID_ACTIONS:
        raise ValueError(
            f"invalid action '{action}', must be one of: {', '.join(sorted(_VALID_ACTIONS))}"
        )
    return action


@dataclass
class ValidatorConfig:
    action: str = "block"
    cache_ttl: int | None = None  # None = use default from [cache]
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_action(self.action)


# Default parameters for each validator
_VALIDATOR_DEFAULTS: dict[str, dict[str, Any]] = {
    "npm_blocklist": {"action": "block"},
    "npm_allowlist": {"action": "block"},
    "npm_registry": {"action": "warn", "cache_ttl": 86400},
    "npm_existence": {"action": "block"},
    "npm_typosquat": {"action": "block", "max_distance": 2},
    "npm_age": {"action": "block", "min_days": 7},
    "npm_downloads": {"action": "warn", "min_weekly": 10, "cache_ttl": 86400},
    "url_blocklist": {"action": "block"},
    "url_allowlist": {"action": "block"},
    "url_dns": {"action": "block"},
    "url_domain_age": {"action": "block", "min_days": 30, "cache_ttl": 604800},
}


@dataclass
class CacheConfig:
    default_ttl: int = 3600
    max_entries: int = 50000


@dataclass
class VibewallConfig:
    port: int = 7777
    host: str = "0.0.0.0"
    validators: dict[str, ValidatorConfig] = field(default_factory=dict)
    cache: CacheConfig = field(default_factory=CacheConfig)
    config_dir: Path = field(default_factory=lambda: Path("config"))

    def get_validator(self, name: str) -> ValidatorConfig | None:
        """Get config for a validator, or None if disabled."""
        return self.validators.get(name)

    def is_enabled(self, name: str) -> bool:
        return name in self.validators

    @staticmethod
    def load(path: Path | None = None) -> VibewallConfig:
        if path is None:
            return _build_default_config()
        if not path.exists():
            log.warning("config file '%s' not found, using defaults", path)
            return _build_default_config()

        with open(path, "rb") as f:
            data = tomllib.load(f)

        cfg = VibewallConfig()
        cfg.port = data.get("port", cfg.port)
        cfg.host = data.get("host", cfg.host)

        if "config_dir" in data:
            cfg.config_dir = Path(data["config_dir"])

        # Cache config
        if "cache" in data:
            cache_data = data["cache"]
            cfg.cache.default_ttl = cache_data.get("default_ttl", cfg.cache.default_ttl)
            cfg.cache.max_entries = cache_data.get("max_entries", cfg.cache.max_entries)

        # Per-validator config from [validators.*] sections
        validators_data = data.get("validators", {})
        cfg.validators = {}
        for name, section in validators_data.items():
            defaults = _VALIDATOR_DEFAULTS.get(name, {})
            action = _validate_action(section.get("action", defaults.get("action", "block")))
            cache_ttl = section.get("cache_ttl", defaults.get("cache_ttl"))

            # Everything except action and cache_ttl goes into params
            params = dict(defaults)
            params.pop("action", None)
            params.pop("cache_ttl", None)
            params.update({k: v for k, v in section.items() if k not in ("action", "cache_ttl")})

            cfg.validators[name] = ValidatorConfig(
                action=action, cache_ttl=cache_ttl, params=params
            )

        # If no validators section at all, enable all with defaults
        if "validators" not in data:
            cfg.validators = _default_validators()

        return cfg


def _default_validators() -> dict[str, ValidatorConfig]:
    result = {}
    for name, defaults in _VALIDATOR_DEFAULTS.items():
        action = defaults.get("action", "block")
        cache_ttl = defaults.get("cache_ttl")
        params = {k: v for k, v in defaults.items() if k not in ("action", "cache_ttl")}
        result[name] = ValidatorConfig(action=action, cache_ttl=cache_ttl, params=params)
    return result


def _build_default_config() -> VibewallConfig:
    cfg = VibewallConfig()
    cfg.validators = _default_validators()
    return cfg
