from __future__ import annotations

import logging
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

from vibewall.validators.checks import VALIDATOR_DEFAULTS

_VALID_ACTIONS = {"block", "warn", "ask-allow", "ask-block", "ask-llm-allow", "ask-llm-block"}


def _validate_action(action: str) -> str:
    if action == "ask":
        raise ValueError(
            "action 'ask' was removed; use 'ask-allow' or 'ask-block' instead"
        )
    if action not in _VALID_ACTIONS:
        raise ValueError(
            f"invalid action '{action}', must be one of: {', '.join(sorted(_VALID_ACTIONS))}"
        )
    return action


@dataclass
class ValidatorConfig:
    action: str = "block"
    cache_ttl: int | None = None  # None = use default from [cache]
    ignore_allowlist: bool = False
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_action(self.action)


@dataclass
class NotificationsConfig:
    enabled: bool = True  # auto-detect if True + notify-send on PATH
    blocked: bool = True  # notify on blocked requests
    warned: bool = True  # notify on warned requests
    ask: bool = True  # interactive notification for ask-mode
    expire_ms: int = 10000  # notification timeout in ms


@dataclass
class LlmConfig:
    provider: str = "anthropic"  # "anthropic" or "openai"
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""  # raw key or "$ENV_VAR_NAME"
    base_url: str | None = None  # override for OpenAI-compatible endpoints
    max_tokens: int = 256
    temperature: float = 0.0
    max_concurrent: int = 5  # max concurrent LLM API calls
    cache_ttl: int = 120  # seconds; 0 = disabled

    def __repr__(self) -> str:
        masked = f"...{self.api_key[-4:]}" if len(self.api_key) >= 4 else "***"
        return (
            f"LlmConfig(provider={self.provider!r}, model={self.model!r}, "
            f"api_key={masked!r}, base_url={self.base_url!r}, "
            f"max_tokens={self.max_tokens!r}, temperature={self.temperature!r}, "
            f"max_concurrent={self.max_concurrent!r}, cache_ttl={self.cache_ttl!r})"
        )


@dataclass
class CacheConfig:
    default_ttl: int = 3600
    max_entries: int = 50000


@dataclass
class VibewallConfig:
    port: int = 7777
    host: str = "0.0.0.0"
    pipeline_timeout: int = (
        120  # seconds; max time for entire check pipeline per request
    )
    validators: dict[str, ValidatorConfig] = field(default_factory=dict)
    cache: CacheConfig = field(default_factory=CacheConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    llm: LlmConfig | None = None
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
        cfg.pipeline_timeout = data.get("pipeline_timeout", cfg.pipeline_timeout)

        if "config_dir" in data:
            cfg.config_dir = Path(data["config_dir"])

        # Cache config
        if "cache" in data:
            cache_data = data["cache"]
            cfg.cache.default_ttl = cache_data.get("default_ttl", cfg.cache.default_ttl)
            cfg.cache.max_entries = cache_data.get("max_entries", cfg.cache.max_entries)

        # Notifications config
        if "notifications" in data:
            n = data["notifications"]
            cfg.notifications = NotificationsConfig(
                enabled=n.get("enabled", cfg.notifications.enabled),
                blocked=n.get("blocked", cfg.notifications.blocked),
                warned=n.get("warned", cfg.notifications.warned),
                ask=n.get("ask", cfg.notifications.ask),
                expire_ms=n.get("expire_ms", cfg.notifications.expire_ms),
            )

        # LLM config
        if "llm" in data:
            llm_data = data["llm"]
            api_key = llm_data.get("api_key", "")
            if isinstance(api_key, str) and api_key.startswith("$"):
                api_key = os.environ.get(api_key[1:], "")
            cfg.llm = LlmConfig(
                provider=llm_data.get("provider", "anthropic"),
                model=llm_data.get("model", "claude-sonnet-4-20250514"),
                api_key=api_key,
                base_url=llm_data.get("base_url"),
                max_tokens=llm_data.get("max_tokens", 256),
                temperature=llm_data.get("temperature", 0.0),
                max_concurrent=llm_data.get("max_concurrent", 5),
                cache_ttl=llm_data.get("cache_ttl", 120),
            )

        # Per-validator config from [validators.*] sections
        validators_data = data.get("validators", {})
        cfg.validators = {}
        for name, section in validators_data.items():
            defaults = VALIDATOR_DEFAULTS.get(name, {})
            action = _validate_action(
                section.get("action", defaults.get("action", "block"))
            )
            cache_ttl = section.get("cache_ttl", defaults.get("cache_ttl"))
            ignore_allowlist = section.get(
                "ignore_allowlist", defaults.get("ignore_allowlist", False)
            )

            # Everything except action, cache_ttl, ignore_allowlist goes into params
            _meta_keys = {"action", "cache_ttl", "ignore_allowlist"}
            params = dict(defaults)
            for k in _meta_keys:
                params.pop(k, None)
            params.update(
                {k: v for k, v in section.items() if k not in _meta_keys}
            )

            cfg.validators[name] = ValidatorConfig(
                action=action, cache_ttl=cache_ttl,
                ignore_allowlist=ignore_allowlist, params=params,
            )

        # If no validators section at all, enable all with defaults
        if "validators" not in data:
            cfg.validators = _default_validators()

        return cfg


def _default_validators() -> dict[str, ValidatorConfig]:
    result = {}
    _meta_keys = {"action", "cache_ttl", "ignore_allowlist"}
    for name, defaults in VALIDATOR_DEFAULTS.items():
        action = defaults.get("action", "block")
        cache_ttl = defaults.get("cache_ttl")
        ignore_allowlist = defaults.get("ignore_allowlist", False)
        params = {k: v for k, v in defaults.items() if k not in _meta_keys}
        result[name] = ValidatorConfig(
            action=action, cache_ttl=cache_ttl,
            ignore_allowlist=ignore_allowlist, params=params,
        )
    return result


def _build_default_config() -> VibewallConfig:
    cfg = VibewallConfig()
    cfg.validators = _default_validators()
    return cfg
