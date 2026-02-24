from __future__ import annotations

from pathlib import Path

import pytest

from vibewall.config import VibewallConfig, ValidatorConfig


def test_default_config_has_all_validators() -> None:
    cfg = VibewallConfig.load(None)
    assert "npm_blocklist" in cfg.validators
    assert "npm_registry" in cfg.validators
    assert "url_dns" in cfg.validators
    assert len(cfg.validators) == 20


def test_load_nonexistent_returns_defaults() -> None:
    cfg = VibewallConfig.load(Path("/nonexistent/path.toml"))
    assert cfg.port == 7777
    assert len(cfg.validators) == 20


def test_load_toml_with_validators(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
port = 9999

[validators.npm_blocklist]
action = "block"

[validators.npm_registry]
action = "warn"
cache_ttl = 1234

[cache]
default_ttl = 999
max_entries = 100
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.port == 9999
    assert len(cfg.validators) == 2
    assert cfg.validators["npm_registry"].cache_ttl == 1234
    assert cfg.validators["npm_registry"].action == "warn"
    assert cfg.cache.default_ttl == 999


def test_invalid_action_raises(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
[validators.npm_blocklist]
action = "invalid"
""")
    with pytest.raises(ValueError, match="invalid action"):
        VibewallConfig.load(toml)


def test_validator_params_loaded(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
[validators.npm_typosquat]
action = "block"
max_distance = 5
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.validators["npm_typosquat"].params["max_distance"] == 5


def test_legacy_ask_action_gives_helpful_error(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
[validators.npm_blocklist]
action = "ask"
""")
    with pytest.raises(ValueError, match="use 'ask-allow' or 'ask-block' instead"):
        VibewallConfig.load(toml)


def test_error_ttl_default() -> None:
    cfg = VibewallConfig.load(None)
    assert cfg.cache.error_ttl == 60


def test_error_ttl_from_toml(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
[cache]
error_ttl = 30
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.cache.error_ttl == 30


def test_disabled_validator() -> None:
    cfg = VibewallConfig.load(None)
    del cfg.validators["npm_downloads"]
    assert not cfg.is_enabled("npm_downloads")
    assert cfg.get_validator("npm_downloads") is None
