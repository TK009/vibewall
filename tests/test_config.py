from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from vibewall.config import VibewallConfig, ValidatorConfig
from vibewall.exceptions import ConfigError


def test_default_config_has_all_validators() -> None:
    cfg = VibewallConfig.load(None)
    assert "npm_rules" in cfg.validators
    assert "npm_registry" in cfg.validators
    assert "url_dns" in cfg.validators
    assert len(cfg.validators) == 17


def test_load_nonexistent_returns_defaults() -> None:
    cfg = VibewallConfig.load(Path("/nonexistent/path.toml"))
    assert cfg.port == 7777
    assert len(cfg.validators) == 17


def test_load_toml_with_validators(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
port = 9999

[validators.npm_rules]
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
[validators.npm_rules]
action = "invalid"
""")
    with pytest.raises(ConfigError, match="invalid action"):
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
[validators.npm_rules]
action = "ask"
""")
    with pytest.raises(ConfigError, match="use 'ask-allow' or 'ask-block' instead"):
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


def test_unknown_keys_produce_warnings(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
port = 7777
cache_tll = 9999

[cache]
defalt_ttl = 1234

[notifications]
enbled = true

[llm]
providr = "anthropic"
api_key = "test"
""")
    with caplog.at_level(logging.WARNING, logger="vibewall.config"):
        VibewallConfig.load(toml)

    messages = [r.message for r in caplog.records]
    assert any("cache_tll" in m and "[root]" in m for m in messages)
    assert any("defalt_ttl" in m and "[cache]" in m for m in messages)
    assert any("enbled" in m and "[notifications]" in m for m in messages)
    assert any("providr" in m and "[llm]" in m for m in messages)


def test_llm_config_loading(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
[llm]
provider = "openai"
model = "gpt-4"
api_key = "sk-test-key"
max_tokens = 512
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.llm is not None
    assert cfg.llm.provider == "openai"
    assert cfg.llm.model == "gpt-4"
    assert cfg.llm.api_key == "sk-test-key"
    assert cfg.llm.max_tokens == 512


def test_llm_api_key_env_var_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIBEWALL_TEST_KEY", "secret-from-env")
    toml = tmp_path / "test.toml"
    toml.write_text("""
[llm]
api_key = "$VIBEWALL_TEST_KEY"
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.llm is not None
    assert cfg.llm.api_key == "secret-from-env"


def test_llm_missing_env_var_resolves_to_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIBEWALL_NONEXISTENT_KEY", raising=False)
    toml = tmp_path / "test.toml"
    toml.write_text("""
[llm]
api_key = "$VIBEWALL_NONEXISTENT_KEY"
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.llm is not None
    assert cfg.llm.api_key == ""


def test_no_llm_section_gives_none() -> None:
    cfg = VibewallConfig.load(None)
    assert cfg.llm is None


def test_cache_config_loading(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
[cache]
db_path = "/tmp/test-cache.db"
cleanup_interval = 600
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.cache.db_path == "/tmp/test-cache.db"
    assert cfg.cache.cleanup_interval == 600


def test_notifications_ask_timeout(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
[notifications]
ask_timeout = 60
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.notifications.ask_timeout == 60


def test_host_and_port_overrides(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
host = "127.0.0.1"
port = 8888
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 8888


def test_pipeline_timeout_override(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
pipeline_timeout = 60
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.pipeline_timeout == 60


def test_validator_ignore_allowlist_flag(tmp_path: Path) -> None:
    toml = tmp_path / "test.toml"
    toml.write_text("""
[validators.npm_advisories]
action = "block"
ignore_allowlist = true
""")
    cfg = VibewallConfig.load(toml)
    assert cfg.validators["npm_advisories"].ignore_allowlist is True
