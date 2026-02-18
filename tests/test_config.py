from __future__ import annotations

import pytest

from vibewall.config import NpmConfig, UrlConfig, VibewallConfig


def test_valid_mode_block() -> None:
    cfg = NpmConfig(mode="block")
    assert cfg.mode == "block"


def test_valid_mode_warn() -> None:
    cfg = UrlConfig(mode="warn")
    assert cfg.mode == "warn"


def test_invalid_npm_mode_raises() -> None:
    with pytest.raises(ValueError, match="invalid mode 'blcok'"):
        NpmConfig(mode="blcok")


def test_invalid_url_mode_raises() -> None:
    with pytest.raises(ValueError, match="invalid mode 'foo'"):
        UrlConfig(mode="foo")


def test_load_nonexistent_returns_defaults() -> None:
    cfg = VibewallConfig.load(None)
    assert cfg.port == 8888
    assert cfg.npm.mode == "block"
    assert cfg.url.mode == "block"


def test_load_with_invalid_mode(tmp_path) -> None:
    toml_file = tmp_path / "bad.toml"
    toml_file.write_text('[npm]\nmode = "invalid"\n')
    with pytest.raises(ValueError, match="invalid mode"):
        VibewallConfig.load(toml_file)
