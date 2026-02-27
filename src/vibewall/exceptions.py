"""Structured exception hierarchy for vibewall."""


class VibewallError(Exception):
    """Base exception for all vibewall errors."""


class ConfigError(VibewallError):
    """Invalid or missing configuration."""


class CheckError(VibewallError):
    """Error during check execution or initialization."""


class CacheError(VibewallError):
    """Cache operation failure (flush, deserialize, cleanup)."""
