from __future__ import annotations

from vibewall.validators.checks._registry_base import RegistryCheckBase


class NpmRegistryCheck(RegistryCheckBase):
    name = "npm_registry"
    scope = "npm"
    registry_url_template = "https://registry.npmjs.org/{encoded}"
    safe_chars = "@"
    log_prefix = "npm"
