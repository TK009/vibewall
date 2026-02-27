from __future__ import annotations

from vibewall.validators.checks._registry_base import RegistryCheckBase


class PypiRegistryCheck(RegistryCheckBase):
    name = "pypi_registry"
    scope = "pypi"
    registry_url_template = "https://pypi.org/pypi/{encoded}/json"
    safe_chars = ""
    log_prefix = "pypi"
