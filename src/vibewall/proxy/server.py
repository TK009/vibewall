from __future__ import annotations

import inspect
import shutil
from pathlib import Path

import aiohttp
import structlog
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from vibewall.cache.store import TTLCache
from vibewall.config import VibewallConfig
from vibewall.console import ConsoleDisplay
from vibewall.proxy.addon import VibewallAddon
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseCheck
from vibewall.validators.checks import ALL_CHECKS, CHECK_ABBREVS, SCOPE_ORDER
from vibewall.validators.runner import CheckRunner

logger = structlog.get_logger()

# Dependencies available to check constructors, keyed by parameter name.
_DEP_KEYS = {"lists", "url_lists", "session"}


def _build_checks(
    config: VibewallConfig,
    npm_lists: AllowBlockList,
    url_lists: AllowBlockList,
    session: aiohttp.ClientSession,
) -> list[BaseCheck]:
    """Instantiate all check classes with only the dependencies they declare."""
    available: dict[str, object] = {
        "lists": npm_lists,
        "url_lists": url_lists,
        "session": session,
    }

    checks: list[BaseCheck] = []
    for cls in ALL_CHECKS:
        vc = config.get_validator(cls.name)
        params = dict(vc.params) if vc else {}

        # Inspect the constructor to determine which deps it actually accepts
        sig = inspect.signature(cls.__init__)
        accepted = set(sig.parameters.keys()) - {"self"}
        has_var_keyword = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()
        )

        kwargs: dict[str, object] = {}
        for key, value in available.items():
            if key in accepted or has_var_keyword:
                kwargs[key] = value
        kwargs.update(params)

        try:
            checks.append(cls(**kwargs))
        except TypeError as e:
            logger.error("check_init_skipped", check=cls.name, error=str(e))

    return checks


def _build_enabled_checks(config: VibewallConfig, runner: CheckRunner) -> dict[str, list[str]]:
    """Get enabled check names per scope for the display."""
    enabled: dict[str, list[str]] = {}
    for scope in ("npm", "url"):
        names = runner.get_enabled_check_names(scope)
        if names:
            enabled[scope] = names
    return enabled


async def run_proxy(config: VibewallConfig, verbose: bool = False) -> None:
    cache = TTLCache(max_entries=config.cache.max_entries)

    # Load allow/block lists
    npm_lists = AllowBlockList(
        config.config_dir / "allowlist.txt",
        config.config_dir / "blocklist.txt",
    )
    url_lists = AllowBlockList(
        config.config_dir / "url_allowlist.txt",
        config.config_dir / "url_blocklist.txt",
    )

    # Shared HTTP session (trust_env=False to avoid proxy loop)
    session = aiohttp.ClientSession(trust_env=False)

    checks = _build_checks(config, npm_lists, url_lists, session)
    runner = CheckRunner(checks, config, cache)

    # Build console display
    enabled_checks = _build_enabled_checks(config, runner)
    display = ConsoleDisplay(
        enabled_checks, CHECK_ABBREVS, SCOPE_ORDER, verbose=verbose,
    )
    display.set_port(config.port)

    addon = VibewallAddon(config, runner, display)

    opts = options.Options(
        listen_host=config.host,
        listen_port=config.port,
    )
    master = DumpMaster(opts)
    master.addons.add(addon)

    # Suppress mitmproxy's built-in Dumper output
    opts.update(flow_detail=0)

    # Copy CA cert to shared volume if it exists
    ca_cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    cert_dest = Path("/certs/mitmproxy-ca-cert.pem")
    if cert_dest.parent.exists() and ca_cert.exists():
        shutil.copy2(ca_cert, cert_dest)
        logger.info("ca_cert_copied", dest=str(cert_dest))

    display.start()
    try:
        await master.run()
    finally:
        display.print_stats()
        await session.close()
