from __future__ import annotations

import shutil
from pathlib import Path

import aiohttp
import structlog
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from vibewall.cache.store import TTLCache
from vibewall.config import VibewallConfig
from vibewall.proxy.addon import VibewallAddon
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.checks import ALL_CHECKS
from vibewall.validators.runner import CheckRunner

logger = structlog.get_logger()


def _build_checks(
    config: VibewallConfig,
    npm_lists: AllowBlockList,
    url_lists: AllowBlockList,
    session: aiohttp.ClientSession,
) -> list:
    """Instantiate all check classes with their dependencies."""
    from vibewall.validators.base import BaseCheck

    # Shared kwargs available to all check constructors
    kwargs_map: dict[str, dict] = {}
    for cls in ALL_CHECKS:
        name = cls.name
        vc = config.get_validator(name)
        params = vc.params if vc else {}

        kwargs = dict(params)
        kwargs["lists"] = npm_lists
        kwargs["url_lists"] = url_lists
        kwargs["session"] = session
        kwargs_map[name] = kwargs

    checks: list[BaseCheck] = []
    for cls in ALL_CHECKS:
        try:
            checks.append(cls(**kwargs_map[cls.name]))
        except TypeError as e:
            logger.warning("check_init_failed", check=cls.name, error=str(e))

    return checks


async def run_proxy(config: VibewallConfig) -> None:
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

    addon = VibewallAddon(config, runner)

    opts = options.Options(
        listen_host=config.host,
        listen_port=config.port,
    )
    master = DumpMaster(opts)
    master.addons.add(addon)

    # Copy CA cert to shared volume if it exists
    ca_cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    cert_dest = Path("/certs/mitmproxy-ca-cert.pem")
    if cert_dest.parent.exists() and ca_cert.exists():
        shutil.copy2(ca_cert, cert_dest)
        logger.info("ca_cert_copied", dest=str(cert_dest))

    logger.info("proxy_starting", host=config.host, port=config.port)
    try:
        await master.run()
    finally:
        await session.close()
