from __future__ import annotations

import shutil
from pathlib import Path

import structlog
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from vibewall.cache.store import TTLCache
from vibewall.config import VibewallConfig
from vibewall.proxy.addon import VibewallAddon
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.npm import NpmValidator
from vibewall.validators.url import UrlValidator

logger = structlog.get_logger()


async def run_proxy(config: VibewallConfig) -> None:
    cache = TTLCache(max_entries=config.cache.max_entries)

    allowlist_path = config.config_dir / "allowlist.txt"
    blocklist_path = config.config_dir / "blocklist.txt"
    npm_lists = AllowBlockList(allowlist_path, blocklist_path)

    npm_validator = NpmValidator(
        config=config.npm,
        cache_config=config.cache,
        cache=cache,
        lists=npm_lists,
    )

    url_allowlist_path = config.config_dir / "url_allowlist.txt"
    url_blocklist_path = config.config_dir / "url_blocklist.txt"
    url_lists = AllowBlockList(url_allowlist_path, url_blocklist_path)
    url_validator = UrlValidator(
        config=config.url,
        cache_config=config.cache,
        cache=cache,
        lists=url_lists,
    )

    addon = VibewallAddon(config, npm_validator, url_validator)

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
        await npm_validator.close()
        await url_validator.close()
