from __future__ import annotations

import asyncio
from pathlib import Path

import click
import structlog

from vibewall.config import VibewallConfig
from vibewall.proxy.server import run_proxy


@click.command()
@click.option("--port", "-p", default=None, type=int, help="Proxy listen port")
@click.option("--host", "-H", default=None, help="Proxy listen host")
@click.option("--config", "-c", "config_path", default=None, type=click.Path(exists=False), help="Path to vibewall.toml")
@click.option("--config-dir", default=None, type=click.Path(), help="Directory containing allowlist/blocklist")
def main(port: int | None, host: str | None, config_path: str | None, config_dir: str | None) -> None:
    """Vibewall — Hallucination firewall for AI coding agents."""
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
    )
    log = structlog.get_logger()

    cfg_path = Path(config_path) if config_path else None
    config = VibewallConfig.load(cfg_path)

    # Only override config file values when explicitly passed on the CLI
    if port is not None:
        config.port = port
    if host is not None:
        config.host = host
    if config_dir is not None:
        config.config_dir = Path(config_dir)

    log.info(
        "vibewall_config",
        port=config.port,
        host=config.host,
        validators=list(config.validators.keys()),
    )

    asyncio.run(run_proxy(config))


if __name__ == "__main__":
    main()
