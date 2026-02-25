from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click
import structlog

from vibewall.config import VibewallConfig
from vibewall.proxy.server import run_proxy


@click.group(invoke_without_command=True)
@click.option("--port", "-p", default=None, type=click.IntRange(1, 65535), help="Proxy listen port")
@click.option("--host", "-H", default=None, help="Proxy listen host")
@click.option("--config", "-c", "config_path", default=None, type=click.Path(exists=False), help="Path to vibewall.toml")
@click.option("--config-dir", default=None, type=click.Path(), help="Directory containing allowlist/blocklist")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose output (show debug logs)")
@click.pass_context
def main(ctx: click.Context, port: int | None, host: str | None, config_path: str | None, config_dir: str | None, verbose: bool) -> None:
    """Vibewall — Hallucination firewall for AI coding agents."""
    log_level = logging.DEBUG if verbose else logging.WARNING
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
    logging.basicConfig(level=log_level, format="%(message)s", handlers=[logging.StreamHandler()])

    # If a subcommand is invoked, skip the proxy startup
    if ctx.invoked_subcommand is not None:
        return

    cfg_path = Path(config_path) if config_path else None
    config = VibewallConfig.load(cfg_path)

    if port is not None:
        config.port = port
    if host is not None:
        config.host = host
    if config_dir is not None:
        config.config_dir = Path(config_dir)

    asyncio.run(run_proxy(config, verbose=verbose))


@main.group()
def cache() -> None:
    """Cache management commands."""


@cache.command()
@click.argument("source", type=click.Path(exists=True))
@click.option("--target", "-t", default="~/.vibewall/cache.db", help="Target cache DB path")
def merge(source: str, target: str) -> None:
    """Merge a source cache DB into the target (last-write-wins)."""
    from vibewall.cache.merge import merge_databases

    target_resolved = str(Path(target).expanduser())
    source_resolved = str(Path(source).expanduser())

    count = merge_databases(target_resolved, source_resolved)
    click.echo(f"Merged {count} entries from {source} into {target_resolved}")


if __name__ == "__main__":
    main()
