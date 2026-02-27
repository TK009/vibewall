from __future__ import annotations

import inspect
import shutil
from pathlib import Path

import aiohttp
import structlog
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from vibewall.cache.store import SQLiteCache
from vibewall.config import VibewallConfig
from vibewall.exceptions import CheckError
from vibewall.console import ConsoleDisplay
from vibewall.notifications import Notifier
from vibewall.proxy.addon import VibewallAddon
from vibewall.validators.base import BaseCheck
from vibewall.validators.checks import ALL_CHECKS, CHECK_ABBREVS, SCOPE_ORDER
from vibewall.validators.rules import RuleSet
from vibewall.validators.runner import CheckRunner

logger = structlog.get_logger()


def _build_checks(
    config: VibewallConfig,
    ruleset: RuleSet,
    session: aiohttp.ClientSession,
) -> list[BaseCheck]:
    """Instantiate all check classes with only the dependencies they declare."""
    available: dict[str, object] = {
        "ruleset": ruleset,
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
        except (TypeError, CheckError) as e:
            logger.error("check_init_skipped", check=cls.name, error=str(e))

    return checks


def _build_enabled_checks(config: VibewallConfig, runner: CheckRunner) -> dict[str, list[str]]:
    """Get enabled check names per scope for the display."""
    enabled: dict[str, list[str]] = {}
    for scope in ("npm", "url", "pypi"):
        names = runner.get_enabled_check_names(scope)
        if names:
            enabled[scope] = names
    return enabled


async def run_proxy(config: VibewallConfig, verbose: bool = False) -> None:
    cache = SQLiteCache(
        db_path=config.cache.db_path,
        max_entries=config.cache.max_entries,
        cleanup_interval=config.cache.cleanup_interval,
    )
    await cache.open()

    # Load unified rules
    ruleset = RuleSet.load(config.config_dir / "rules.txt", config.config_dir)

    # Shared HTTP session (trust_env=False to avoid proxy loop)
    session = aiohttp.ClientSession(trust_env=False)

    checks = _build_checks(config, ruleset, session)

    # LLM client + request history for ask-llm-* actions
    llm_client = None
    if config.llm and config.llm.api_key:
        from vibewall.llm.client import LlmClient

        llm_client = LlmClient(config.llm, session)
        logger.info("llm_client_enabled", provider=config.llm.provider, model=config.llm.model)

    from vibewall.llm.history import RequestHistory

    history = RequestHistory(maxlen=50)

    runner = CheckRunner(checks, config, cache, llm_client=llm_client, history=history)

    # Build notifier
    notifier = Notifier(
        enabled=config.notifications.enabled,
        expire_ms=config.notifications.expire_ms,
    )

    # Build console display
    enabled_checks = _build_enabled_checks(config, runner)
    display = ConsoleDisplay(
        enabled_checks, CHECK_ABBREVS, SCOPE_ORDER, verbose=verbose,
        notifier=notifier if config.notifications.ask else None,
        ask_timeout=config.notifications.ask_timeout,
    )
    display.set_port(config.port)

    addon = VibewallAddon(
        config, runner, display,
        notifier=notifier if config.notifications.enabled else None,
    )

    confdir = Path.home() / ".vibewall"
    confdir.mkdir(parents=True, exist_ok=True)

    opts = options.Options(
        listen_host=config.host,
        listen_port=config.port,
        confdir=str(confdir),
    )
    master = DumpMaster(opts)
    master.addons.add(addon)

    # Suppress mitmproxy's built-in Dumper output
    opts.update(flow_detail=0)

    # Copy CA cert to shared volume if it exists
    ca_cert = confdir / "mitmproxy-ca-cert.pem"
    cert_dest = Path("/certs/mitmproxy-ca-cert.pem")
    if cert_dest.parent.exists() and ca_cert.exists():
        shutil.copy2(ca_cert, cert_dest)
        logger.info("ca_cert_copied", dest=str(cert_dest))

    display.start()
    try:
        await master.run()
    finally:
        display.print_stats()
        await runner.shutdown()
        await cache.close()
        await session.close()
