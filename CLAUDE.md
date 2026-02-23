# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Vibewall

Vibewall is a hallucination firewall for AI coding agents. It's an HTTP/HTTPS proxy (mitmproxy addon) that intercepts outgoing requests and validates npm packages, PyPI packages, and URLs against a pipeline of checks. Blocked requests return 403; warn-mode checks log but allow through.

## Commands

```bash
# Install for development
uv pip install -e ".[dev]"

# Run tests
uv run pytest

# Run a single test
uv run pytest tests/test_checks_npm.py::test_name

# Run the proxy
uv run vibewall --config config/vibewall.toml --config-dir config

# Docker
docker compose up --build
```

Requires Python 3.14+.

## Architecture

### Check Pipeline System

The core pattern is a **check pipeline** with dependency resolution. Each check is a subclass of `BaseCheck` (in `validators/base.py`) that:
- Has a `name`, `abbrev`, `scope` ("npm", "pypi", or "url"), and `depends_on` list
- Implements `async run(target, context) -> CheckResult`
- Returns a `CheckResult` with status `OK`, `FAIL`, `SUS` (suspicious/warn), or `ERR` (fail-open)

`CheckRunner` (`validators/runner.py`) topologically sorts checks into layers (Kahn's algorithm), runs each layer concurrently with `asyncio.gather()`, and passes results between dependent checks via `CheckContext`.

### Short-circuit behavior

- Blocklist `FAIL` → immediate block, skip remaining checks
- Allowlist `OK` with `allowlisted=True` in data → immediate allow, skip remaining checks

### Action modes

Each validator has an action: `"block"`, `"warn"`, `"ask-allow"`, `"ask-block"`, `"ask-llm-allow"`, or `"ask-llm-block"`. The runner downgrades FAIL→SUS for warn-action checks. Ask-action checks prompt the user interactively. Ask-llm actions batch all pending FAILs into a single LLM call that returns `DECISION: ALLOW|BLOCK|WARN`. Action resolution logic lives in `validators/action.py`.

### LLM integration

The `llm/` module provides an optional LLM adjudicator for `ask-llm-*` actions. `llm/client.py` wraps the LLM API, `llm/prompt.py` builds structured prompts from check results, and `llm/history.py` tracks past decisions. The LLM makes a single batched decision per target.

### Key source layout

- `src/vibewall/cli.py` — Click CLI entry point (`vibewall.cli:main`)
- `src/vibewall/proxy/addon.py` — mitmproxy addon, intercepts requests, extracts package names via regex, routes to npm/pypi/url scope
- `src/vibewall/proxy/server.py` — bootstraps everything: cache, lists, aiohttp session, checks, mitmproxy DumpMaster
- `src/vibewall/validators/checks/` — individual check implementations (npm_*, pypi_*, url_*)
- `src/vibewall/validators/runner.py` — check orchestration with topological sort, caching, short-circuiting
- `src/vibewall/validators/action.py` — action resolution: warn downgrade, ask prompting, LLM adjudication
- `src/vibewall/validators/allowlist.py` — allowlist/blocklist loading and matching
- `src/vibewall/models.py` — frozen dataclasses: `CheckResult`, `CheckContext`, `RunResult`, `CheckStatus` enum
- `src/vibewall/config.py` — TOML config loading with `VibewallConfig`, `ValidatorConfig`, `CacheConfig`; default validator configs in `_VALIDATOR_DEFAULTS`
- `src/vibewall/cache/store.py` — in-memory TTL cache with LRU eviction
- `src/vibewall/console.py` — Rich-based live terminal UI showing check status per request
- `config/` — `vibewall.toml`, `allowlist.txt`, `blocklist.txt`, `url_allowlist.txt`, `url_blocklist.txt`

### Conventions

- All check results are frozen dataclasses for async safety
- Checks fail open on network errors (ERR status allows the request through)
- Checks receive dependencies via constructor injection (allowlist/blocklist objects, aiohttp session, config params)
- `CheckResult` uses factory methods: `CheckResult.ok()`, `.fail()`, `.sus()`, `.err()`
- Cache keys are `{check_name}:{target}`; TTL is per-validator configurable
- Tests use `StubCheck` for runner logic tests and `aioresponses`/`pytest-httpserver` for HTTP mocking
- pytest runs with `asyncio_mode = "auto"` (no need for `@pytest.mark.asyncio`)
- npm, PyPI, and URL scopes follow the same check pattern — each scope has blocklist, allowlist, registry, existence, typosquat, age, downloads, and advisories checks (URL scope has dns and domain_age instead)
