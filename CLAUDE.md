# CLAUDE.md

## What is Vibewall

Vibewall is a hallucination firewall for AI coding agents. It's an HTTP/HTTPS proxy (mitmproxy addon) that intercepts outgoing requests and validates npm packages and URLs against a pipeline of checks. Blocked requests return 403; warn-mode checks log but allow through.

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

## Architecture

### Check Pipeline System

The core pattern is a **check pipeline** with dependency resolution. Each check is a subclass of `BaseCheck` (in `validators/base.py`) that:
- Has a `name`, `abbrev`, `scope` ("npm" or "url"), and `depends_on` list
- Implements `async run(target, context) -> CheckResult`
- Returns a `CheckResult` with status `OK`, `FAIL`, `SUS` (suspicious/warn), or `ERR` (fail-open)

`CheckRunner` (`validators/runner.py`) topologically sorts checks into layers (Kahn's algorithm), runs each layer concurrently with `asyncio.gather()`, and passes results between dependent checks via `CheckContext`.

### Short-circuit behavior

- Blocklist `FAIL` → immediate block, skip remaining checks
- Allowlist `OK` with `allowlisted=True` in data → immediate allow, skip remaining checks

### Action modes

Each validator has an action: `"block"`, `"warn"`, or `"ask"`. The runner downgrades FAIL→SUS for warn-action checks. Ask-action checks prompt the user interactively.

### Key source layout

- `src/vibewall/proxy/addon.py` — mitmproxy addon, intercepts requests, extracts npm package names via regex, routes to npm or url scope
- `src/vibewall/proxy/server.py` — bootstraps everything: cache, lists, aiohttp session, checks, mitmproxy DumpMaster
- `src/vibewall/validators/checks/` — individual check implementations (npm_blocklist, npm_existence, npm_typosquat, npm_age, npm_downloads, npm_advisories, url_dns, url_domain_age, etc.)
- `src/vibewall/validators/runner.py` — check orchestration with topological sort, caching, short-circuiting
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
