# What is Vibewall

Vibewall is a hallucination firewall for AI coding agents. It's an HTTP/HTTPS proxy (mitmproxy addon) that intercepts outgoing requests and validates npm packages, PyPI packages, and URLs etc. against a pipeline of checks.

# Commands

```bash
# Install for development
uv sync

# Run tests
uv run pytest

# Run the proxy
uv run vibewall --config config/vibewall.toml --config-dir config
```

# Architecture

## Check Pipeline System

The core pattern is a **check pipeline** with dependency resolution. Each check is a subclass of `BaseCheck` (in `validators/base.py`) that:
- Has a `name`, `abbrev`, `scope` ("npm", "pypi", or "url"), and `depends_on` list
- Implements `async run(target, context) -> CheckResult`
- Returns a `CheckResult` with status `OK`, `FAIL`, `SUS` (suspicious/warn), or `ERR` (fail-open)

`CheckRunner` topologically sorts checks into layers, runs concurrently, and passes results between dependent checks via `CheckContext`.

## Action modes

Each validator has an action: `"block"`, `"warn"`, `"ask-allow"`, `"ask-block"`, `"ask-llm-allow"`, or `"ask-llm-block"`. The runner downgrades FAIL→SUS for warn-action checks. Ask-action checks prompt the user interactively. Ask-llm actions batch all pending FAILs into a single LLM call that returns `DECISION: ALLOW|BLOCK|WARN`.

The `llm/` module provides an optional LLM adjudicator for `ask-llm-*` actions. `llm/client.py` wraps the LLM API, `llm/prompt.py` builds structured prompts from check results, and `llm/history.py` tracks past decisions. The LLM makes a single batched decision per target.

## Conventions

- All check results are frozen dataclasses for async safety
- Checks receive dependencies via constructor injection (allowlist/blocklist objects, aiohttp session, config params)
- Tests use `StubCheck` for runner logic tests and `aioresponses`/`pytest-httpserver` for HTTP mocking
- pytest runs with `asyncio_mode = "auto"` (no need for `@pytest.mark.asyncio`)
