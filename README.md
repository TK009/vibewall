# Vibewall — Keep bad vibes away

> [!WARNING]
> **Warning:** Vibewall is in early alpha. Expect rough edges, breaking changes, and bugs. Do not rely on it as your sole security layer. Contributions and bug reports are welcome.

**Firewall for AI coding agents.**

Your AI agent just suggested installing `reqeusts` instead of `requests`. A typosquatting package. Or maybe it hallucinated a package that doesn't exist at all — and someone already registered it with malware inside. Vibewall catches these before they reach your system. The goal is to catch all issues that even humans could do.

### What it does

- **Blocks hallucinated packages** — catches npm and PyPI packages that don't exist
- **Detects typosquatting** — flags packages suspiciously similar to popular ones (Levenshtein distance)
- **Checks security advisories** — queries OSV for known vulnerabilities with per-severity actions
- **Enforces package age** — blocks brand-new packages (configurable threshold)
- **Monitors download counts** — warns on packages with suspiciously low adoption
- **Validates URLs** — blocks unresolvable domains and newly registered domains via WHOIS
- **Rules engine** — allowlist/blocklist with regex support, `@import` directives, and per-scope method filtering
- **LLM adjudication** — optionally route ambiguous decisions to Claude or OpenAI for a second opinion
- **Desktop notifications** — interactive allow/block prompts via `notify-send`
- **Smart caching** — two-tier (memory + SQLite) cache with background refresh near expiry
- **Real-time console** — Rich-formatted live table showing every check as it runs

## How it works

Vibewall sits between your AI agent and the internet as a [mitmproxy](https://mitmproxy.org/) addon. Every outgoing request is intercepted and run through a check pipeline before reaching its destination.

```
Agent → HTTP_PROXY → Vibewall → [check pipeline] → Allow / 403 Forbidden
```

Checks are topologically sorted by dependency and run concurrently within each layer. Each check returns **OK**, **FAIL**, **SUS** (suspicious/warn), or **ERR** (fail-open). The pipeline short-circuits on blocklist hits and allowlist matches.

Each validator runs independently in one of six action modes:

| Action | Behavior |
|---|---|
| `block` | Returns HTTP 403 Forbidden |
| `warn` | Logs the issue, allows the request (FAIL → SUS) |
| `ask-allow` | Interactive prompt, defaults to allow |
| `ask-block` | Interactive prompt, defaults to block |
| `ask-llm-allow` | Batched LLM decision, defaults to allow on error |
| `ask-llm-block` | Batched LLM decision, defaults to block on error |

## Checks

### npm

| Check | Description | Default |
|---|---|---|
| `npm_rules` | Allowlist/blocklist matching | block |
| `npm_registry` | Fetches package metadata from the npm registry | warn |
| `npm_existence` | Fails if the package doesn't exist (catches hallucinations) | block |
| `npm_typosquat` | Flags names similar to allowlisted packages (edit distance ≤ 2) | warn |
| `npm_age` | Blocks packages younger than 7 days | block |
| `npm_downloads` | Flags packages with fewer than 10 weekly downloads | warn |
| `npm_advisories` | Queries OSV for known vulnerabilities with per-severity actions | block |

### PyPI

| Check | Description | Default |
|---|---|---|
| `pypi_rules` | Allowlist/blocklist matching | block |
| `pypi_registry` | Fetches package metadata from the PyPI JSON API | warn |
| `pypi_existence` | Fails if the package doesn't exist (catches hallucinations) | block |
| `pypi_typosquat` | Flags names similar to allowlisted packages (edit distance ≤ 2) | warn |
| `pypi_age` | Blocks packages younger than 7 days | block |
| `pypi_downloads` | Flags packages with low weekly downloads via pypistats.org | warn |
| `pypi_advisories` | Queries OSV for known vulnerabilities with per-severity actions | block |

### URL

| Check | Description | Default |
|---|---|---|
| `url_rules` | Allowlist/blocklist with HTTP method filtering | block |
| `url_dns` | Fails if the domain doesn't resolve in DNS | block |
| `url_domain_age` | Blocks domains younger than 30 days via WHOIS | block |

## Quick start

### Docker (recommended)

```bash
docker compose up --build
```

This starts vibewall on port 7777 and an example agent container pre-configured to route through the proxy. The mitmproxy CA certificate is shared via a Docker volume.

### Direct install

```bash
uv sync
uv run vibewall --config config/vibewall.toml --config-dir config
```

Requires Python 3.14+.

### Point your agent at the proxy

```bash
export HTTP_PROXY=http://localhost:7777
export HTTPS_PROXY=http://localhost:7777
```

### Trust the mitmproxy CA certificate

Install the CA into your OS trust store so most HTTP clients (curl, wget, Python, Go, etc.) trust the proxy automatically.

**Debian/Ubuntu:**

```bash
cp /path/to/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
update-ca-certificates
```

**Alpine:**

```bash
apk add ca-certificates
cp /path/to/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
update-ca-certificates
```

**Node.js** uses its own bundled CAs and ignores the OS store, so it still needs explicit configuration:

```bash
export NODE_EXTRA_CA_CERTS=/path/to/mitmproxy-ca-cert.pem
export npm_config_cafile=/path/to/mitmproxy-ca-cert.pem
```

## Configuration

Edit `config/vibewall.toml`. Every validator is independently configurable:

```toml
port = 7777
host = "0.0.0.0"
pipeline_timeout = 120

[validators.npm_age]
action = "block"
min_days = 7
missing_date = "fail"

[validators.npm_advisories]
action = "block"
ignore_allowlist = true
severity_low = "allow"
severity_medium = "warn"
severity_high = "warn"
severity_critical = "ask-block"
cache_ttl = 3600

[validators.url_domain_age]
action = "block"
min_days = 30
cache_ttl = 604800
```

### Rules

`config/rules.txt` is a unified rules file supporting allowlists, blocklists, regex patterns, and imports:

```
# Import external lists with scope and action
@import blocklist.txt [block scope=npm]
@import allowlist.txt [allow scope=npm]

# Inline rules with regex
[block scope=url methods=POST]
/evil\.example\.com/
```

### Cache

```toml
[cache]
default_ttl = 3600        # 1h default
error_ttl = 60             # 1min for errors (fail-open, retry soon)
max_entries = 50000         # LRU eviction at capacity
# db_path = "~/.vibewall/cache.db"
```

### LLM adjudication (optional)

Route ambiguous `ask-llm-*` decisions to an LLM. Supports Anthropic and OpenAI-compatible endpoints:

```toml
[llm]
provider = "anthropic"
model = "claude-sonnet-4-20250514"
api_key = "$ANTHROPIC_API_KEY"
max_tokens = 256
temperature = 0.0
max_concurrent = 5
cache_ttl = 120
```

### Notifications

```toml
[notifications]
# enabled = true          # auto-detect notify-send
expire_ms = 20000
ask_timeout = 70           # seconds for interactive prompts
```

## CLI

```
vibewall [OPTIONS]

  --port, -p PORT        Proxy listen port (default: 7777)
  --host, -H HOST        Proxy listen host (default: 0.0.0.0)
  --config, -c PATH      Path to vibewall.toml
  --config-dir DIR       Directory containing rules, allowlist, blocklist
  --verbose, -v          Show debug logs

vibewall cache merge <source> [--target <path>]
  Merge a source cache DB into the target (last-write-wins)
```

## Development

```bash
uv sync
uv run pytest
```

## Dependencies

- [mitmproxy](https://mitmproxy.org/) — HTTP/HTTPS proxy
- [aiohttp](https://docs.aiohttp.org/) — async HTTP client
- [aiosqlite](https://github.com/omnilib/aiosqlite) — async SQLite for caching
- [rapidfuzz](https://github.com/rapidfuzz/RapidFuzz) — typosquatting detection
- [python-whois](https://pypi.org/project/python-whois/) — domain age checks
- [click](https://click.palletsprojects.com/) — CLI
- [structlog](https://www.structlog.org/) — structured logging
- [rich](https://github.com/Textualize/rich) — console display
- [anthropic](https://github.com/anthropics/anthropic-sdk-python) / [openai](https://github.com/openai/openai-python) — LLM clients
