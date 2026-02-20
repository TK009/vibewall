Vibewall - Keep bad vibes away
==============================

Hallucination firewall for AI coding agents. Vibewall is an HTTP/HTTPS proxy that intercepts network requests from your agent sandbox and blocks suspicious activity — hallucinated npm packages, typosquatting attempts, and sketchy domains.

## How it works

Vibewall sits between your AI agent and the internet as a [mitmproxy](https://mitmproxy.org/) addon. Every outgoing request is validated before it reaches its destination.

Each validator runs in **block**, **warn**, or **ask** mode independently. Block mode returns `403 Forbidden`; warn mode logs the issue but lets the request through; ask mode prompts interactively.

## Validators

### npm checks

| Validator | Description | Default action |
|---|---|---|
| `npm_blocklist` | Rejects packages on the blocklist immediately | block |
| `npm_allowlist` | Trusts allowlisted packages and skips remaining checks | block |
| `npm_registry` | Fetches package metadata from the npm registry | warn |
| `npm_existence` | Fails if the package doesn't exist on npm (catches hallucinations) | block |
| `npm_typosquat` | Flags packages suspiciously similar to allowlisted names (Levenshtein distance) | warn |
| `npm_age` | Blocks packages younger than a configurable threshold (default: 7 days) | block |
| `npm_downloads` | Flags packages with fewer than a configurable number of weekly downloads | warn |
| `npm_advisories` | Queries OSV for known vulnerabilities with configurable severity thresholds | block |

### PyPI checks

| Validator | Description | Default action |
|---|---|---|
| `pypi_blocklist` | Rejects packages on the blocklist immediately | block |
| `pypi_allowlist` | Trusts allowlisted packages and skips remaining checks | block |
| `pypi_registry` | Fetches package metadata from the PyPI JSON API | warn |
| `pypi_existence` | Fails if the package doesn't exist on PyPI (catches hallucinations) | block |
| `pypi_typosquat` | Flags packages suspiciously similar to allowlisted names (Levenshtein distance) | warn |
| `pypi_age` | Blocks packages younger than a configurable threshold (default: 7 days) | block |
| `pypi_downloads` | Flags packages with low weekly downloads via pypistats.org | warn |
| `pypi_advisories` | Queries OSV for known vulnerabilities with configurable severity thresholds | block |

### URL checks

| Validator | Description | Default action |
|---|---|---|
| `url_blocklist` | Rejects domains on the blocklist immediately | block |
| `url_allowlist` | Trusts allowlisted domains and skips remaining checks | block |
| `url_dns` | Fails if the domain doesn't resolve in DNS | block |
| `url_domain_age` | Blocks domains younger than a configurable threshold (default: 30 days) via WHOIS | block |

## Quick start

### Docker (recommended)

```bash
docker compose up --build
```

This starts vibewall on port 7777 and an example Node agent container pre-configured to route through the proxy. The mitmproxy CA certificate is shared via a Docker volume.

### Direct install

```bash
pip install .
vibewall --config config/vibewall.toml --config-dir config
```

Requires Python 3.12+.

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

Edit `config/vibewall.toml`:

```toml
port = 7777
host = "0.0.0.0"

[npm]
min_weekly_downloads = 10        # minimum weekly downloads to allow
min_package_age_days = 7         # minimum package age
max_typosquat_distance = 2       # Levenshtein distance threshold
mode = "block"                   # "block" or "warn"

[url]
min_domain_age_days = 30         # minimum domain age
mode = "block"                   # "block" or "warn"
enabled = true                   # toggle URL validation

[cache]
npm_positive_ttl = 86400         # 24h — allowed packages
npm_negative_ttl = 3600          # 1h — blocked packages
url_ttl = 3600                   # 1h — URL checks
whois_ttl = 604800               # 7d — WHOIS lookups
```

### Allowlist and blocklist

`config/allowlist.txt` and `config/blocklist.txt` are plain text, one entry per line. Comments start with `#`.

The default allowlist includes 110+ popular npm packages (react, express, lodash, etc.) which bypass registry checks for performance.

## CLI options

```
vibewall [OPTIONS]

  --port, -p       Proxy listen port (default: 7777)
  --host, -h       Proxy listen host (default: 0.0.0.0)
  --config, -c     Path to vibewall.toml
  --config-dir     Directory containing allowlist/blocklist (default: config)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Dependencies

- [mitmproxy](https://mitmproxy.org/) — HTTP/HTTPS proxy
- [aiohttp](https://docs.aiohttp.org/) — async HTTP client
- [rapidfuzz](https://github.com/rapidfuzz/RapidFuzz) — typosquatting detection
- [python-whois](https://pypi.org/project/python-whois/) — domain age checks
- [click](https://click.palletsprojects.com/) — CLI
- [structlog](https://www.structlog.org/) — structured logging
