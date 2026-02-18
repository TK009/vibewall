Vibewall - Keep bad vibes away
==============================

Hallucination firewall for AI coding agents. Vibewall is an HTTP/HTTPS proxy that intercepts network requests from your agent sandbox and blocks suspicious activity — hallucinated npm packages, typosquatting attempts, and sketchy domains.

## How it works

Vibewall sits between your AI agent and the internet as a [mitmproxy](https://mitmproxy.org/) addon. Every outgoing request is validated before it reaches its destination.

**npm registry requests** go through layered checks:

1. **Blocklist** — known malicious packages are rejected immediately
2. **Allowlist** — trusted packages (110+ popular ones included) skip further checks
3. **Existence** — the package must actually exist on npm (catches hallucinations)
4. **Typosquatting** — packages suspiciously similar to allowlisted names are flagged (Levenshtein distance)
5. **Age** — packages younger than 7 days are blocked
6. **Popularity** — packages with fewer than 10 weekly downloads are blocked

**All other URLs** (when enabled) are validated for:

1. **DNS resolution** — the domain must actually exist
2. **Domain age** — domains younger than 30 days are blocked via WHOIS lookup

Each validator runs in **block** or **warn** mode independently. Block mode returns `403 Forbidden`; warn mode logs the issue but lets the request through.

## Quick start

### Docker (recommended)

```bash
docker compose up --build
```

This starts vibewall on port 8888 and an example Node agent container pre-configured to route through the proxy. The mitmproxy CA certificate is shared via a Docker volume.

### Direct install

```bash
pip install .
vibewall --config config/vibewall.toml --config-dir config
```

Requires Python 3.12+.

### Point your agent at the proxy

```bash
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888

# For Node/npm — trust the mitmproxy CA
export NODE_EXTRA_CA_CERTS=/path/to/mitmproxy-ca-cert.pem
export npm_config_cafile=/path/to/mitmproxy-ca-cert.pem
```

## Configuration

Edit `config/vibewall.toml`:

```toml
port = 8888
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

  --port, -p       Proxy listen port (default: 8888)
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
