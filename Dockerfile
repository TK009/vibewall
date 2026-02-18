FROM python:3.12-slim

RUN groupadd -r vibewall && useradd -r -g vibewall -m vibewall

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY config/ config/

RUN pip install --no-cache-dir . && \
    mkdir -p /certs && chown vibewall:vibewall /certs

USER vibewall

EXPOSE 7777

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7777')" || exit 1

CMD ["vibewall", "--config", "config/vibewall.toml", "--config-dir", "config"]
