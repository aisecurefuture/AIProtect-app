ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    pydantic \
    httpx \
    cryptography

# Detonation runs in a SEPARATE service (services/detonation-worker/)
# built on Microsoft's official Playwright Python image. The gate is
# only an HTTP client — see services/url-trust-gate/detonation.py.
#
# This split exists for two reasons:
#   1. Mixing fetches of attacker-controlled URLs with calls to
#      internal services (detection, policy, audit) is the wrong shape.
#      The compose stack puts the worker on its own egress-only network.
#   2. Microsoft's published image tracks Chromium + OS libs;
#      installing Playwright onto the gate's Debian PQC base hit
#      Ubuntu/Debian package-name mismatches in `playwright install
#      --with-deps`.
#
# Configure with DETONATION_WORKER_URL (e.g. http://detonation-worker:8015).
# If unset, the gate cleanly downgrades deep-mode requests to standard.

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH:-}"

COPY services/url-trust-gate/main.py          ./main.py
COPY services/url-trust-gate/canonicalize.py  ./canonicalize.py
COPY services/url-trust-gate/reputation.py    ./reputation.py
COPY services/url-trust-gate/crawler.py       ./crawler.py
COPY services/url-trust-gate/detonation.py    ./detonation.py
COPY services/url-trust-gate/extractors.py    ./extractors.py
COPY services/url-trust-gate/evidence.py      ./evidence.py
COPY services/url-trust-gate/feeds.py         ./feeds.py
COPY services/url-trust-gate/safebrowsing_v4.py ./safebrowsing_v4.py
COPY services/url-trust-gate/metrics.py       ./metrics.py
COPY services/url-trust-gate/tenant_lists.py  ./tenant_lists.py
COPY scripts/security/run_uvicorn_tls.py      ./run_uvicorn_tls.py

# The audit spool must exist in the image, owned by appuser, BEFORE the named
# volume is mounted over it: Docker seeds a fresh volume from the mount point as
# it exists in the image, and creates it ROOT-OWNED if the path is absent. This
# process runs as appuser, so the spool would be unusable on first boot and
# every event would be counted as lost during an audit outage.
RUN mkdir -p /var/lib/cyberarmor/audit-spool
RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

RUN chown -R appuser:appuser /var/lib/cyberarmor
USER appuser

# IMPORTANT: this service initiates outbound requests to attacker-controlled
# URLs. In production it MUST run in a dedicated network namespace with NO
# route to internal services or metadata endpoints. The Python-level SSRF
# checks in crawler.py are belt-and-braces; the network namespace is the
# real boundary.
EXPOSE 8014
CMD ["python", "run_uvicorn_tls.py", "main:app", "8014"]
