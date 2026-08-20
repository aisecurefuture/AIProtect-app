FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi "uvicorn[standard]" pydantic sqlalchemy alembic httpx cryptography stripe

# The shared kernel. Not pip-installable (no pyproject/__init__ -- see
# FORK-PROVENANCE.md), so it ships by COPY + PYTHONPATH like every other
# service that uses it.
COPY libs/cyberarmor-core /app/libs/cyberarmor-core

# The policy engine, imported AS A LIBRARY. Its modules use flat imports
# (`import opa_client`), so the DIRECTORY must be importable -- there is no
# package to import from. policy_fields.py additionally reads
# shared/policy-fields.json off disk at import time, so that file has to ship
# too or the container dies at boot.
COPY libs/policy-engine /app/libs/policy-engine
COPY shared/policy-fields.json /app/shared/policy-fields.json
COPY shared/tiers.json /app/shared/tiers.json

ENV PYTHONPATH="/app/libs/cyberarmor-core:/app/libs/policy-engine:${PYTHONPATH:-}"

# No OPA sidecar in this product. The engine defaults this to true, and every
# evaluation would pay a urllib timeout against http://opa:8181 before falling
# back to the Python engine.
ENV OPA_ENABLED=false

COPY apps/api/*.py /app/

# The migrations, and Alembic's config. NOT optional: init_db() runs
# `alembic upgrade head` in-process on startup, so an image without these
# starts and then fails on the first request -- or, worse, would start against
# a schema nobody had migrated. The `*.py` glob above does not reach them.
COPY apps/api/alembic.ini /app/
COPY apps/api/migrations /app/migrations

RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8100
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
