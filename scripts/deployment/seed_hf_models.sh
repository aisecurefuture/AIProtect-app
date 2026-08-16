#!/usr/bin/env bash
#
# Seed the HuggingFace model cache into the `hf_models` volume, and refuse to
# report success unless every model then loads with the offline flag on.
#
# RUN THIS ONCE PER DEPLOYMENT, BEFORE THE STACK IS EXPECTED TO DETECT
# ANYTHING, and again after adding a model to ml_models.MODEL_IDS.
#
# WHY IT EXISTS
#   /models is the named volume docker-compose_hf_models. It was populated by
#   hand and nothing in the repo said so, so a fresh deployment came up with an
#   empty volume, TRANSFORMERS_OFFLINE=1 from /etc/cyberarmor/demo.env, and
#   five failed models -- prompt injection among them -- while every health
#   signal stayed green. Model loads are lazy and failures are swallowed into
#   a status field nobody's deploy checked.
#
# WHY IT IS SAFE TO RE-RUN
#   `docker compose run --rm` starts a THROWAWAY container from the detection
#   service definition. It gets the same hf_models volume, and it does not
#   touch the running detection container -- no restart, no dropped requests,
#   and emphatically not `docker compose down` (COMPOSE_PROFILES=prod puts
#   caddy in the default set, so `down` is a full 80/443 outage). Downloads are
#   idempotent; an already-cached model is a no-op.
#
# THE OFFLINE FLAGS ARE OVERRIDDEN FOR THIS RUN ONLY
#   demo.env sets TRANSFORMERS_OFFLINE=1, which is correct for the service and
#   fatal for a seeder. The -e flags below apply to the throwaway container and
#   change nothing about the running one. seed_models.py then forces the flags
#   back ON for its verification phase, so what gets proven is a cold offline
#   load, not the download that just happened.
#
# USAGE
#   scripts/deployment/seed_hf_models.sh
#   CYBERARMOR_ENV_FILE_ARG=/etc/cyberarmor/demo.env scripts/deployment/seed_hf_models.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_DIR="${REPO_ROOT}/infra/docker-compose"

# Production always passes --env-file /etc/cyberarmor/demo.env. Default to it
# when it exists so the common case needs no argument, and fall back to the
# local dev .env otherwise.
ENV_FILE="${CYBERARMOR_ENV_FILE_ARG:-}"
if [ -z "${ENV_FILE}" ]; then
    if [ -f /etc/cyberarmor/demo.env ]; then
        ENV_FILE=/etc/cyberarmor/demo.env
    else
        ENV_FILE="${COMPOSE_DIR}/.env"
    fi
fi

if [ ! -f "${ENV_FILE}" ]; then
    echo "env file not found: ${ENV_FILE}" >&2
    echo "pass one with CYBERARMOR_ENV_FILE_ARG=/path/to/env" >&2
    exit 2
fi

echo "repo      : ${REPO_ROOT}"
echo "compose   : ${COMPOSE_DIR}/docker-compose.yml"
echo "env file  : ${ENV_FILE}"
echo

cd "${COMPOSE_DIR}"

# --rm: throwaway. --no-deps: seeding needs no postgres, and starting one as a
# side effect of a model download would be a surprise on a live box.
#
# `|| status=$?` is load-bearing under `set -e`: without it a failing seed
# aborts the script right here, and the operator never sees the message below
# saying the deployment is not ready. Reporting the failure IS the feature.
status=0
docker compose --env-file "${ENV_FILE}" run --rm --no-deps \
    -e TRANSFORMERS_OFFLINE=0 \
    -e HF_HUB_OFFLINE=0 \
    -e HF_DATASETS_OFFLINE=0 \
    detection \
    python3 /app/seed_models.py || status=$?

echo
if [ "${status}" -eq 0 ]; then
    echo "Model cache seeded and verified. The detection service will load"
    echo "these from /models with TRANSFORMERS_OFFLINE=1."
    echo
    echo "NOTE: a detection container started BEFORE this ran may have already"
    echo "cached a failed load. Check /ready, and restart it if any model"
    echo "reports failed:"
    echo "  docker compose --env-file ${ENV_FILE} up -d detection"
else
    echo "SEEDING FAILED (exit ${status}). Do not treat this deployment as" >&2
    echo "ready: the affected detectors cannot load and their scans will" >&2
    echo "report no findings." >&2
fi

exit "${status}"
