#!/usr/bin/env bash
set -euo pipefail

MODELS_DIR="${TRANSFORMERS_CACHE:-${HF_HOME:-/tmp/cyberarmor_models}}"

# Make sure the model cache exists. mkdir is harmless either way; non-root
# users won't be allowed to create parents under /tmp that don't already
# exist, but our Dockerfile already creates /tmp/cyberarmor_models at build
# time so the mkdir is idempotent.
mkdir -p "${MODELS_DIR}"

# The Dockerfile sets ``USER appuser`` so this script normally runs as
# appuser and the cache dir is already chown'd at build time. The previous
# version of this script called ``su -s /bin/sh appuser -c ...`` which
# failed because (a) appuser has no password and (b) we're already running
# as appuser, so su has nothing useful to do. We only need to handle the
# user switch when the image is (re-)built to start as root — e.g. to
# fix permissions on a host-bind-mounted volume.
if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser "${MODELS_DIR}"
    exec runuser -u appuser -- uvicorn main:app --host 0.0.0.0 --port 8002
fi

exec uvicorn main:app --host 0.0.0.0 --port 8002
