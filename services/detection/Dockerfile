ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app

# System deps for tokenizers / torch CPU
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Web framework (from PyPI)
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic cryptography

# CPU-only torch – must use PyTorch's own index to get the +cpu wheel
RUN pip install --no-cache-dir "torch==2.6.0+cpu" \
    --index-url https://download.pytorch.org/whl/cpu

# HuggingFace model libraries
RUN pip install --no-cache-dir \
    transformers \
    tokenizers \
    accelerate \
    sentencepiece

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH:-}"

# Serving controls. ml_models.py imports detection_profile at module scope, so
# omitting any of these three kills the container at boot -- the exact defect
# scripts/security/check_deployed_artifact_imports.py exists to catch, and the
# reason that checker runs in CI rather than living in someone's memory.
COPY services/detection/detection_profile.py ./detection_profile.py
COPY services/detection/scan_cache.py ./scan_cache.py
COPY services/detection/rate_limit.py ./rate_limit.py
COPY services/detection/ml_models.py ./ml_models.py
COPY services/detection/main.py ./main.py
COPY services/detection/run_detection_service.sh ./run_detection_service.sh
# The COPY set IS the production filesystem -- prod builds images on the box.
# seed_models.py is run from inside this image by
# scripts/deployment/seed_hf_models.sh, so leaving it out means a fresh
# deployment has no way to populate the model cache.
COPY services/detection/seed_models.py ./seed_models.py

# Model cache directory. /models is where the hf_models named volume mounts in
# every compose file, so the image agrees with the deployment instead of
# contradicting it. This used to say /tmp/cyberarmor_models, which was
# overridden at runtime and sent anyone reading the Dockerfile to a path the
# service never uses. Created at build time with the right ownership so the
# image also works when run WITHOUT the volume -- appuser cannot mkdir at the
# filesystem root.
RUN mkdir -p /models
RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app /models && \
    chmod +x /app/run_detection_service.sh
# HF_HUB_CACHE is the one that decides where models are found. HF_HOME=/models
# alone resolves the hub cache to /models/hub, and the models live at /models
# -- measured on the box with transformers 5.14.1 / huggingface_hub 1.26.0,
# where TRANSFORMERS_CACHE turned out to have no effect at all.
ENV HF_HUB_CACHE=/models
ENV TRANSFORMERS_CACHE=/models
ENV HF_HOME=/models
# 0 is correct HERE and must stay 0: seeding downloads models through this
# image, and an image that cannot reach the Hub cannot populate its own cache.
# Production turns it on at RUNTIME -- TRANSFORMERS_OFFLINE=1 in
# /etc/cyberarmor/demo.env -- which is the right layer for it, because the
# offline guarantee belongs to the deployment and not to the artifact.
# scripts/deployment/seed_hf_models.sh overrides it back to 0 for the
# throwaway seeding container only.
ENV TRANSFORMERS_OFFLINE=0

USER appuser

EXPOSE 8002
CMD ["bash", "/app/run_detection_service.sh"]
