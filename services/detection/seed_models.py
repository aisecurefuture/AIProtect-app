#!/usr/bin/env python3
"""Seed the HuggingFace model cache, then PROVE every model loads offline.

WHY THIS EXISTS

`/models` in the detection container is the named volume
`docker-compose_hf_models`. It was populated by hand -- once on 2026-05-05 and
again on 2026-08-05 for `ner_phi` -- and nothing in the repository recorded
that this had to happen. A fresh deployment therefore came up with an empty
volume, `TRANSFORMERS_OFFLINE=1` set from `/etc/cyberarmor/demo.env`, and
FIVE FAILED MODELS, prompt injection among them. The stack reported healthy
throughout: model loading is lazy, a failed load is caught and recorded, and
the container's health probe only asks whether HTTP answers.

State that lives only on the box is invisible to git and will not reproduce.
This script is that state, committed.

WHAT IT DOES, AND WHY IN TWO PHASES

  Phase 1 -- download. Fetches every model in ml_models.MODEL_IDS with the
    offline flags explicitly OFF. Idempotent: an already-cached model is a
    no-op, so this is safe to run on every deploy.

  Phase 2 -- verify, in a FRESH SUBPROCESS with TRANSFORMERS_OFFLINE=1 and
    HF_HUB_OFFLINE=1 forced on. This is the phase that matters and it is not
    redundant. Phase 1 succeeding proves bytes arrived; it does not prove the
    service can load them under the conditions production actually runs in.
    A partial download, a model whose config needs a file the snapshot missed,
    a cache written under the wrong path, or a tokenizer requiring a
    conversion that itself wants network -- all pass Phase 1 and fail at 3am
    as a silently degraded detector. A separate process is required because
    transformers caches offline-ness and the model itself at import time, so
    checking in-process would test the download we just did rather than a
    cold start.

The list comes from ml_models.MODEL_IDS, never a literal copy of it. A sixth
model added to the service is seeded by this script the moment it is added,
with no second place to remember. test_every_model_is_declared_and_seeded.py
pins that, and pins that the deployment declares each one too.

EXIT CODE IS THE CONTRACT: non-zero, naming every model that failed, if any
model cannot be loaded offline afterwards. Do not let a deploy proceed past a
non-zero exit -- that is the empty-volume state, and it is invisible until a
customer's prompt goes unscanned.

USAGE
    scripts/deployment/seed_hf_models.sh          # the supported entry point

    # or directly, inside the detection image, offline flags off:
    TRANSFORMERS_OFFLINE=0 HF_HUB_OFFLINE=0 python3 /app/seed_models.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

# Import the service's own registry so the model list cannot drift from the
# one the service actually loads.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ml_models import MODEL_IDS, MODELS_CACHE_DIR  # noqa: E402


# Artifacts this service will never load, skipped at download time.
#
# MEASURED: an unfiltered snapshot_download of these five models put 14GB in
# the volume -- dslim/bert-base-NER alone took 2.1GB for a ~430MB model, and
# facebook/bart-large-mnli 6.5GB for ~1.6GB. A HuggingFace repo commonly ships
# the same weights three or four times over: PyTorch, TensorFlow, Flax, ONNX.
# The detection image installs torch and nothing else, so every non-PyTorch
# copy is pure cost in bandwidth, disk and deploy time.
#
# DELIBERATELY CONSERVATIVE. `.bin` and `.safetensors` are BOTH kept: some
# repos ship only one, transformers prefers safetensors when both exist, and
# guessing wrong here means a model that cannot load. Only formats that
# require an explicit opt-in the service never passes (from_tf=True,
# from_flax=True) or a library it does not install (optimum, for ONNX) are
# excluded. If this list ever grows to cover a PyTorch format, phase 2 is what
# catches it -- it loads every model through the service's own accessor, so an
# over-aggressive filter fails the seed rather than shipping a dead detector.
IGNORE_PATTERNS = [
    "*.h5", "tf_model*",                    # TensorFlow
    "*.msgpack", "flax_model*",             # Flax
    "*.onnx", "*.onnx_data", "onnx/*",      # ONNX / optimum
    "*.tflite",                             # TFLite
    "rust_model.ot",                        # rust-bert
    "*.ckpt", "*.ckpt.index", "*.ckpt.meta",  # TF checkpoints
]

#: Never ignore these -- excluding one is how a model silently stops loading.
REQUIRED_ARTIFACT_HINTS = ("*.bin", "*.safetensors", "*.json", "*.txt",
                           "*.model", "tokenizer*")


def download(name: str, model_id: str) -> tuple[bool, str]:
    """Phase 1. Returns (ok, detail)."""
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        return False, "huggingface_hub not installed in this image"
    try:
        path = snapshot_download(
            repo_id=model_id,
            cache_dir=MODELS_CACHE_DIR or None,
            ignore_patterns=IGNORE_PATTERNS,
        )
        return True, path
    except Exception as exc:  # noqa: BLE001 - report, never abort the sweep
        return False, f"{type(exc).__name__}: {exc}"


# Loads through ml_models.load_pipeline -- the SERVICE'S own accessor, not a
# hand-rolled pipeline() call. This exact line was the bug: a bespoke
# `pipeline(task, model=id)` resolved the cache from the environment
# (HF_HOME=/models -> /models/hub) while the service passes cache_dir=/models
# explicitly and the models live at /models. All five models reported
# "cannot load offline" while the running service had all five loaded.
#
# A verifier that does not use the code path it verifies is not a verifier.
_VERIFY_SNIPPET = """
import json, sys
sys.path.insert(0, {app_dir!r})
try:
    import ml_models
    pipe = ml_models.load_pipeline({name!r})
    state = ml_models.model_status().get({name!r}, {{}})
    if pipe is None:
        print(json.dumps({{"ok": False,
                           "detail": "load returned None; status=%s last_error=%s"
                                     % (state.get("status"), state.get("last_error"))}}))
        sys.exit(1)
    print(json.dumps({{"ok": True, "detail": "loaded offline via %s"
                                             % ml_models.PIPELINE_ACCESSORS[{name!r}]}}))
except Exception as exc:
    print(json.dumps({{"ok": False,
                       "detail": type(exc).__name__ + ": " + str(exc)[:300]}}))
    sys.exit(1)
"""


def verify_offline(name: str, model_id: str) -> tuple[bool, str]:
    """Phase 2. Cold-load in a subprocess with offline FORCED on."""
    env = dict(os.environ)
    env["TRANSFORMERS_OFFLINE"] = "1"
    env["HF_HUB_OFFLINE"] = "1"
    env["HF_DATASETS_OFFLINE"] = "1"
    code = _VERIFY_SNIPPET.format(
        app_dir=os.path.dirname(os.path.abspath(__file__)), name=name,
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(code)],
            env=env, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return False, "timed out after 600s loading offline"
    line = (proc.stdout or "").strip().splitlines()
    if line:
        try:
            payload = json.loads(line[-1])
            return bool(payload.get("ok")), str(payload.get("detail", ""))
        except json.JSONDecodeError:
            pass
    return False, (proc.stderr or proc.stdout or "no output").strip()[:300]


def main() -> int:
    print(f"cache dir      : {MODELS_CACHE_DIR}")
    print(f"models to seed : {len(MODEL_IDS)}  (from ml_models.MODEL_IDS)")
    for n, m in MODEL_IDS.items():
        print(f"                 {n:<18} {m}")
    print()

    if os.getenv("TRANSFORMERS_OFFLINE") == "1" or os.getenv("HF_HUB_OFFLINE") == "1":
        print("REFUSING TO RUN: offline flags are set, so nothing could be "
              "downloaded and this would report success having done nothing.\n"
              "Run with TRANSFORMERS_OFFLINE=0 HF_HUB_OFFLINE=0 -- see "
              "scripts/deployment/seed_hf_models.sh.")
        return 2

    print("=== phase 1: download ===")
    downloaded = {}
    for name, model_id in MODEL_IDS.items():
        ok, detail = download(name, model_id)
        downloaded[name] = ok
        print(f"  {'ok  ' if ok else 'FAIL'} {name:<18} {model_id}")
        if not ok:
            print(f"       {detail}")

    print()
    print("=== phase 2: verify each model loads with offline FORCED on ===")
    failed = []
    for name, model_id in MODEL_IDS.items():
        ok, detail = verify_offline(name, model_id)
        print(f"  {'ok  ' if ok else 'FAIL'} {name:<18} {model_id}")
        if not ok:
            print(f"       {detail}")
            failed.append((name, model_id, detail))

    print()
    if failed:
        print(f"SEEDING FAILED: {len(failed)} of {len(MODEL_IDS)} model(s) "
              f"cannot be loaded offline.")
        for name, model_id, detail in failed:
            print(f"  - {name} ({model_id}): {detail}")
        print("\nDo NOT treat this deployment as ready. With "
              "TRANSFORMERS_OFFLINE=1 these detectors will fail to load and "
              "the affected scans report no findings.")
        return 1

    print(f"SEEDING OK: all {len(MODEL_IDS)} models load with "
          f"TRANSFORMERS_OFFLINE=1.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
