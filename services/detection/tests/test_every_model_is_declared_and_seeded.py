"""Every model the service loads must be DECLARED in the deployment and
SEEDABLE by a committed script.

WHY THIS EXISTS

Two defects with one shape, both found on 2026-08-05.

  1. `ML_NER_PHI_MODEL` existed in the code with a default and was named in no
     deployment file at all, while its four siblings were pinned in compose.
     Production silently tracked whatever the source default happened to be.
     That is the worst variable in the set to leave implicit: point PHI at a
     model whose label set has no medical-record class and it cannot emit a
     PHI entity at any confidence, so a HIPAA tenant gets a permanently,
     silently clean scan.

  2. `/models` is the named volume `hf_models`, and it was populated BY HAND
     -- twice -- with nothing in the repository recording that this had to
     happen. A fresh deployment came up with an empty volume,
     TRANSFORMERS_OFFLINE=1, and five failed models including prompt
     injection, while every health signal stayed green.

Both are the same failure: something the running service needs, known only to
whoever last touched the box. So this file asserts the three places a model
has to appear, and that they cannot drift apart:

  ml_models.MODEL_IDS   -- what the service loads          (source of truth)
  docker-compose.yml    -- what the deployment pins
  seed_models.py        -- what gets downloaded before offline mode applies

A sixth model added to MODEL_IDS fails this file until it is declared and
seedable. That is the point: the failure arrives at commit time rather than
as a silently degraded detector in production.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # services/detection
REPO = ROOT.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(REPO / "libs" / "cyberarmor-core"))

import detection_profile  # noqa: E402
import ml_models  # noqa: E402
import seed_models  # noqa: E402

COMPOSE = REPO / "infra" / "docker-compose.yml"
DOCKERFILE = ROOT / "Dockerfile"
SEED_SCRIPT = ROOT / "seed_models.py"
SEED_WRAPPER = REPO / "scripts" / "deployment" / "seed_hf_models.sh"


def _detection_service() -> dict:
    import yaml
    with COMPOSE.open() as fh:
        compose = yaml.safe_load(fh)
    return compose["services"]["detection"]


def _detection_environment() -> dict:
    env = _detection_service().get("environment", {})
    if isinstance(env, list):        # compose allows "KEY=value" list form
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return {k: str(v) for k, v in env.items()}


def _models_this_deployment_loads() -> dict:
    """The model set implied by the PROFILE the compose file selects.

    Not ``ml_models.MODEL_IDS``. That is the set for whatever profile this
    *test process* happens to be running, and comparing it against compose
    would be comparing two different profiles and calling the difference a
    drift -- which is how this file started failing the moment a profile
    system existed. The deployment declares a profile; the check must read it.
    """
    profile = _detection_environment().get("CYBERARMOR_DETECTION_PROFILE", "full")
    return detection_profile.models_for_profile(profile, ml_models.ALL_MODEL_IDS)


class TestEveryModelIsDeclaredInTheDeployment(unittest.TestCase):

    def test_every_model_id_is_pinned_in_compose(self):
        """Naming-agnostic: check the VALUE is pinned, however it is spelled."""
        declared = set(_detection_environment().values())
        for name, model_id in _models_this_deployment_loads().items():
            with self.subTest(model=name):
                self.assertIn(
                    model_id, declared,
                    f"{name} loads {model_id!r} but no environment entry in "
                    f"the detection service pins it. Production would follow "
                    f"whatever the source default happens to be, and a change "
                    f"to that default would ship silently.",
                )

    def test_every_model_has_its_conventional_env_var(self):
        """Right value under the wrong name is still a drift the above misses."""
        env = _detection_environment()
        for name, model_id in _models_this_deployment_loads().items():
            var = f"ML_{name.upper()}_MODEL"
            with self.subTest(model=name, var=var):
                self.assertIn(var, env, f"{var} is not declared in compose")
                self.assertEqual(
                    env[var], model_id,
                    f"compose pins {var}={env[var]!r} but the service loads "
                    f"{model_id!r}",
                )

    def test_compose_caches_models_where_the_volume_is_mounted(self):
        """A cache path that is not the mount point is not persisted.

        Models would re-download on every restart -- and with
        TRANSFORMERS_OFFLINE=1 they would simply fail to load instead.
        """
        svc = _detection_service()
        env = _detection_environment()
        mounts = {
            str(v).split(":")[1]
            for v in svc.get("volumes", []) if ":" in str(v)
        }
        for var in ("HF_HUB_CACHE", "TRANSFORMERS_CACHE", "HF_HOME"):
            with self.subTest(var=var):
                self.assertIn(var, env, f"{var} is not set for detection")
                self.assertIn(
                    env[var], mounts,
                    f"{var}={env[var]!r} is not a mounted volume path "
                    f"(mounted: {sorted(mounts)}), so the cache does not "
                    f"survive a restart",
                )

    def test_the_resolved_hub_cache_is_where_the_service_looks(self):
        """The defect this test was written against, as pure data.

        huggingface_hub resolves its cache as:
            HF_HUB_CACHE  ->  $HF_HOME/hub  ->  ~/.cache/huggingface/hub

        With only HF_HOME=/models set, that lands on /models/hub. The models
        are at /models. Measured on the box (transformers 5.14.1 /
        huggingface_hub 1.26.0), /models/hub did not exist at all, and
        TRANSFORMERS_CACHE had NO effect on the resolution -- it is dead in
        transformers 5.x.

        Nothing caught it because the service passes cache_dir explicitly, so
        it worked while every code path that did not pass one silently looked
        at an empty directory.
        """
        env = _detection_environment()
        if "HF_HUB_CACHE" in env:
            resolved = env["HF_HUB_CACHE"]
        elif "HF_HOME" in env:
            resolved = env["HF_HOME"].rstrip("/") + "/hub"
        else:
            resolved = "~/.cache/huggingface/hub"

        service_dir = env.get("TRANSFORMERS_CACHE") or env.get("HF_HOME")
        self.assertEqual(
            resolved, service_dir,
            f"huggingface_hub would resolve its cache to {resolved!r} but the "
            f"service reads models from {service_dir!r} "
            f"(ml_models.MODELS_CACHE_DIR). Any call that does not pass "
            f"cache_dir by hand -- including the seeder's verification step -- "
            f"looks in the wrong place and reports the models missing.",
        )


class TestTheSeederCoversEveryModel(unittest.TestCase):

    def test_the_seeder_reads_the_same_registry_the_service_does(self):
        """Not a copy of the list -- the list itself.

        A literal copy is how the PHI model got missed everywhere else: the
        second place to remember is the place nobody remembers.
        """
        self.assertIs(
            seed_models.MODEL_IDS, ml_models.MODEL_IDS,
            "seed_models must import MODEL_IDS from ml_models, not restate it",
        )

    def test_the_seeder_hardcodes_no_model_ids(self):
        """Belt and braces: catch a literal creeping back in beside the import."""
        src = SEED_SCRIPT.read_text()
        body = src.split('"""', 2)[-1]          # skip the module docstring
        for name, model_id in ml_models.MODEL_IDS.items():
            with self.subTest(model=name):
                self.assertNotIn(
                    f'"{model_id}"', body,
                    f"{model_id!r} is hardcoded in seed_models.py; it must "
                    f"come from MODEL_IDS so a new model cannot be forgotten",
                )

    def test_every_model_has_a_pipeline_accessor(self):
        """Verification loads by registry name, so every name needs one."""
        self.assertEqual(
            set(ml_models.PIPELINE_ACCESSORS), set(ml_models.ALL_MODEL_IDS),
            "PIPELINE_ACCESSORS and MODEL_IDS have drifted apart; a model "
            "with no accessor cannot be verified, and an accessor with no "
            "model is dead code",
        )
        for name, accessor in ml_models.PIPELINE_ACCESSORS.items():
            with self.subTest(model=name):
                self.assertTrue(
                    hasattr(ml_models._registry, accessor),
                    f"{name} maps to {accessor!r}, which the registry does "
                    f"not define",
                )

    def test_verification_loads_through_the_services_own_accessor(self):
        """Phase 2 must not build its own pipeline() call.

        A bespoke `pipeline(task, model=id)` is what produced the false
        failure: it resolved the cache from the environment while the service
        passes cache_dir explicitly, so all five models reported unloadable
        while the running service had all five loaded. A verifier that does
        not use the path it verifies is not a verifier.
        """
        src = SEED_SCRIPT.read_text()
        verify = src[src.index("_VERIFY_SNIPPET"):src.index("def main")]
        self.assertIn(
            "ml_models.load_pipeline", verify,
            "phase 2 must load via ml_models.load_pipeline, so it inherits "
            "the real task, aggregation strategy and cache_dir",
        )
        self.assertNotRegex(
            verify, r"from transformers import pipeline",
            "phase 2 must not construct its own transformers pipeline",
        )

    def test_the_download_filter_never_excludes_a_pytorch_weight_format(self):
        """The dangerous direction of the disk-saving filter.

        Excluding non-PyTorch artifacts saved ~10GB across five models (an
        unfiltered fetch put 14GB in the volume; bert-base-NER alone took
        2.1GB for a ~430MB model, because repos ship the same weights as
        PyTorch, TensorFlow, Flax and ONNX). But excluding a format the
        service DOES load produces a model that downloads "successfully" and
        cannot be loaded -- and some repos ship only `.bin`, others only
        `.safetensors`.
        """
        for pattern in seed_models.REQUIRED_ARTIFACT_HINTS:
            with self.subTest(pattern=pattern):
                self.assertNotIn(
                    pattern, seed_models.IGNORE_PATTERNS,
                    f"{pattern} is required to load a model and must never be "
                    f"in IGNORE_PATTERNS",
                )
        for pattern in seed_models.IGNORE_PATTERNS:
            with self.subTest(pattern=pattern):
                self.assertNotIn(
                    "safetensors", pattern,
                    "safetensors is the preferred PyTorch weight format",
                )
                self.assertNotEqual(
                    pattern, "*.bin",
                    "some repos ship only pytorch_model.bin",
                )

    def test_the_download_filter_is_actually_passed_to_the_hub(self):
        """A filter defined and not used saves nothing."""
        src = SEED_SCRIPT.read_text()
        fn = src[src.index("def download"):src.index("_VERIFY_SNIPPET")]
        self.assertIn(
            "ignore_patterns=IGNORE_PATTERNS", fn,
            "IGNORE_PATTERNS is defined but never handed to snapshot_download",
        )

    def test_the_seeder_refuses_to_run_with_offline_flags_set(self):
        """The whole point is downloading. Running offline would 'succeed'
        having downloaded nothing -- the exact shape this repo keeps hitting."""
        src = SEED_SCRIPT.read_text()
        self.assertIn("REFUSING TO RUN", src)
        self.assertIn("TRANSFORMERS_OFFLINE", src)

    def test_phase_two_forces_offline_back_on(self):
        """Verification must be a COLD offline load, not a re-read of the
        download that just happened."""
        src = SEED_SCRIPT.read_text()
        fn = src[src.index("def verify_offline"):src.index("def main")]
        self.assertIn('"TRANSFORMERS_OFFLINE"] = "1"', fn)
        self.assertIn('"HF_HUB_OFFLINE"] = "1"', fn)
        self.assertIn(
            "subprocess", fn,
            "a fresh process is required: transformers caches offline-ness "
            "and the model at import time",
        )

class TestTheExitCodeIsTheContract(unittest.TestCase):
    """The deploy script keys off this, so it is asserted by RUNNING main(),
    not by reading it.

    An earlier version of this test parsed the AST for "some non-zero return"
    and passed happily when `return 1` was changed to `return 0` -- the
    refusal path's `return 2` satisfied it. A test that passes for the wrong
    reason is worse than none, so both outcomes are now executed.
    """

    def setUp(self):
        # main() refuses outright if these are set, which would short-circuit
        # both cases below and prove nothing about the failure path.
        import os
        for var in ("TRANSFORMERS_OFFLINE", "HF_HUB_OFFLINE"):
            original = os.environ.pop(var, None)
            if original is not None:
                self.addCleanup(os.environ.__setitem__, var, original)

    def _run_main(self, download_ok: bool, verify_ok: bool) -> int:
        import io
        from contextlib import redirect_stdout
        orig_dl, orig_vf = seed_models.download, seed_models.verify_offline
        seed_models.download = lambda n, m: (download_ok, "simulated")
        seed_models.verify_offline = lambda n, m: (verify_ok, "simulated")
        try:
            with redirect_stdout(io.StringIO()):
                return seed_models.main()
        finally:
            seed_models.download, seed_models.verify_offline = orig_dl, orig_vf

    def test_a_model_that_cannot_load_offline_fails_the_run(self):
        self.assertNotEqual(
            self._run_main(download_ok=True, verify_ok=False), 0,
            "A model that downloaded but cannot be loaded with "
            "TRANSFORMERS_OFFLINE=1 is exactly the production failure this "
            "script exists to prevent. Exiting 0 here lets a deploy proceed "
            "onto an unusable cache.",
        )

    def test_a_failed_download_fails_the_run(self):
        self.assertNotEqual(
            self._run_main(download_ok=False, verify_ok=False), 0)

    def test_the_all_good_path_returns_zero(self):
        """Fail-closed must not become fail-always."""
        self.assertEqual(
            self._run_main(download_ok=True, verify_ok=True), 0)

    def test_offline_flags_make_it_refuse_rather_than_no_op(self):
        """Executed, not read: running offline would 'succeed' having
        downloaded nothing."""
        import os
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        self.addCleanup(os.environ.pop, "TRANSFORMERS_OFFLINE", None)
        self.assertEqual(self._run_main(download_ok=True, verify_ok=True), 2)


class TestTheSeederActuallyShipsInTheImage(unittest.TestCase):
    """Ground rule: production BUILDS images on the box, so the Dockerfile's
    COPY set IS the production filesystem. A seeding script that is not
    COPYed does not exist where it has to run."""

    def test_the_dockerfile_copies_the_seed_script(self):
        text = DOCKERFILE.read_text()
        self.assertRegex(
            text, r"COPY\s+services/detection/seed_models\.py",
            "seed_models.py is not in the Dockerfile COPY set, so it is "
            "absent from the built image and the wrapper cannot run it",
        )

    def test_the_wrapper_invokes_the_path_the_dockerfile_creates(self):
        """WORKDIR /app + COPY ... ./seed_models.py -> /app/seed_models.py."""
        self.assertTrue(SEED_WRAPPER.exists(), SEED_WRAPPER)
        self.assertIn("/app/seed_models.py", SEED_WRAPPER.read_text())

    def test_the_wrapper_never_takes_the_stack_down(self):
        """`docker compose down` is a full 80/443 outage on this deployment --
        COMPOSE_PROFILES=prod puts caddy in the default set."""
        text = SEED_WRAPPER.read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            self.assertNotRegex(
                stripped, r"docker\s+compose\b[^|]*\bdown\b",
                f"seeding must never bring the stack down: {stripped!r}",
            )

    def test_the_wrapper_overrides_offline_for_the_seeding_container_only(self):
        text = SEED_WRAPPER.read_text()
        self.assertRegex(text, r"run\s+--rm",
                         "seeding must use a throwaway container, not the "
                         "running detection service")
        self.assertIn("-e TRANSFORMERS_OFFLINE=0", text)


class TestTheDockerfileDoesNotContradictTheDeployment(unittest.TestCase):
    """The Dockerfile used to point at /tmp/cyberarmor_models, which nothing
    ever used -- it was overridden at runtime, so anyone reading the image
    for the cache location was sent to the wrong path."""

    def test_image_cache_dir_matches_the_compose_mount(self):
        text = DOCKERFILE.read_text()
        env = _detection_environment()
        for var in ("TRANSFORMERS_CACHE", "HF_HOME"):
            with self.subTest(var=var):
                m = re.search(rf"^ENV\s+{var}=(\S+)\s*$", text, re.MULTILINE)
                self.assertIsNotNone(m, f"{var} not set in the Dockerfile")
                self.assertEqual(
                    m.group(1), env[var],
                    f"Dockerfile sets {var}={m.group(1)!r} but the deployment "
                    f"uses {env[var]!r}; the image documents a path the "
                    f"service never reads",
                )


if __name__ == "__main__":
    unittest.main()
