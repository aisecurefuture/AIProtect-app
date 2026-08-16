"""Repo-root test bootstrap: make a local run resemble the deployed artifact.

WHY THIS FILE EXISTS
--------------------
``libs/cyberarmor-core`` is a real runtime dependency of most services -- every
one of their Dockerfiles ``COPY``s it in, and ``scripts/security/
check_deployed_artifact_imports.py`` asserts they can import it from the image.
It is not pip-installed on a dev machine, so a local test run has no path to it.

Today each test file that needs it repeats::

    sys.path.insert(0, str(REPO_ROOT / "libs" / "cyberarmor-core"))

That works for the files that remember. ``services/agent-identity/tests/
test_compat.py`` does not, so it raised ``ModuleNotFoundError: No module named
'cyberarmor_core'`` at collection -- which, before ``pytest.ini`` set
``--import-mode=importlib``, ABORTED the entire repo-wide run. One suite
forgetting one line stopped every other suite in the repository from running,
and reported it as a collection error rather than a failure.

Setting it once here means the path is a property of the repository rather than
something each new test file has to remember, and a forgotten line can no
longer take the whole harness down.

The per-file inserts are deliberately left in place. They become no-ops once
this has run, and they keep each file runnable on its own -- the same reasoning
``services/policy/tests/conftest.py`` records for its ``os.environ.setdefault``
calls.

WHAT THIS FILE MUST NOT BECOME
------------------------------
A place to make failing tests pass. It sets import paths only. Anything that
changes what a test MEASURES belongs in that suite's own conftest, where the
person reading the test can see it.
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent

#: Source roots that tests import from and that are not installed locally.
#:
#: libs/cyberarmor-core is shipped into every service image by its Dockerfile.
#:
#: A conftest.py inside sdks/python/tests would have been the tidier home, but
#: that directory has an __init__.py, so its conftest resolves to the module
#: name `tests.conftest` and collides with services/ai-router/tests, which is
#: also a package. Two `tests` packages, one name. This is the placement that
#: does not have that problem.
_SOURCE_ROOTS = (
    _REPO_ROOT / "libs" / "cyberarmor-core",
    # Not a package: the policy engine modules do `import opa_client`,
    # so the DIRECTORY has to be on the path.
    _REPO_ROOT / "libs" / "policy-engine",
)

for _root in _SOURCE_ROOTS:
    _path = str(_root)
    if _root.is_dir() and _path not in sys.path:
        sys.path.insert(0, _path)


# --- import the real cyberarmor_core BEFORE any test can stub it -------------
#
# Eighteen test files carry a fallback like::
#
#     if "cyberarmor_core" not in sys.modules:
#         sys.modules["cyberarmor_core"] = types.ModuleType("cyberarmor_core")
#
# They exist because libs/cyberarmor-core was not importable on a dev machine,
# and each was right to add one -- skipping the module instead would have meant
# the assertions silently did not run, which several of their docstrings call
# out by name.
#
# But `not in sys.modules` asks "has it been imported yet", not "can it be".
# The real package is importable as soon as the path above is set; it simply
# has not been imported at that moment, so the stub wins the name for the whole
# process. The stub is a plain ModuleType with no __path__, so it is not a
# package -- and every later suite that needs a SUBMODULE gets:
#
#     ModuleNotFoundError: No module named 'cyberarmor_core.evidence';
#     'cyberarmor_core' is not a package
#
# Measured 2026-07-31: `pytest services/policy/tests services/control-plane/tests`
# aborted collection on two control-plane modules for exactly this, while each
# suite passed alone. Thirteen of the eighteen stubbers are in services/policy,
# which is why that suite appeared to "break" control-plane.
#
# Importing the real package here makes all eighteen guards no-ops without
# touching them, and keeps them working as intended if the package is ever
# genuinely unavailable.
try:
    import cyberarmor_core  # noqa: F401
    import cyberarmor_core.crypto  # noqa: F401
except Exception:
    # Genuinely unavailable. Leave sys.modules alone so the per-file stubs do
    # their job -- that is what they are for.
    pass


# --- keep every suite importing ITS OWN main/models --------------------------
#
# Every service in this repo has top-level modules named `main`, `models`, `db`
# and so on, and every suite imports them by bare name after a sys.path.insert.
# sys.modules is global and process-wide, so in a repo-wide run the FIRST suite
# to import a name wins it and every later suite silently receives THAT
# service's module. Measured 2026-07-31:
#
#   services/control-plane/tests/test_corpus_manifest_api.py
#   E  ImportError: cannot import name 'ApiKey' from 'models'
#      (/.../services/policy/models.py)
#
#   services/url-trust-gate/tests/test_extractors.py
#      ...ran against /.../services/siem-connector/main.py
#
# An ImportError is the loud outcome and the lucky one. The quiet outcome is a
# suite that finds a same-named symbol in the wrong service's module (`app`,
# `health`, `ApiKey`, `_verify_api_key` all exist in several), asserts against
# it, and PASSES, having proven nothing about the service it names. That is the
# defect class this repo tracks, living in the harness meant to catch it.
#
# WHY HERE AND NOT IN EACH SUITE. The first attempt was a conftest.py per
# service tests/ directory. It cannot cover everything: services/ai-router/tests
# and services/url-trust-gate/tests both contain an __init__.py, and neither
# parent can be a package (a hyphen is not a valid Python identifier), so both
# of their conftests resolve to the module name `tests.conftest` and pytest
# refuses the second with "Plugin already registered". url-trust-gate was
# therefore the one suite that could not have the guard -- and it is one of the
# two that provably needed it. Deriving the service directory from the test's
# own path needs no per-directory file at all.
#
# WHY runtest_setup AND NOT COLLECTION. Several suites import inside a fixture
# or a test body rather than at module scope -- test_corpus_manifest_api.py:73
# does `from models import ApiKey` inside a static method -- which runs long
# after collection, by which time another service's copy is cached and its
# directory sits ahead on sys.path. This hook is the only point that reliably
# precedes a deferred import.

#: Top-level module names that more than one service defines.
_SERVICE_LOCAL_MODULES = ("main", "models", "db", "schemas", "auth", "deps")

#: Every service-local module ever imported, keyed by (service_dir, module_name).
#:
#: EVICTION ALONE IS NOT ENOUGH, and the half-fix is worse than it looks.
#:
#: The loop below used to only DELETE the wrong service's module. Nothing put
#: the right one back, so a suite whose tests were collected early and run late
#: reached its own test body with its module simply ABSENT from sys.modules:
#:
#:     collect audit    -> imports services/audit/main.py  as `main`  (object A)
#:     collect policy   -> evicts A, imports services/policy/main.py  (object P)
#:     RUN audit's test -> evicts P ... and `main` is now gone entirely
#:
#: Absent is not neutral. The next `import main` re-executes the same FILE into
#: a SECOND module object (B), and A and B do not share globals. Measured
#: 2026-08-01 in services/audit/tests/test_batch_chain.py:
#:
#:     with patch("main._latest_tenant_event"):      # imports B, patches B
#:         _get_batch_previous_for_tenant(...)       # bound to A at collection
#:
#: The patch took effect on a module object nothing under test was using, so
#: the REAL `_latest_tenant_event` ran and issued a query against a plain
#: `object()`. That test passes when run alone and fails only in a repo-wide
#: run, which is why it sat on the known-failures list as "pre-existing".
#:
#: A failed patch is the loud outcome. The quiet one is a deferred
#: `from models import Base` (policy and control-plane both do this) picking up
#: a FRESH declarative base: `Base.metadata.create_all(engine)` then creates
#: tables for a registry the application's own models were never added to, and
#: the suite tests an empty parallel schema while reporting green.
#:
#: Caching and restoring makes module identity per service STABLE for the whole
#: run: a given service's `main` is the same object on every one of its tests,
#: whatever ran in between. That is the property the eviction was reaching for.
_SERVICE_MODULE_CACHE: dict[tuple[str, str], object] = {}


def _service_dir_for(test_file: Path) -> Path | None:
    """The service root owning a test file: the parent of its `tests/` dir.

    services/policy/tests/test_x.py      -> services/policy
    agents/endpoint-agent/tests/test_x.py -> agents/endpoint-agent
    Returns None for a test that does not live under a `tests/` directory,
    which is left completely alone.
    """
    for parent in test_file.parents:
        if parent.name == "tests":
            return parent.parent
    return None


def _prime_for(test_file: Path) -> None:
    """Give the owning service sys.path priority and ITS OWN service-local modules.

    Three states per module name, and the third is the one that was missing:

    * already this service's  -> cache it, leave it alone (no work, keeps state)
    * another service's       -> cache it under ITS owner, then evict
    * absent                  -> restore this service's copy if we have ever
                                 imported it, so the SAME module object is used
                                 on every one of this suite's tests
    """
    service_dir = _service_dir_for(test_file)
    if service_dir is None:
        return
    here = str(service_dir)

    # Move to the front rather than appending, so sys.path does not grow by one
    # entry per test across a long run.
    while here in sys.path:
        sys.path.remove(here)
    sys.path.insert(0, here)

    for name in _SERVICE_LOCAL_MODULES:
        mod = sys.modules.get(name)
        if mod is not None:
            origin = getattr(mod, "__file__", "") or ""
            if not origin:
                # No file to attribute it to (namespace package, C extension,
                # a stub someone installed). Not ours to reason about.
                continue
            owner = str(Path(origin).parent)
            # Cache under the service that owns it, so evicting it here is not
            # destructive -- whoever owns it gets this exact object back.
            _SERVICE_MODULE_CACHE[(owner, name)] = mod
            if owner == here:
                continue
            del sys.modules[name]

        cached = _SERVICE_MODULE_CACHE.get((here, name))
        if cached is not None:
            sys.modules[name] = cached


def pytest_collectstart(collector):
    """Before a test MODULE is imported -- covers module-scope `import main`."""
    path = getattr(collector, "path", None)
    if path is not None:
        _prime_for(Path(str(path)))


def pytest_runtest_setup(item):
    """Before each test RUNS -- covers imports deferred into a fixture or body.

    Both hooks are needed and neither is redundant. Collection-time priming
    alone misses `from models import ApiKey` inside a static method; run-time
    priming alone misses a module-scope `import main`, which happens while the
    module is being collected and never reaches this hook at all.
    """
    _prime_for(Path(str(item.path)))
