"""Finding data files that ship beside the code, in either layout.

TWO LAYOUTS, AND CODE THAT ONLY KNEW ONE
========================================
In the repository this service lives at `apps/api/`, with its data files two
levels up:

    <repo>/apps/api/entitlements.py
    <repo>/shared/tiers.json

In the image, `apps/api/*.py` is flattened into `/app` and the data files are
copied beside it:

    /app/entitlements.py
    /app/shared/tiers.json

`entitlements.py` and `presets.py` both computed their paths as
`Path(__file__).resolve().parents[2]`, which is correct in the repository and
raises `IndexError` in the image -- `/app/entitlements.py` simply does not
have three parents. The container could not import its own modules, so the
API had never started in a container even once. Every test passed throughout,
because tests run from the repository.

So paths are resolved by SEARCHING for the resource rather than by counting
directories. Counting encodes one layout; searching works in both, and fails
with a message naming what it looked for rather than an IndexError from
pathlib.
"""

from __future__ import annotations

import os
from pathlib import Path

#: How far up to look. Enough for the repo layout (two), with room to spare;
#: bounded so a missing file cannot walk to the filesystem root.
_MAX_DEPTH = 5


def find_resource(*parts: str, env_var: str | None = None) -> Path:
    """Locate a data file that ships with this service.

    Searches the directory containing this module and each of its parents.
    `env_var`, when given and set, wins outright -- an operator relocating a
    file should not have to satisfy a search.

    Raises FileNotFoundError naming every place that was tried, because the
    failure mode this replaced was an IndexError from pathlib that said
    nothing about which file was missing.
    """
    if env_var:
        override = os.getenv(env_var, "").strip()
        if override:
            candidate = Path(override)
            if candidate.is_file():
                return candidate
            raise FileNotFoundError(
                f"{env_var}={override!r} does not name a readable file"
            )

    here = Path(__file__).resolve().parent
    tried = []
    for depth, base in enumerate([here, *here.parents]):
        if depth > _MAX_DEPTH:
            break
        candidate = base.joinpath(*parts)
        tried.append(str(candidate))
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        f"could not find {'/'.join(parts)}. Tried:\n  " + "\n  ".join(tried)
    )


def find_directory(*parts: str, env_var: str | None = None) -> Path:
    """As `find_resource`, for a directory (e.g. libs/policy-engine)."""
    if env_var:
        override = os.getenv(env_var, "").strip()
        if override:
            candidate = Path(override)
            if candidate.is_dir():
                return candidate
            raise NotADirectoryError(
                f"{env_var}={override!r} does not name a readable directory"
            )

    here = Path(__file__).resolve().parent
    tried = []
    for depth, base in enumerate([here, *here.parents]):
        if depth > _MAX_DEPTH:
            break
        candidate = base.joinpath(*parts)
        tried.append(str(candidate))
        if candidate.is_dir():
            return candidate

    raise FileNotFoundError(
        f"could not find directory {'/'.join(parts)}. Tried:\n  " + "\n  ".join(tried)
    )
