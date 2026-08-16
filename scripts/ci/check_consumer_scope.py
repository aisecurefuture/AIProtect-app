#!/usr/bin/env python3
"""CI guard: the consumer product must not grow a tenant.

AIProtect has accounts, families and devices. It does not have tenants, and it
must never acquire one by accident -- a `tenant_id` threaded through the API is
how a single-user product slowly turns back into the B2B one it was forked from,
one reasonable-looking commit at a time.

SCOPE: `apps/**` only.

`services/` and `libs/` were forked with their inherited tenant plumbing still
in place (cosmetic in detection -- echoed, never authorised against). Stripping
it is on the port-back list in FORK-PROVENANCE.md. Guarding those directories
today would mean starting red, and a guard that starts red gets disabled.
`apps/` is new code, so it can be held to the rule from the first line.

Usage:
    python3 scripts/ci/check_consumer_scope.py
    python3 scripts/ci/check_consumer_scope.py --self-test

Exit 0 = clean. Exit 1 = at least one violation.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

#: Spellings that all mean the same thing. Checking one form is how the
#: sibling guard in the B2B repo let `from customer_portal.app import thing`
#: through -- a python module cannot contain a hyphen.
FORBIDDEN = re.compile(
    r"\b(tenant[_-]?id|tenantId|TENANT_ID|x-tenant-id)\b", re.IGNORECASE
)

SCANNED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".swift", ".kt"}

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", "__pycache__",
    "venv", ".venv", "coverage", ".turbo", "Pods", "DerivedData",
}

GUARDED_ROOT = "apps"


def strip_comment(line: str) -> str:
    """Drop the obvious comment tail.

    Prose may name the thing it is refusing -- this file does, the READMEs do.
    Only a line that would put a tenant into the running product counts.
    """
    for marker in ("#", "//"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    return line


def code_lines(text: str, suffix: str):
    """Yield (line_no, code) skipping docstrings and block comments.

    Added after the guard flagged the module docstring in apps/api/models.py --
    a paragraph explaining WHY this product has no tenant. Forcing that
    explanation to be reworded to appease the checker would make the codebase
    worse to read, and a guard that does that is a guard someone eventually
    disables. It should catch a tenant entering the running product, not a
    sentence about not having one.
    """
    in_doc = None          # the triple-quote delimiter we are inside, if any
    in_block = False       # inside a /* ... */ comment
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw

        if suffix == ".py":
            rest = line
            while rest:
                if in_doc is None:
                    idx3 = min(
                        (i for i in (rest.find('"""'), rest.find("'''")) if i != -1),
                        default=-1,
                    )
                    if idx3 == -1:
                        break
                    in_doc = rest[idx3:idx3 + 3]
                    line = line[: line.index(in_doc)] if in_doc in line else ""
                    rest = rest[idx3 + 3:]
                    if in_doc in rest:                 # opened and closed here
                        rest = rest[rest.index(in_doc) + 3:]
                        in_doc = None
                        continue
                    break
                else:
                    if in_doc in rest:
                        rest = rest[rest.index(in_doc) + 3:]
                        in_doc = None
                        line = rest
                        continue
                    line = ""
                    break
            if in_doc is not None:
                line = ""
        else:
            if in_block:
                if "*/" in line:
                    line = line[line.index("*/") + 2:]
                    in_block = False
                else:
                    line = ""
            if "/*" in line:
                head = line[: line.index("/*")]
                if "*/" in line[line.index("/*"):]:
                    tail = line[line.index("/*"):]
                    line = head + tail[tail.index("*/") + 2:]
                else:
                    line = head
                    in_block = True

        yield n, strip_comment(line)


def scan(root: Path) -> list[tuple[Path, int, str]]:
    target = root / GUARDED_ROOT
    if not target.is_dir():
        return []
    violations: list[tuple[Path, int, str]] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file() or path.suffix not in SCANNED_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        raw_lines = text.splitlines()
        for n, code in code_lines(text, path.suffix):
            raw = raw_lines[n - 1] if n <= len(raw_lines) else ""
            if FORBIDDEN.search(code):
                try:
                    rel = path.relative_to(root)
                except ValueError:
                    rel = path
                violations.append((rel, n, raw.strip()[:100]))
    return violations


_SELF_TEST_CASES = (
    ("py_snake.py", "def get(tenant_id: str):\n    return tenant_id\n", True),
    ("ts_camel.ts", "const tenantId = req.headers['x-tenant-id'];\n", True),
    ("py_header.py", 'h = {"x-tenant-id": t}\n', True),
    ("ok_comment.py", "# deliberately no tenant_id in this product\n", False),
    ("ok_device.py", "device_id = enroll()\naccount_id = session.user\n", False),
    ("ok_family.py", "family_id = plan.owner\n", False),
    # Prose explaining why there is no tenant must not be flagged -- a guard
    # that forces worse documentation is one somebody eventually disables.
    ("ok_docstring.py", '"""This product has no tenant_id, by design."""\n', False),
    ("ok_multiline_doc.py",
     '"""Header.\n\nWe never store a tenant_id here.\n"""\nx = 1\n', False),
    # ...but code AFTER a docstring is still checked.
    ("bad_after_doc.py", '"""Doc about tenants."""\ntenant_id = req.q\n', True),
)


def self_test() -> int:
    """Prove the guard can still fail.

    A boundary check that passes because it inspects nothing reports OK for
    work it never did -- the same defect class the product is built to refuse.
    """
    import shutil
    import tempfile

    print("consumer-scope guard: self-test")
    failures = 0
    tmp_root = Path(tempfile.mkdtemp())
    try:
        probe = tmp_root / GUARDED_ROOT / "_selftest"
        probe.mkdir(parents=True)
        for name, body, should_flag in _SELF_TEST_CASES:
            path = probe / name
            path.write_text(body, encoding="utf-8")
            flagged = bool(scan(tmp_root))
            path.unlink()
            ok = flagged == should_flag
            failures += not ok
            print(f"  [{'PASS' if ok else 'FAIL'}] "
                  f"{'flags' if should_flag else 'ignores'} {name}")
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    if failures:
        print(f"\nself-test FAILED: {failures} case(s). The guard is not trustworthy.")
        return 1
    print(f"self-test OK: {len(_SELF_TEST_CASES)}/{len(_SELF_TEST_CASES)} cases.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    root = Path(args.root).resolve()
    violations = scan(root)
    if not violations:
        print(f"consumer-scope check: OK (no tenant_id in {GUARDED_ROOT}/**)")
        return 0

    print(f"consumer-scope check: {len(violations)} VIOLATION(S)\n")
    for rel, line_no, snippet in violations:
        print(f"  {rel}:{line_no}\n    {snippet}\n")
    print("AIProtect has accounts, families and devices -- not tenants.")
    print("Use the enrolled device id for attribution (agent_id) and the")
    print("account id for ownership. See README.md, rule 1.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
