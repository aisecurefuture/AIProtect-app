"""No CyberArmor name reaches a consumer's machine.

WHY A TEST AND NOT A CODE REVIEW
================================
`apps/agent/` is being ported module by module from `agents/endpoint-agent/`
in CyberArmorAi, which is ~49k lines with the B2B product name written into
string literals throughout: service names, LaunchDaemon labels, bundle ids,
install and log paths, notification titles, user-agent strings.

Porting renames most of them. The ones it misses are invisible in review --
`/var/log/cyberarmor` inside an f-string in an error path, a notification
title in a branch that only fires on failure -- and they surface on a paying
consumer's Mac, in a product they bought called AIProtect. That is a support
ticket at best and, for a security product, a "why is this talking to a
company I have never heard of" at worst.

So the constraint is mechanical: identifiers come from `branding.py`, and any
literal that slips back in fails here.

WHAT IS DELIBERATELY ALLOWED
============================
1. `PUBLISHER_NAME` and `PRODUCT_FULL_NAME` in branding.py -- the code-signing
   publisher IS CyberArmor.AI, and saying so on the installer is the whole
   point of the two-name split. See branding.py.
2. Provenance comments naming the fork point, so a reader can find the
   original. `apps/extension/src/ai-services.js` already does this.
3. `cyberarmor_core` imports -- the shared library keeps its name by decision
   on 2026-08-16. It is a package name, never user-visible.
4. Markdown. Developer documentation in this directory does not ship to a
   customer's machine, and the port plan in README.md has to be able to name
   the codebase it is porting FROM. Scanning it would make the guard fail on
   its own instructions. Docstrings and UI strings inside .py ARE scanned,
   because those can be rendered -- an About box built from a module docstring
   is exactly the leak this test is for.

Everything else is a defect.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent          # apps/agent

#: Case-insensitive: "CyberArmor", "cyberarmor", "CYBERARMOR".
NAME = re.compile(r"cyberarmor", re.IGNORECASE)

#: The shared library keeps its name -- a package import, not a brand.
ALLOWED_LIBRARY = re.compile(r"cyberarmor[-_]core", re.IGNORECASE)

#: A comment line. Provenance notes are allowed; a comment cannot reach a user.
COMMENT = re.compile(r"^\s*(#|//|\*|/\*|\"\"\"|''')")


def _source_files() -> list[Path]:
    out: list[Path] = []
    for path in AGENT_DIR.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {"__pycache__", "build", "dist", ".pytest_cache"}
               for part in path.parts):
            continue
        # No ".md" -- see allowance 4 in the module docstring. Every other
        # extension here is something that gets installed onto a machine.
        if path.suffix in {".py", ".sh", ".plist", ".xml", ".json",
                           ".service", ".txt", ".cfg", ".ini"}:
            out.append(path)
    return out


class NoCyberArmorIdentifiersReachAConsumer(unittest.TestCase):
    def test_no_source_file_carries_the_b2b_product_name(self):
        offenders: list[str] = []

        for path in _source_files():
            rel = path.relative_to(AGENT_DIR)
            # branding.py states the publisher on purpose.
            if rel.as_posix() == "branding.py":
                continue
            # This test file names it in order to forbid it.
            if rel.as_posix().startswith("tests/test_the_agent_carries_no"):
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

            for lineno, line in enumerate(text.splitlines(), start=1):
                if not NAME.search(line):
                    continue
                if ALLOWED_LIBRARY.search(line):
                    continue          # cyberarmor_core -- allowed
                if COMMENT.match(line):
                    continue          # provenance note -- allowed
                offenders.append(f"{rel}:{lineno}: {line.strip()}")

        self.assertEqual(
            offenders, [],
            "CyberArmor identifiers found in shipped agent code. Import the "
            "name from branding.py instead:\n  " + "\n  ".join(offenders),
        )

    def test_branding_declares_a_distinct_identifier_for_every_os_hook(self):
        """A shared identifier is a collision, not a saving.

        The daemon label and the menu-bar app's bundle id must differ: macOS
        keys notification permission to the bundle id, and a LaunchDaemon and
        a UI agent sharing one identifier is a launchctl conflict.
        """
        import sys
        sys.path.insert(0, str(AGENT_DIR))
        import branding

        ids = [branding.BUNDLE_ID, branding.STATUS_BUNDLE_ID, branding.SERVICE_NAME]
        self.assertEqual(len(ids), len(set(ids)), "identifiers collide")
        for identifier in (branding.BUNDLE_ID, branding.STATUS_BUNDLE_ID):
            self.assertTrue(
                identifier.startswith("app.aiprotect."),
                f"{identifier} is not under the aiprotect.app reverse-DNS prefix",
            )

    def test_no_path_lands_outside_an_aiprotect_directory(self):
        import sys
        sys.path.insert(0, str(AGENT_DIR))
        import branding

        for system in ("Darwin", "Linux"):
            for fn in (branding.install_dir, branding.config_dir, branding.log_dir):
                path = fn(system)
                self.assertIn(
                    "aiprotect", str(path).lower(),
                    f"{fn.__name__}({system}) -> {path} is not an AIProtect path",
                )

    def test_the_display_name_is_not_hardcoded_to_one_platform(self):
        """The bug this guards: one constant reading "AIProtect for Mac",
        imported everywhere, shipped on Windows."""
        import sys
        sys.path.insert(0, str(AGENT_DIR))
        import branding

        self.assertIn("Mac", branding.agent_display_name("Darwin"))
        self.assertIn("Windows", branding.agent_display_name("Windows"))
        self.assertIn("Linux", branding.agent_display_name("Linux"))
        self.assertNotIn("Darwin", branding.agent_display_name("Darwin"))


if __name__ == "__main__":
    unittest.main()
