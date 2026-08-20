"""Every user-visible name and OS-level identifier the desktop agent uses.

WHY THIS FILE EXISTS
====================
The agent is a fork of `agents/endpoint-agent/` in CyberArmorAi, where the
product name is baked into ~49k lines as string literals: service names,
LaunchDaemon labels, bundle identifiers, install paths, log paths, notification
titles. A fork that copies those and renames them by hand renames MOST of them,
and the ones it misses surface as `/var/log/cyberarmor` on a consumer's Mac or
a notification from "CyberArmor" on a product they bought called AIProtect.

So the names live here once, the ported modules import them, and
`tests/test_the_agent_carries_no_cyberarmor_identifiers.py` fails the build if
a literal slips back in.

THE TWO-NAME BRANDING, AND WHERE EACH IS USED
=============================================
`PRODUCT_NAME` ("AIProtect") is the in-product name: menu-bar title, tray
tooltip, notification sender, status window. It is short, it is repeated
constantly, and it is what the customer bought.

`PRODUCT_FULL_NAME` ("AIProtect.app by CyberArmor.AI") is for the surfaces
where a stranger is deciding whether to trust an installer: the installer
welcome pane, the About box, the docs footer, the store listing.

That split is not decoration. Code signing forces the question anyway — the
Authenticode publisher string on Windows and the Developer ID on macOS are the
enrolled ORGANISATION, which is CyberArmor. An installer whose Gatekeeper
prompt says "CyberArmor" for a product the customer knows as "AIProtect" reads
as a supply-chain problem to exactly the security-conscious customer this
product is sold to. Saying it up front costs nothing and removes the surprise.

IDENTIFIERS ARE PERMANENT -- GET THEM RIGHT NOW
===============================================
`STATUS_BUNDLE_ID` is the one to be careful with. macOS keys the user's
notification permission to the bundle identifier, so changing it after any
install exists silently resets that permission for every existing user and the
agent goes quiet without erroring. There are zero installs today, so this is
the last free moment to choose it. The same is true of `SERVICE_NAME` for
systemd and NSSM: renaming a unit later orphans the old one, still enabled,
still pointing at a path that no longer exists.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Names shown to a person
# ---------------------------------------------------------------------------

#: In-product. Menu bar, tray, notifications, status window.
PRODUCT_NAME = "AIProtect"

#: Trust surfaces. Installer welcome, About box, store listing, docs footer.
#: Pairs the product with the organisation that signs it -- see the module
#: docstring for why that is stated rather than hidden.
PRODUCT_FULL_NAME = "AIProtect.app by CyberArmor.AI"

#: The legal entity on the code-signing certificate. Not a marketing string:
#: this is what Gatekeeper and SmartScreen will display, whatever we prefer.
PUBLISHER_NAME = "CyberArmor.AI"

SUPPORT_URL = "https://support.aiprotect.app"
PRIVACY_URL = "https://aiprotect.app/privacy"
ACCOUNT_URL = "https://app.aiprotect.app"
API_BASE_URL = "https://api.aiprotect.app"

# ---------------------------------------------------------------------------
# OS-level identifiers -- permanent once anything is installed
# ---------------------------------------------------------------------------

#: Reverse-DNS of aiprotect.app. Reads oddly and is correct.
BUNDLE_ID = "app.aiprotect.agent"

#: Keyed to the user's notification permission by macOS. Never change this
#: after the first install without a migration nobody has written.
STATUS_BUNDLE_ID = "app.aiprotect.statusui"

#: systemd unit / NSSM service / scheduled task name.
SERVICE_NAME = "aiprotect-agent"

#: The macOS menu-bar app bundle. `.app` is appended by the build.
STATUS_APP_NAME = "AIProtect Status"
STATUS_APP_EXECUTABLE = "AIProtectStatus"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

INSTALL_DIRS = {
    "Darwin": Path("/usr/local/aiprotect"),
    "Linux": Path("/opt/aiprotect"),
}

CONFIG_DIRS = {
    "Darwin": Path("/etc/aiprotect"),
    "Linux": Path("/etc/aiprotect"),
}

LOG_DIRS = {
    "Darwin": Path("/var/log/aiprotect"),
    "Linux": Path("/var/log/aiprotect"),
}


def agent_display_name(system: str) -> str:
    """"AIProtect for Mac" / "for Windows" / "for Linux".

    Consumers say "Mac", not "Darwin". The platform string is translated here
    rather than shown raw, which is how `Darwin` ends up in a UI.
    """
    return {
        "Darwin": f"{PRODUCT_NAME} for Mac",
        "Windows": f"{PRODUCT_NAME} for Windows",
        "Linux": f"{PRODUCT_NAME} for Linux",
    }.get(system, f"{PRODUCT_NAME} for {system}")


def install_dir(system: str) -> Path:
    return INSTALL_DIRS.get(system, Path("/opt/aiprotect"))


def config_dir(system: str) -> Path:
    return CONFIG_DIRS.get(system, Path("/etc/aiprotect"))


def log_dir(system: str) -> Path:
    return LOG_DIRS.get(system, Path("/var/log/aiprotect"))
