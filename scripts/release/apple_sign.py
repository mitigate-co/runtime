"""Sign a private build copy using an existing runner Keychain, then notarize it.

No key import, password arguments, credential discovery or customer state access.
The caller owns the temporary directory and the separately selected Apple team.
"""

import json
import os
import platform
import re
import subprocess

import apple_verify
from authenticate import VerificationError, regular
from install_contract import MAX_FILE, closed_object, require
from package import archive_bytes


def signing_inputs(identity, team, keychain, profile):
    require(platform.system() == "Darwin", "apple_signing_platform")
    require(
        isinstance(identity, str) and re.fullmatch(r"[0-9A-Fa-f]{40}", identity),
        "apple_signing_identity",
    )
    require(
        isinstance(team, str) and re.fullmatch(r"[A-Z0-9]{10}", team),
        "apple_identity_required",
    )
    require(
        isinstance(profile, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", profile),
        "apple_notary_profile",
    )
    try:
        require(keychain.is_absolute() and regular(keychain.lstat()), "apple_keychain")
    except OSError:
        raise VerificationError("apple_keychain") from None


def invoke(command, timeout, category, output=False):
    # Fixed system tools only; never inherit workload secrets, debug hooks or an
    # alternate developer toolchain. Keychain ACLs must permit noninteractive use.
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"HOME", "TMPDIR", "LANG", "LC_ALL"}
    }
    environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    try:
        result = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if output else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise VerificationError(category) from None
    require(result.returncode == 0, category)
    if output:
        require(0 < len(result.stdout) <= 16 * 1024, category)
        return result.stdout
    return None


def sign_and_notarize(binary, identity, team, keychain, profile):
    signing_inputs(identity, team, keychain, profile)
    invoke(
        [
            "/usr/bin/codesign",
            "--force",  # Replace the compiler's ad-hoc Apple Silicon signature.
            "--sign",
            identity,
            "--keychain",
            str(keychain),
            "--identifier",
            "co.mitigate.runtime",
            "--options",
            "runtime",
            "--timestamp",
            str(binary),
        ],
        120,
        "apple_signing_failed",
    )
    # Submit only this binary, never a workspace, credential file or arbitrary
    # directory. Raw CLI executables cannot carry a stapled notarization ticket.
    info = binary.lstat()
    require(regular(info) and 0 < info.st_size <= MAX_FILE, "apple_signed_binary")
    submission = binary.parent / "notary-submission.zip"
    archive_bytes(submission, {"mitigate": (binary.read_bytes(), True)})
    response = invoke(
        [
            "/usr/bin/xcrun",
            "notarytool",
            "submit",
            str(submission),
            "--keychain-profile",
            profile,
            "--keychain",
            str(keychain),
            "--wait",
            "--timeout",
            "15m",
            "--output-format",
            "json",
        ],
        16 * 60,
        "apple_notarization_failed",
        output=True,
    )
    try:
        result = json.loads(response.decode("utf-8"), object_pairs_hook=closed_object)
    except (ValueError, RecursionError, VerificationError):
        raise VerificationError("apple_notarization_failed") from None
    require(
        isinstance(result, dict)
        and result.get("status") == "Accepted"
        and isinstance(result.get("id"), str)
        and re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", result["id"]
        ),
        "apple_notarization_failed",
    )
    # Acceptance alone is insufficient: verify the resulting code, Developer ID
    # chain, independently selected team and Apple's ticket with native tools.
    apple_verify.verify(binary, team)
