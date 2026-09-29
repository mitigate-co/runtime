"""Prepare only an ephemeral hosted signing runner's explicit release Keychain.

Never use this on a developer/customer host. Protected environment credentials
are consumed once, removed from child environment inheritance and never printed.
"""

import base64
import binascii
from contextlib import contextmanager
import os
from pathlib import Path
import platform
import re
import secrets
import tempfile

from apple_sign import invoke
from authenticate import VerificationError
from install import write_new
from install_contract import require

INPUTS = frozenset(
    {
        "APPLE_CERTIFICATE_P12_BASE64",
        "APPLE_CERTIFICATE_PASSWORD",
        "APPLE_NOTARY_KEY_P8_BASE64",
        "APPLE_NOTARY_KEY_ID",
        "APPLE_NOTARY_ISSUER_ID",
        "APPLE_SIGNING_IDENTITY",
        "APPLE_TEAM_ID",
    }
)


def consume(environment):
    values = {key: environment.pop(key, None) for key in INPUTS}
    require(
        all(isinstance(value, str) for value in values.values()),
        "apple_credentials_missing",
    )
    for key, pattern in (
        ("APPLE_SIGNING_IDENTITY", r"[0-9a-fA-F]{40}"),
        ("APPLE_TEAM_ID", r"[A-Z0-9]{10}"),
        ("APPLE_NOTARY_KEY_ID", r"[A-Z0-9]{10}"),
        (
            "APPLE_NOTARY_ISSUER_ID",
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}",
        ),
    ):
        require(re.fullmatch(pattern, values[key]), "apple_credentials_invalid")
    password = values["APPLE_CERTIFICATE_PASSWORD"]
    require(
        0 < len(password.encode("utf-8")) <= 4096 and "\x00" not in password,
        "apple_credentials_invalid",
    )
    for key, limit in (
        ("APPLE_CERTIFICATE_P12_BASE64", 1024 * 1024),
        ("APPLE_NOTARY_KEY_P8_BASE64", 64 * 1024),
    ):
        value = values[key]
        require(0 < len(value) <= (limit + 2) // 3 * 4, "apple_credentials_invalid")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise VerificationError("apple_credentials_invalid") from None
        require(0 < len(decoded) <= limit, "apple_credentials_invalid")
        values[key] = decoded
    return values


@contextmanager
def prepared_keychain(environment):
    """Yield public key references; destroy only this owned Keychain on exit.

    The caller has already checked workflow/source/environment prerequisites.
    No untrusted compilation or binary execution may occur in this job. Native
    security requires password argv briefly; same-user process inspection is
    outside this dedicated ephemeral-runner trust boundary.
    """
    require(
        platform.system() == "Darwin"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_JOB") == "sign",
        "apple_credentials_context",
    )
    values = consume(environment)
    with tempfile.TemporaryDirectory(prefix="mitigate-release-keys-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        keychain = root / "release.keychain-db"
        certificate, notary_key = root / "certificate.p12", root / "notary.p8"
        write_new(certificate, values["APPLE_CERTIFICATE_P12_BASE64"])
        write_new(notary_key, values["APPLE_NOTARY_KEY_P8_BASE64"])
        password = secrets.token_urlsafe(32)
        try:
            invoke(
                ["/usr/bin/security", "create-keychain", "-p", password, str(keychain)],
                30,
                "apple_keychain_setup",
            )
            invoke(
                [
                    "/usr/bin/security",
                    "set-keychain-settings",
                    "-lut",
                    "3600",
                    str(keychain),
                ],
                30,
                "apple_keychain_setup",
            )
            invoke(
                ["/usr/bin/security", "unlock-keychain", "-p", password, str(keychain)],
                30,
                "apple_keychain_setup",
            )
            invoke(
                [
                    "/usr/bin/security",
                    "import",
                    str(certificate),
                    "-k",
                    str(keychain),
                    "-P",
                    values["APPLE_CERTIFICATE_PASSWORD"],
                    "-T",
                    "/usr/bin/codesign",
                ],
                60,
                "apple_keychain_setup",
            )
            invoke(
                [
                    "/usr/bin/security",
                    "set-key-partition-list",
                    "-S",
                    "apple-tool:,apple:,codesign:",
                    "-s",
                    "-k",
                    password,
                    str(keychain),
                ],
                30,
                "apple_keychain_setup",
            )
            invoke(
                [
                    "/usr/bin/xcrun",
                    "notarytool",
                    "store-credentials",
                    "mitigate-release",
                    "--key",
                    str(notary_key),
                    "--key-id",
                    values["APPLE_NOTARY_KEY_ID"],
                    "--issuer",
                    values["APPLE_NOTARY_ISSUER_ID"],
                    "--keychain",
                    str(keychain),
                ],
                120,
                "apple_notary_credentials",
            )
            # Native stores now own the keys. Remove import files before signing.
            certificate.unlink()
            notary_key.unlink()
            yield {
                "identity": values["APPLE_SIGNING_IDENTITY"],
                "team": values["APPLE_TEAM_ID"],
                "keychain": keychain,
                "profile": "mitigate-release",
            }
        finally:
            # A failed create/import may still leave native state. Cleanup
            # failure remains failure even if archive bytes were completed.
            invoke(
                ["/usr/bin/security", "delete-keychain", str(keychain)],
                30,
                "apple_keychain_cleanup",
            )
