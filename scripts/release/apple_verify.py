"""Native Apple trust check for a previously publisher-authenticated CLI binary."""

import os
import re
import subprocess

from authenticate import VerificationError


def verify(binary, team):
    # The expected team is supplied independently, never read from the archive.
    if not isinstance(team, str) or re.fullmatch(r"[A-Z0-9]{10}", team) is None:
        raise VerificationError("apple_identity_required")
    requirement = (
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
        f'and certificate leaf[subject.OU] = "{team}" and notarized'
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"HOME", "TMPDIR", "LANG", "LC_ALL"}
    }
    environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    try:
        result = subprocess.run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--all-architectures",
                "--test-requirement=" + requirement,
                str(binary),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45,
            env=environment,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise VerificationError("apple_verification_unavailable") from None
    if result.returncode != 0:
        raise VerificationError("apple_verification_failed")
