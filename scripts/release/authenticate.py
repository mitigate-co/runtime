"""Verify release-file publisher identity without installing or executing it.

GitHub CLI owns Sigstore signature, certificate, transparency and artifact-digest
verification. This layer fixes Mitigate's identity policy and snapshots bounded
inputs before verification. It does not issue release or installation approval.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from preflight import REPOSITORY, expected_source

WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"
ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://slsa.dev/provenance/v1"
MAX_ARTIFACT = 128 * 1024 * 1024
MAX_BUNDLE = 4 * 1024 * 1024
VERIFIER_ENVIRONMENT = frozenset(
    {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "TMP",
        "TEMP",
        "TMPDIR",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_CONFIG_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    }
)


class VerificationError(Exception):
    """A fixed category, never a provider message or caller-supplied path."""


@dataclass(frozen=True)
class VerifiedArtifact:
    """Verified snapshot, usable only inside authenticated_snapshot's context.

    The source path can change after reading. Consumers must use this private
    snapshot, not reopen the original using the report as an authorization token.
    """

    path: Path
    sha256: str
    size: int
    commit: str
    tag: str

    def report(self):
        return {
            "schema_version": 1,
            "publisher_verified": True,
            "repository": REPOSITORY,
            "source_commit": self.commit,
            "tag": self.tag,
            "artifact_sha256": self.sha256,
            "artifact_size": self.size,
        }


def regular(info):
    return stat.S_ISREG(info.st_mode) and not (
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def snapshot(source, destination, limit, category):
    """Copy a bounded regular file through one descriptor; reject link switches.

    A trusted OS/temp directory and absence of a malicious same-user process are
    prerequisites. We do not claim filesystem immutability or a host sandbox.
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = None
    try:
        before = source.lstat()
        if not regular(before) or not 0 < before.st_size <= limit:
            raise VerificationError(category)
        descriptor = os.open(source, flags)
        opened = os.fstat(descriptor)
        if not regular(opened) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise VerificationError(category)
        digest = hashlib.sha256()
        count = 0
        with os.fdopen(descriptor, "rb") as reader:
            descriptor = None
            with destination.open("xb") as writer:
                while chunk := reader.read(min(64 * 1024, limit + 1 - count)):
                    count += len(chunk)
                    if count > limit:
                        raise VerificationError(category)
                    writer.write(chunk)
                    digest.update(chunk)
            final = os.fstat(reader.fileno())
        if (
            count != opened.st_size
            or count != final.st_size
            or final.st_mtime_ns != opened.st_mtime_ns
        ):
            raise VerificationError(category)
        destination.chmod(0o600)
        return digest.hexdigest(), count
    except (OSError, ValueError):
        raise VerificationError(category) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def verify_signature(artifact, bundle, commit, tag):
    # Identity constraints apply to certificate claims; a predicate's editable
    # source text is not proof of workflow or repository identity.
    command = [
        "gh",
        "attestation",
        "verify",
        str(artifact),
        "--bundle",
        str(bundle),
        "--hostname",
        "github.com",
        "--repo",
        REPOSITORY,
        "--signer-repo",
        REPOSITORY,
        "--signer-workflow",
        WORKFLOW,
        "--signer-digest",
        commit,
        "--source-digest",
        commit,
        "--source-ref",
        "refs/tags/" + tag,
        "--cert-identity",
        f"https://github.com/{WORKFLOW}@refs/tags/{tag}",
        "--cert-oidc-issuer",
        ISSUER,
        "--predicate-type",
        PREDICATE,
        "--digest-alg",
        "sha256",
        "--deny-self-hosted-runners",
    ]
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in VERIFIER_ENVIRONMENT
    }
    environment.update(
        {
            "GH_HOST": "github.com",
            "GH_PROMPT_DISABLED": "1",
            "GH_NO_UPDATE_NOTIFIER": "1",
            "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
        }
    )
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise VerificationError("verification_unavailable") from None
    if result.returncode != 0:
        raise VerificationError("verification_failed")


@contextmanager
def authenticated_snapshot(artifact, bundle, commit, tag):
    """Yield authenticated bytes only after every fixed identity constraint passes.

    The expected version/revision must come from a separately trusted release
    decision. No latest lookup, arbitrary workflow/root, or insecure fallback.
    """
    if not expected_source(commit, tag) or len(tag) > 64:
        raise VerificationError("invalid_source")
    try:
        with tempfile.TemporaryDirectory(prefix="mitigate-verify-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            artifact_copy, bundle_copy = root / "artifact", root / "bundle.jsonl"
            digest, size = snapshot(
                artifact, artifact_copy, MAX_ARTIFACT, "artifact_input"
            )
            snapshot(bundle, bundle_copy, MAX_BUNDLE, "attestation_input")
            verify_signature(artifact_copy, bundle_copy, commit, tag)
            yield VerifiedArtifact(artifact_copy, digest, size, commit, tag)
    except OSError:
        raise VerificationError("verification_unavailable") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        with authenticated_snapshot(
            args.artifact, args.bundle, args.commit, args.tag
        ) as artifact:
            print(json.dumps(artifact.report(), sort_keys=True))
        return 0
    except VerificationError as error:
        print(
            json.dumps(
                {"schema_version": 1, "publisher_verified": False, "error": str(error)}
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
