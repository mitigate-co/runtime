"""Stage this workflow run's native candidate for later publisher attestation.

Only the direct reviewed release workflow may invoke this entrypoint. A staged
manifest is not signed merely because its schema kind says signed_release.
"""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import apple_sign
import package
from authenticate import MAX_ARTIFACT, VerificationError, snapshot
from install import native_target, new_destination, write_new
from install_contract import (
    BUILD_FIELDS,
    MAX_FILE,
    MAX_MANIFEST,
    checked_files,
    require,
    validate_candidate,
    validate_manifest,
)
from preflight import REPOSITORY, expected_source, preflight
from sbom import json_bytes, sha256


@dataclass(frozen=True)
class BuildArchive:
    """Byte integrity descriptor for our own build, without publisher authority."""

    path: Path
    sha256: str
    size: int


def workflow_context(commit, tag, environment, *, job="sign"):
    require(expected_source(commit, tag) and len(tag) <= 64, "invalid_source")
    require(job in {"preflight", "sign", "accept"}, "release_workflow_context")
    required = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/tags/" + tag,
        "GITHUB_SHA": commit,
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}",
        "GITHUB_WORKFLOW_SHA": commit,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": job,
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    require(
        all(environment.get(key) == value for key, value in required.items())
        and re.fullmatch(r"[1-9][0-9]{0,19}", environment.get("GITHUB_RUN_ID", "")),
        "release_workflow_context",
    )


def read_candidate(directory, temporary, target, commit, tag):
    prefix = f"mitigate-{tag[1:]}-{target}"
    manifest_copy = temporary / "candidate-manifest.json"
    snapshot(
        directory / (prefix + ".manifest.json"),
        manifest_copy,
        MAX_MANIFEST,
        "candidate_manifest",
    )
    manifest, prefix, binary = validate_candidate(
        manifest_copy.read_bytes(), target, commit, tag
    )
    archive_copy = temporary / "candidate.zip"
    digest, size = snapshot(
        directory / (prefix + ".zip"), archive_copy, MAX_ARTIFACT, "candidate_archive"
    )
    # Structural integrity only. The workflow must download the exact named
    # immutable candidate from its own successful, unprivileged build jobs.
    archive = BuildArchive(archive_copy, digest, size)
    return manifest, prefix, binary, checked_files(archive, manifest, prefix)


def finalize(manifest, prefix, binary, files, output, commit, tag):
    """Write a new directory; only successful return allows later attestation.

    Caller supplies checked build bytes and, on Apple, the notarized replacement.
    I/O failure deliberately leaves new output for inspection; no recursive erase.
    """
    info = {key: manifest[key] for key in BUILD_FIELDS}
    info["kind"] = "signed_release"
    files = dict(files)
    files["build-info.json"] = json_bytes(info)
    files["INSTALL.txt"] = (
        "Verify the archive and manifest with their publisher attestation bundles.\n"
        "Do not execute a verifier contained in an untrusted download.\n"
        f"Source: https://github.com/{REPOSITORY}/tree/{commit}\n"
        f"Installation: https://github.com/{REPOSITORY}/blob/{commit}/docs/VERIFIED_INSTALL.md\n"
        "Installation does not activate the executable or change existing local state.\n"
    ).encode("utf-8")
    output.mkdir(mode=0o700)
    archive = output / (prefix + ".zip")
    package.archive_bytes(
        archive,
        {f"{prefix}/{key}": (value, key == binary) for key, value in files.items()},
    )
    require(0 < archive.stat().st_size <= MAX_ARTIFACT, "release_archive_size")
    digest, size = sha256(archive.read_bytes()), archive.stat().st_size
    result = {
        **info,
        "archive": archive.name,
        "archive_sha256": digest,
        "archive_size": size,
        "files": {
            name: {
                "sha256": sha256(data),
                "size": len(data),
                "executable": name == binary,
            }
            for name, data in sorted(files.items())
        },
    }
    encoded = json_bytes(result)
    # Use the installer's actual contract, not a second permissive writer check.
    checked, _, _ = validate_manifest(encoded, info["target"], commit, tag)
    require(
        checked_files(BuildArchive(archive, digest, size), checked, prefix) == files,
        "release_roundtrip",
    )
    write_new(output / (prefix + ".manifest.json"), encoded)
    write_new(output / (prefix + ".spdx.json"), files["sbom.spdx.json"])
    checksums = "".join(
        f"{sha256(path.read_bytes())}  {path.name}\n"
        for path in sorted(output.iterdir())
    )
    write_new(output / "SHA256SUMS", checksums.encode("utf-8"))
    return {
        "schema_version": 1,
        "staged": True,
        "publisher_signed": False,
        "source_commit": commit,
        "tag": tag,
        "target": info["target"],
        "archive_sha256": digest,
    }


def stage(
    root,
    candidate,
    commit,
    tag,
    output,
    identity=None,
    team=None,
    keychain=None,
    profile=None,
):
    workflow_context(commit, tag, os.environ)
    target = native_target()
    output = new_destination(output)
    require(package.source_revision(root) == commit, "release_checkout")
    require(preflight(commit, tag)["source_eligible"], "release_source_gates")
    is_apple = target.endswith("apple-darwin")
    if is_apple:
        require(keychain is not None, "apple_keychain")
        apple_sign.signing_inputs(identity, team, keychain, profile)
    else:
        require(
            all(value is None for value in (identity, team, keychain, profile)),
            "unexpected_apple_identity",
        )
    with tempfile.TemporaryDirectory(prefix="mitigate-release-stage-") as temporary:
        temporary = Path(temporary)
        temporary.chmod(0o700)
        manifest, prefix, binary, files = read_candidate(
            candidate, temporary, target, commit, tag
        )
        if is_apple:
            executable = temporary / "mitigate"
            write_new(executable, files[binary], 0o700)
            apple_sign.sign_and_notarize(executable, identity, team, keychain, profile)
            signed_copy = temporary / "notarized-binary"
            snapshot(executable, signed_copy, MAX_FILE, "apple_signed_binary")
            files[binary] = signed_copy.read_bytes()
        # Recheck source evidence after a potentially long native notary
        # wait; a moved tag, changed checkout or newly failing run blocks output.
        require(package.source_revision(root) == commit, "release_checkout")
        require(preflight(commit, tag)["source_eligible"], "release_source_gates")
        return finalize(manifest, prefix, binary, files, output, commit, tag)


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise VerificationError("release_arguments")


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--apple-identity")
    parser.add_argument("--apple-team")
    parser.add_argument("--apple-keychain", type=Path)
    parser.add_argument("--apple-notary-profile")
    try:
        args = parser.parse_args()
        report = stage(
            Path(__file__).resolve().parents[2],
            args.candidate,
            args.commit,
            args.tag,
            args.output,
            args.apple_identity,
            args.apple_team,
            args.apple_keychain,
            args.apple_notary_profile,
        )
    except VerificationError as error:
        report = {"schema_version": 1, "staged": False, "error": str(error)}
    except (OSError, ValueError, subprocess.CalledProcessError):
        report = {"schema_version": 1, "staged": False, "error": "release_build_io"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["staged"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
