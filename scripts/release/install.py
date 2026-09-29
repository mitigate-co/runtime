"""Install a separately selected authenticated release into a NEW local directory.

No download, PATH edit, activation, updater, downgrade, binary execution or state
migration. Unsigned CI candidates cannot satisfy this install contract.
"""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import platform
import re
import tempfile

import apple_verify
from authenticate import VerificationError, authenticated_snapshot
from install_contract import MAX_MANIFEST, checked_files, require, validate_manifest


def native_target():
    target = {
        ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
        ("Windows", "AMD64"): "x86_64-pc-windows-msvc",
        ("Windows", "x86_64"): "x86_64-pc-windows-msvc",
        ("Darwin", "arm64"): "aarch64-apple-darwin",
        ("Darwin", "x86_64"): "x86_64-apple-darwin",
    }.get((platform.system(), platform.machine()))
    require(target is not None, "unsupported_platform")
    return target


def new_destination(path):
    # Parent directories are operator-trusted. Final target creation is exclusive;
    # neither an existing directory nor a link can be replaced.
    name = path.name
    require(
        bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name))
        and not name.endswith("."),
        "install_destination",
    )
    stem = name.split(".")[0].upper()
    require(
        stem
        not in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        },
        "install_destination",
    )
    parent = path.absolute().parent
    require(
        parent.is_dir() and not path.exists() and not path.is_symlink(),
        "install_destination",
    )
    return parent / name


def write_new(path, data, mode=0o600):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), mode
    )
    with os.fdopen(descriptor, "wb") as writer:
        writer.write(data)
        writer.flush()
        os.fsync(writer.fileno())


def materialize(destination, files, binary, manifest_bytes, receipt):
    # mkdir is the atomic non-replacement boundary. Failed writes deliberately
    # leave this new directory for inspection; never delete through a replaced
    # path. An I/O failure can leave complete-looking bytes without durability.
    try:
        destination.mkdir(mode=0o700)
        for name, data in files.items():
            if name != binary:
                write_new(destination / name, data)
        write_new(destination / "release.manifest.json", manifest_bytes)
        write_new(destination / binary, files[binary])
        (destination / binary).chmod(0o700)
        write_new(
            destination / "install-receipt.json",
            (json.dumps(receipt, sort_keys=True) + "\n").encode(),
        )
        if os.name != "nt":
            descriptor = os.open(
                destination, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except OSError:
        # Classify before leaving the authentication contexts; failure to install
        # is distinct from failure to authenticate the already checked bytes.
        raise VerificationError("install_io") from None


def install(
    manifest_path,
    manifest_bundle,
    archive_path,
    archive_bundle,
    commit,
    tag,
    destination,
    apple_team=None,
):
    target = native_target()
    destination = new_destination(destination)
    is_apple = target.endswith("apple-darwin")
    require(
        not is_apple
        or isinstance(apple_team, str)
        and re.fullmatch(r"[A-Z0-9]{10}", apple_team) is not None,
        "apple_identity_required",
    )
    require(is_apple or apple_team is None, "unexpected_apple_identity")
    with ExitStack() as stack:
        # Both independent signatures must bind the exact selected source and tag.
        signed_manifest = stack.enter_context(
            authenticated_snapshot(manifest_path, manifest_bundle, commit, tag)
        )
        require(signed_manifest.size <= MAX_MANIFEST, "release_contract")
        manifest_bytes = signed_manifest.path.read_bytes()
        manifest, prefix, binary = validate_manifest(
            manifest_bytes, target, commit, tag
        )
        archive = stack.enter_context(
            authenticated_snapshot(archive_path, archive_bundle, commit, tag)
        )
        files = checked_files(archive, manifest, prefix)
        if is_apple:
            # Signature verification needs a file, but neither extraction to the
            # selected install directory nor execution happens before this check.
            temporary = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="mitigate-apple-check-")
                )
            )
            temporary.chmod(0o700)
            selected = temporary / "mitigate"
            write_new(selected, files[binary])
            apple_verify.verify(selected, apple_team)
        receipt = {
            "schema_version": 1,
            "installed": True,
            "activated": False,
            "version": manifest["version"],
            "source_commit": commit,
            "target": target,
            "archive_sha256": archive.sha256,
            "manifest_sha256": signed_manifest.sha256,
            "apple_verified": is_apple,
        }
        materialize(destination, files, binary, manifest_bytes, receipt)
    return receipt


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise VerificationError("install_arguments")


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-bundle", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--archive-bundle", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--install-dir", required=True, type=Path)
    parser.add_argument("--apple-team")
    try:
        args = parser.parse_args()
        report = install(
            args.manifest,
            args.manifest_bundle,
            args.archive,
            args.archive_bundle,
            args.commit,
            args.tag,
            args.install_dir,
            args.apple_team,
        )
    except VerificationError as error:
        report = {"schema_version": 1, "installed": False, "error": str(error)}
    except (OSError, ValueError):
        report = {"schema_version": 1, "installed": False, "error": "install_io"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["installed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
