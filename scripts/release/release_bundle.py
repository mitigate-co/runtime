"""Authenticate every release asset before retaining its publisher bundle."""

from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import tempfile

from authenticate import MAX_BUNDLE, VerificationError, authenticated_snapshot, snapshot
from install import native_target, write_new
from install_contract import MAX_MANIFEST, checked_files, require, validate_manifest
from package import TARGETS
from preflight import expected_source
from signing_gate import signing_gate
from stage_release import Parser, workflow_context


@contextmanager
def verified_release(directory, bundle, commit, tag, *, target=None):
    """Yield private authenticated assets, valid only inside this context.

    Each asset needs publisher authentication. Checksums and the external SBOM
    must also agree with the installer's closed archive/manifest contract.
    Never execute downloaded code as part of this verification.
    An explicit supported target permits cross-architecture package review;
    installation still independently requires its actual native target.
    """
    require(expected_source(commit, tag) and len(tag) <= 64, "invalid_source")
    target = native_target() if target is None else target
    require(target in TARGETS, "unsupported_platform")
    prefix = f"mitigate-{tag[1:]}-{target}"
    with ExitStack() as stack:
        temporary = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        temporary.chmod(0o700)
        bundle_copy = temporary / "attestation.jsonl"
        snapshot(bundle, bundle_copy, MAX_BUNDLE, "attestation_input")
        names = {
            "manifest": prefix + ".manifest.json",
            "archive": prefix + ".zip",
            "sbom": prefix + ".spdx.json",
            "checksums": "SHA256SUMS",
        }
        assets = {
            kind: stack.enter_context(
                authenticated_snapshot(directory / name, bundle_copy, commit, tag)
            )
            for kind, name in names.items()
        }
        require(assets["manifest"].size <= MAX_MANIFEST, "release_contract")
        manifest, _, _ = validate_manifest(
            assets["manifest"].path.read_bytes(), target, commit, tag
        )
        files = checked_files(assets["archive"], manifest, prefix)
        require(
            assets["sbom"].path.read_bytes() == files["sbom.spdx.json"],
            "release_sbom_mismatch",
        )
        expected = "".join(
            f"{assets[kind].sha256}  {name}\n"
            for kind, name in sorted(names.items(), key=lambda entry: entry[1])
            if kind != "checksums"
        ).encode("utf-8")
        require(
            assets["checksums"].path.read_bytes() == expected,
            "release_checksums_mismatch",
        )
        yield assets, bundle_copy


def retain_bundle(root, directory, bundle, commit, tag):
    workflow_context(commit, tag, os.environ)
    require(
        signing_gate(root, commit, tag, job="sign")["signing_prerequisites_met"],
        "release_signing_gates",
    )
    with verified_release(directory, bundle, commit, tag) as (_, verified_bundle):
        try:
            write_new(directory / "attestation.jsonl", verified_bundle.read_bytes())
        except OSError:
            raise VerificationError("release_bundle_io") from None
    return {"schema_version": 1, "publisher_verified": True, "published": False}


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    try:
        args = parser.parse_args()
        report = retain_bundle(
            Path(__file__).resolve().parents[2],
            args.directory,
            args.bundle,
            args.commit,
            args.tag,
        )
    except VerificationError as error:
        report = {"schema_version": 1, "publisher_verified": False, "error": str(error)}
    except (OSError, ValueError):
        report = {
            "schema_version": 1,
            "publisher_verified": False,
            "error": "release_bundle_io",
        }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["publisher_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
