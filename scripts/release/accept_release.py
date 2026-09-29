"""Install and smoke-test an authenticated native release on a fresh CI runner.

This executes the binary only after all publisher and platform checks. Never run
it on the signing runner or on a developer/customer host with existing state.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile

from authenticate import VerificationError
from install import install, native_target
from install_contract import require
from release_bundle import verified_release
from smoke import exercise
from stage_release import Parser, workflow_context


def accept(directory, commit, tag, apple_team=None):
    workflow_context(commit, tag, os.environ, job="accept")
    with verified_release(directory, directory / "attestation.jsonl", commit, tag) as (
        assets,
        bundle,
    ):
        with tempfile.TemporaryDirectory(
            prefix="mitigate-release-accept-"
        ) as temporary:
            destination = Path(temporary) / "installation"
            receipt = install(
                assets["manifest"].path,
                bundle,
                assets["archive"].path,
                bundle,
                commit,
                tag,
                destination,
                apple_team,
            )
            require(receipt["installed"] is True, "release_installation")
            binary = (
                "mitigate.exe"
                if native_target().endswith("windows-msvc")
                else "mitigate"
            )
            exercise(destination / binary, receipt["version"])
    return {
        "schema_version": 1,
        "accepted": True,
        "source_commit": commit,
        "tag": tag,
        "target": receipt["target"],
        "apple_verified": receipt["apple_verified"],
        "published": False,
    }


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--apple-team")
    try:
        args = parser.parse_args()
        report = accept(args.directory, args.commit, args.tag, args.apple_team)
    except VerificationError as error:
        report = {"schema_version": 1, "accepted": False, "error": str(error)}
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        report = {"schema_version": 1, "accepted": False, "error": "release_acceptance"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
