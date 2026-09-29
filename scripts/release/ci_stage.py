"""Protected signing-job entrypoint. No compilation or candidate execution."""

import json
import os
from pathlib import Path
import subprocess

import apple_credentials
from authenticate import VerificationError
from install import native_target
from install_contract import require
from signing_gate import signing_gate
from stage_release import Parser, stage, workflow_context


def prepare(root, candidate, commit, tag, output):
    workflow_context(commit, tag, os.environ)
    # Remove every Apple input before Git/GitHub subprocesses can inherit it.
    # The protected job already owns these inputs; none is decoded/imported until
    # current source, failure policy and environment evidence are rechecked.
    values = {name: os.environ.pop(name, None) for name in apple_credentials.INPUTS}
    require(
        signing_gate(root, commit, tag, job="sign")["signing_prerequisites_met"],
        "release_signing_gates",
    )
    if native_target().endswith("apple-darwin"):
        with apple_credentials.prepared_keychain(values) as references:
            report = stage(root, candidate, commit, tag, output, **references)
        # Returning only after successful cleanup prevents attestation after an
        # uncertain Keychain deletion, even if complete archive bytes exist.
        return report
    require(
        all(value is None for value in values.values()), "unexpected_apple_credentials"
    )
    return stage(root, candidate, commit, tag, output)


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    try:
        args = parser.parse_args()
        report = prepare(
            Path(__file__).resolve().parents[2],
            args.candidate,
            args.commit,
            args.tag,
            args.output,
        )
    except VerificationError as error:
        report = {"schema_version": 1, "staged": False, "error": str(error)}
    except (OSError, ValueError, subprocess.CalledProcessError):
        report = {"schema_version": 1, "staged": False, "error": "release_build_io"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["staged"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
