"""Draft a macOS cask from two authenticated, natively verified release archives.

No release lookup, artifact download, tap mutation, publication or installation.
The draft and its release still need owner review and actual Homebrew acceptance.
"""

import json
from pathlib import Path
import platform
import re
import tempfile

import apple_verify
from authenticate import VerificationError
from install import write_new
from install_contract import checked_files, require, validate_manifest
from macho_metadata import minimum_system, requirement
from preflight import expected_source, REPOSITORY
from release_bundle import verified_release
from stage_release import Parser

TARGETS = {"arm": "aarch64-apple-darwin", "intel": "x86_64-apple-darwin"}


def render(commit, tag, artifacts):
    require(expected_source(commit, tag) and len(tag) <= 64, "invalid_source")
    require(set(artifacts) == set(TARGETS), "homebrew_architectures")
    for digest, minimum in artifacts.values():
        require(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
            "homebrew_digest",
        )
        require(
            isinstance(minimum, tuple)
            and len(minimum) == 3
            and all(type(n) is int and 0 <= n <= 255 for n in minimum)
            and 10 <= minimum[0] <= 99,
            "release_macho",
        )
    arm, intel = artifacts["arm"], artifacts["intel"]
    return f"""# Reviewed source: https://github.com/{REPOSITORY}/commit/{commit}
cask "mitigate" do
  arch arm: "aarch64", intel: "x86_64"

  version "{tag[1:]}"
  sha256 arm:   "{arm[0]}",
         intel: "{intel[0]}"

  url "https://github.com/{REPOSITORY}/releases/download/v#{{version}}/mitigate-#{{version}}-#{{arch}}-apple-darwin.zip"
  name "Mitigate"
  desc "Local MCP inventory and access controls"
  homepage "https://github.com/{REPOSITORY}"

  on_arm do
    {requirement(arm[1])}
  end
  on_intel do
    {requirement(intel[1])}
  end

  binary "mitigate-#{{version}}-#{{arch}}-apple-darwin/mitigate"
end
"""


def draft(arm_directory, intel_directory, commit, tag, team, output):
    require(platform.system() == "Darwin", "apple_verification_unavailable")
    require(
        isinstance(team, str) and re.fullmatch(r"[A-Z0-9]{10}", team),
        "apple_identity_required",
    )
    require(
        output.name == "mitigate.rb"
        and not output.exists()
        and not output.is_symlink(),
        "homebrew_output",
    )
    artifacts = {}
    for arch, directory in (("arm", arm_directory), ("intel", intel_directory)):
        target = TARGETS[arch]
        with verified_release(
            directory, directory / "attestation.jsonl", commit, tag, target=target
        ) as (assets, _):
            manifest, prefix, binary = validate_manifest(
                assets["manifest"].path.read_bytes(), target, commit, tag
            )
            files = checked_files(assets["archive"], manifest, prefix)
            minimum = minimum_system(files[binary], target)
            with tempfile.TemporaryDirectory(
                prefix="mitigate-homebrew-check-"
            ) as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                executable = root / "mitigate"
                write_new(executable, files[binary])
                apple_verify.verify(executable, team)
            artifacts[arch] = (assets["archive"].sha256, minimum)
    # Nothing is written until both architectures pass every verification.
    write_new(output, render(commit, tag, artifacts).encode("utf-8"))
    return {
        "schema_version": 1,
        "drafted": True,
        "published": False,
        "source_commit": commit,
        "tag": tag,
    }


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--arm-directory", type=Path, required=True)
    parser.add_argument("--intel-directory", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--apple-team", required=True)
    parser.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args()
        report = draft(
            args.arm_directory,
            args.intel_directory,
            args.commit,
            args.tag,
            args.apple_team,
            args.output,
        )
    except VerificationError as error:
        report = {"schema_version": 1, "drafted": False, "error": str(error)}
    except (OSError, ValueError):
        report = {"schema_version": 1, "drafted": False, "error": "homebrew_io"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["drafted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
