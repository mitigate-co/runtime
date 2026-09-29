"""Release assembly contracts; synthetic binaries are never executed or signed."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from authenticate import VerificationError, VerifiedArtifact
from install_contract import checked_files, validate_manifest
from package import TARGETS, archive_bytes
from sbom import json_bytes, sha256
import stage_release as staging

COMMIT = "a" * 40
TAG = "v0.1.0"


def context():
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "mitigate-co/runtime",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/tags/" + TAG,
        "GITHUB_SHA": COMMIT,
        "GITHUB_WORKFLOW_REF": "mitigate-co/runtime/.github/workflows/release.yml@refs/tags/"
        + TAG,
        "GITHUB_WORKFLOW_SHA": COMMIT,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": "12345",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }


def candidate(_root, target, output):
    output.mkdir()
    prefix = f"mitigate-0.1.0-{target}"
    binary = "mitigate.exe" if target.endswith("windows-msvc") else "mitigate"
    info = {
        "schema_version": 1,
        "kind": "unsigned_candidate",
        "version": "0.1.0",
        "source_commit": COMMIT,
        "target": target,
        "rustc": "synthetic compiler",
        "cargo_lock_sha256": "b" * 64,
        "toolchain_file_sha256": "c" * 64,
    }
    files = {
        name: (b"synthetic fixture; not executable code", name == binary)
        for name in (
            binary,
            "LICENSE",
            "NOTICE",
            "THIRD_PARTY_NOTICES.txt",
            "RUST_NOTICES.html",
            "sbom.spdx.json",
            "INSTALL.txt",
        )
    }
    files["build-info.json"] = (json_bytes(info), False)
    archive = output / (prefix + ".zip")
    archive_bytes(
        archive, {prefix + "/" + name: value for name, value in files.items()}
    )
    manifest = {
        **info,
        "archive": archive.name,
        "archive_sha256": sha256(archive.read_bytes()),
        "archive_size": archive.stat().st_size,
        "files": {
            name: {"sha256": sha256(data), "size": len(data), "executable": executable}
            for name, (data, executable) in files.items()
        },
    }
    (output / (prefix + ".manifest.json")).write_bytes(json_bytes(manifest))
    return output


class StageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mitigate-staging-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "release"
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, context(), clear=True))
        self.source = self.stack.enter_context(
            patch.object(staging.package, "source_revision", return_value=COMMIT)
        )
        self.preflight = self.stack.enter_context(
            patch.object(staging, "preflight", return_value={"source_eligible": True})
        )
        self.build = self.stack.enter_context(
            patch.object(staging.package, "package", side_effect=candidate)
        )
        self.target = self.stack.enter_context(
            patch.object(staging, "native_target", return_value=TARGETS[0])
        )
        self.smoke = self.stack.enter_context(patch.object(staging.smoke, "smoke"))

    def stage(self, **kwargs):
        return staging.stage(self.root, COMMIT, TAG, self.output, **kwargs)

    def read_release(self, target):
        prefix = f"mitigate-0.1.0-{target}"
        manifest, prefix, binary = validate_manifest(
            (self.output / (prefix + ".manifest.json")).read_bytes(),
            target,
            COMMIT,
            TAG,
        )
        archive = self.output / (prefix + ".zip")
        return (
            manifest,
            binary,
            checked_files(
                VerifiedArtifact(
                    archive,
                    sha256(archive.read_bytes()),
                    archive.stat().st_size,
                    COMMIT,
                    TAG,
                ),
                manifest,
                prefix,
            ),
        )

    def test_native_layouts_round_trip_through_installer_contract(self):
        for target in TARGETS:
            with self.subTest(target=target):
                self.output = self.root / target
                self.target.return_value = target
                apple = target.endswith("apple-darwin")
                values = (
                    dict(
                        identity="1" * 40,
                        team="A" * 10,
                        keychain=self.root / "keychain",
                        profile="notary",
                    )
                    if apple
                    else {}
                )

                def signed(path, *_args):
                    path.write_bytes(b"synthetic notarized replacement")

                with patch.object(staging.apple_sign, "signing_inputs"), patch.object(
                    staging.apple_sign, "sign_and_notarize", side_effect=signed
                ) as signer:
                    result = self.stage(**values)
                self.assertTrue(result["staged"])
                self.assertFalse(result["publisher_signed"])
                self.assertEqual(signer.call_count, int(apple))
                manifest, binary, files = self.read_release(target)
                self.assertEqual(manifest["kind"], "signed_release")
                self.assertEqual(
                    files[binary],
                    (
                        b"synthetic notarized replacement"
                        if apple
                        else b"synthetic fixture; not executable code"
                    ),
                )
                self.assertIn(COMMIT.encode(), files["INSTALL.txt"])
                self.assertEqual(len(list(self.output.iterdir())), 4)
                checksums = (self.output / "SHA256SUMS").read_text().splitlines()
                for line in checksums:
                    digest, name = line.split("  ")
                    self.assertEqual(sha256((self.output / name).read_bytes()), digest)
                self.assertEqual(len(checksums), 3)
        self.assertEqual(self.preflight.call_count, 8)

    def test_every_workflow_identity_field_is_required_before_build(self):
        for key in context():
            with self.subTest(key=key), patch.dict(os.environ, {key: "wrong"}):
                with self.assertRaisesRegex(
                    VerificationError, "release_workflow_context"
                ):
                    self.stage()
        self.build.assert_not_called()
        self.preflight.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_invalid_source_rejected_before_provider_or_build(self):
        for revision, tag in (
            ("short", TAG),
            (COMMIT, "v0.1.0-rc1"),
            (COMMIT, "v" + "1" * 65 + ".1.0"),
        ):
            with self.assertRaisesRegex(VerificationError, "invalid_source"):
                staging.stage(self.root, revision, tag, self.output)
        self.preflight.assert_not_called()
        self.build.assert_not_called()

    def test_source_ci_failure_prevents_build(self):
        self.preflight.return_value = {"source_eligible": False}
        with self.assertRaisesRegex(VerificationError, "release_source_gates"):
            self.stage()
        self.build.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_new_ci_failure_after_build_refuses_output(self):
        self.preflight.side_effect = [
            {"source_eligible": True},
            {"source_eligible": False},
        ]
        with self.assertRaisesRegex(VerificationError, "release_source_gates"):
            self.stage()
        self.build.assert_called_once()
        self.assertFalse(self.output.exists())

    def test_checkout_change_before_or_during_build_refuses_output(self):
        for revisions in (("b" * 40,), (COMMIT, "b" * 40)):
            self.source.side_effect = revisions
            with self.assertRaisesRegex(VerificationError, "release_checkout"):
                self.stage()
            self.assertFalse(self.output.exists())

    def test_native_smoke_failure_refuses_signing_and_output(self):
        self.smoke.side_effect = ValueError("Synthetic privacy probe failed")
        with patch.object(staging.apple_sign, "sign_and_notarize") as sign:
            with self.assertRaises(ValueError):
                self.stage()
            sign.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_existing_directory_and_creation_race_preserve_owner_files(self):
        self.output.mkdir()
        marker = self.output / "owner.txt"
        marker.write_bytes(b"keep")
        with self.assertRaisesRegex(VerificationError, "install_destination"):
            self.stage()
        self.build.assert_not_called()
        self.assertEqual(marker.read_bytes(), b"keep")
        self.output = self.root / "raced"

        def raced(*args):
            candidate(*args)
            self.output.mkdir()
            (self.output / "owner.txt").write_bytes(b"keep")

        self.build.side_effect = raced
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual([p.name for p in self.output.iterdir()], ["owner.txt"])

    def test_corrupt_candidate_refused_before_signing_or_output(self):
        def corrupted(*args):
            path = candidate(*args)
            next(path.glob("*.zip")).write_bytes(b"tampered")

        self.build.side_effect = corrupted
        with patch.object(staging.apple_sign, "sign_and_notarize") as signer:
            with self.assertRaisesRegex(VerificationError, "archive_mismatch"):
                self.stage()
            signer.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_wrong_candidate_identity_or_kind_refused(self):
        for field, value in (
            ("source_commit", "b" * 40),
            ("version", "0.1.1"),
            ("target", TARGETS[1]),
            ("kind", "signed_release"),
        ):

            def wrong(*args):
                directory = candidate(*args)
                path = next(directory.glob("*.manifest.json"))
                data = json.loads(path.read_bytes())
                data[field] = value
                path.write_bytes(json_bytes(data))

            self.build.side_effect = wrong
            with self.subTest(field=field), self.assertRaises(VerificationError):
                self.stage()
            self.assertFalse(self.output.exists())

    def test_apple_options_refused_on_other_platforms(self):
        with self.assertRaisesRegex(VerificationError, "unexpected_apple_identity"):
            self.stage(team="A" * 10)
        self.build.assert_not_called()

    def test_apple_failure_never_finalizes(self):
        self.target.return_value = TARGETS[2]
        with patch.object(staging.apple_sign, "signing_inputs"), patch.object(
            staging.apple_sign,
            "sign_and_notarize",
            side_effect=VerificationError("apple_notarization_failed"),
        ):
            with self.assertRaisesRegex(VerificationError, "apple_notarization_failed"):
                self.stage(keychain=self.root / "keychain")
        self.assertFalse(self.output.exists())

    def test_io_failure_leaves_partial_output_and_never_claims_success(self):
        with patch.object(
            staging, "write_new", side_effect=OSError("private-path-canary")
        ):
            with self.assertRaises(OSError):
                self.stage()
        self.assertTrue(self.output.is_dir())
        self.assertEqual(len(list(self.output.iterdir())), 1)

    def test_real_cli_blocks_without_release_context_and_does_not_print_input(self):
        environment = dict(os.environ, GITHUB_ACTIONS="false")
        result = subprocess.run(
            [
                sys.executable,
                str(Path(staging.__file__)),
                "--commit",
                COMMIT,
                "--tag",
                TAG,
                "--output",
                str(self.output / "private-path-canary"),
            ],
            env=environment,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["error"], "release_workflow_context")
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"private-path-canary", result.stdout)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
