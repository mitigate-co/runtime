"""Publisher and installation gates use synthetic bytes, never real keys/code."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import accept_release
import apple_verify
import authenticate
import install
from package import TARGETS
import release_bundle
import smoke
import smoke_command
from stage_release import finalize, read_candidate
from test_stage_release import COMMIT, TAG, candidate, context


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mitigate-pipeline-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture(TARGETS[0])
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.signatures = stack.enter_context(
            patch.object(authenticate, "verify_signature")
        )
        self.execute = stack.enter_context(patch.object(accept_release, "exercise"))
        self.apple = stack.enter_context(patch.object(apple_verify, "verify"))
        self.gates = stack.enter_context(
            patch.object(
                release_bundle,
                "signing_gate",
                return_value={"signing_prerequisites_met": True},
            )
        )
        stack.enter_context(patch.dict(os.environ, context(), clear=True))
        for module in (release_bundle, install, accept_release):
            stack.enter_context(
                patch.object(module, "native_target", side_effect=lambda: self.target)
            )

    def fixture(self, target):
        self.target = target
        root = self.root / target
        root.mkdir()
        incoming = candidate(root, target, root / "candidate")
        temporary = root / "temporary"
        temporary.mkdir()
        manifest, prefix, binary, files = read_candidate(
            incoming, temporary, target, COMMIT, TAG
        )
        self.output = root / "release"
        finalize(manifest, prefix, binary, files, self.output, COMMIT, TAG)
        self.prefix = prefix
        self.bundle = root / "bundle.jsonl"
        self.bundle.write_bytes(b"synthetic invalid bundle; verification is mocked")
        (self.output / "attestation.jsonl").write_bytes(self.bundle.read_bytes())

    def accept(self):
        os.environ["GITHUB_JOB"] = "accept"
        team = "AAAAAAAAAA" if self.target.endswith("apple-darwin") else None
        return accept_release.accept(self.output, COMMIT, TAG, team)

    def test_every_asset_authenticated_with_bounded_snapshots(self):
        with release_bundle.verified_release(self.output, self.bundle, COMMIT, TAG) as (
            assets,
            bundle,
        ):
            self.assertEqual(set(assets), {"archive", "manifest", "sbom", "checksums"})
            paths = [value.path for value in assets.values()] + [bundle]
            self.assertTrue(all(path.is_file() for path in paths))
            self.assertTrue(all(path.parent != self.output for path in paths))
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(self.signatures.call_count, 4)
        for call in self.signatures.call_args_list:
            self.assertEqual(call.args[2:], (COMMIT, TAG))
        self.execute.assert_not_called()

    def test_all_native_installers_finish_before_execution(self):
        def check_install(executable, version):
            self.assertTrue(executable.is_file())
            receipt = json.loads(
                (executable.parent / "install-receipt.json").read_bytes()
            )
            self.assertTrue(receipt["installed"])
            self.assertEqual(version, "0.1.0")
            self.assertEqual(receipt["target"], self.target)
            self.assertEqual(self.signatures.call_count, 6)
            self.assertEqual(
                self.apple.call_count, int(self.target.endswith("apple-darwin"))
            )

        self.execute.side_effect = check_install
        for target in TARGETS:
            if target != TARGETS[0]:
                self.fixture(target)
            self.signatures.reset_mock()
            self.apple.reset_mock()
            report = self.accept()
            self.assertTrue(report["accepted"])
            self.assertFalse(report["published"])
            self.assertEqual(report["target"], target)
            self.assertFalse(self.execute.call_args.args[0].exists())

    def test_each_failed_signature_prevents_execution(self):
        for position in range(6):
            self.signatures.side_effect = [None] * position + [
                authenticate.VerificationError("verification_failed")
            ]
            with self.assertRaisesRegex(
                authenticate.VerificationError, "^verification_failed$"
            ):
                self.accept()
        self.execute.assert_not_called()

    def test_external_sbom_must_equal_the_authenticated_embedded_sbom(self):
        (self.output / (self.prefix + ".spdx.json")).write_bytes(
            b"different signed sbom"
        )
        with self.assertRaisesRegex(
            authenticate.VerificationError, "^release_sbom_mismatch$"
        ):
            self.accept()
        self.execute.assert_not_called()

    def test_signed_checksums_cannot_contradict_any_asset(self):
        path = self.output / "SHA256SUMS"
        original = path.read_bytes()
        altered = (b"1" if original.startswith(b"0") else b"0") + original[1:]
        for value in (original.replace(b"  ", b" ", 1), original + original, altered):
            path.write_bytes(value)
            with self.assertRaisesRegex(
                authenticate.VerificationError, "^release_checksums_mismatch$"
            ):
                self.accept()
        self.execute.assert_not_called()

    def test_rejected_manifest_or_archive_never_executes(self):
        path = self.output / (self.prefix + ".manifest.json")
        original = path.read_bytes()
        data = json.loads(original)
        data["unexpected"] = "private-fixture"
        path.write_text(json.dumps(data))
        with self.assertRaises(authenticate.VerificationError):
            self.accept()
        path.write_bytes(original)
        (self.output / (self.prefix + ".zip")).write_bytes(b"invalid archive")
        with self.assertRaises(authenticate.VerificationError):
            self.accept()
        self.execute.assert_not_called()

    def test_apple_rejection_and_smoke_failure_prevent_success(self):
        self.fixture("aarch64-apple-darwin")
        self.apple.side_effect = authenticate.VerificationError(
            "apple_signature_failed"
        )
        with self.assertRaisesRegex(
            authenticate.VerificationError, "apple_signature_failed"
        ):
            self.accept()
        self.execute.assert_not_called()
        self.apple.side_effect = None
        self.execute.side_effect = ValueError("synthetic smoke failed")
        with self.assertRaises(ValueError):
            self.accept()

    def test_acceptance_refuses_signing_or_local_context_before_authentication(self):
        for job in ("sign", "build", "preflight", ""):
            os.environ["GITHUB_JOB"] = job
            with self.assertRaisesRegex(
                authenticate.VerificationError, "release_workflow_context"
            ):
                accept_release.accept(self.output, COMMIT, TAG)
        self.signatures.assert_not_called()
        self.execute.assert_not_called()

    def test_retention_requires_current_gates_and_never_overwrites(self):
        retained = self.output / "attestation.jsonl"
        retained.unlink()
        self.gates.return_value = {"signing_prerequisites_met": False}
        with self.assertRaisesRegex(
            authenticate.VerificationError, "release_signing_gates"
        ):
            release_bundle.retain_bundle(
                self.root, self.output, self.bundle, COMMIT, TAG
            )
        self.signatures.assert_not_called()
        self.assertFalse(retained.exists())
        self.gates.return_value = {"signing_prerequisites_met": True}
        result = release_bundle.retain_bundle(
            self.root, self.output, self.bundle, COMMIT, TAG
        )
        self.assertTrue(result["publisher_verified"])
        self.assertFalse(result["published"])
        self.assertEqual(retained.read_bytes(), self.bundle.read_bytes())
        with self.assertRaisesRegex(
            authenticate.VerificationError, "^release_bundle_io$"
        ):
            release_bundle.retain_bundle(
                self.root, self.output, self.bundle, COMMIT, TAG
            )
        self.execute.assert_not_called()


class SmokeIsolationTests(unittest.TestCase):
    def test_exercise_uses_fresh_state_and_no_provider_credentials(self):
        seen = []

        def command(argv, *, cwd, env, stdin, capture_output, timeout):
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("APPLE_CERTIFICATE_PASSWORD", env)
            self.assertNotIn("PRIVATE_INPUT", env)
            self.assertEqual(env["HOME"], str(cwd))
            self.assertEqual(timeout, 30)
            self.assertEqual(stdin, smoke_command.subprocess.DEVNULL)
            seen.append(cwd)
            category = tuple(argv[1:3])
            reports = {
                ("version", "--json"): {"version": "0.1.0"},
                ("config", "check"): {"valid": True},
                ("mcp", "scan"): {"servers": []},
                ("privacy", "self-test"): dict(
                    passed=True,
                    positive_control=True,
                    queue_isolation=True,
                    persisted_canaries_absent=True,
                    network_requests=0,
                ),
                ("egress", "inspect"): dict(
                    destination=None, queue=None, observed_event_types=[]
                ),
            }
            invalid = (
                category == ("config", "check")
                and b"private-smoke-canary" in (cwd / "config.json").read_bytes()
            )
            from subprocess import CompletedProcess

            return CompletedProcess(
                argv,
                2 if invalid else 0,
                b"" if invalid else json.dumps(reports[category]).encode(),
                b"invalid config" if invalid else b"",
            )

        with patch.dict(
            os.environ,
            {
                "GH_TOKEN": "private-fixture",
                "APPLE_CERTIFICATE_PASSWORD": "private-fixture",
                "PRIVATE_INPUT": "private-fixture",
            },
        ), patch.object(smoke_command.subprocess, "run", side_effect=command):
            smoke.exercise(Path("synthetic-never-executed"), "0.1.0")
        self.assertEqual(len(seen), 6)
        self.assertTrue(all(not path.exists() for path in seen))


if __name__ == "__main__":
    unittest.main()
