"""Cask drafting authenticates fixtures; synthetic Mach-O bytes are never run."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import apple_verify
import authenticate
import homebrew
from release_bundle import verified_release
from macho_metadata import minimum_system, requirement
from stage_release import finalize, read_candidate
from test_stage_release import candidate, COMMIT, TAG


def binary(target, version=(11, 0, 0), legacy=False):
    cpu = 0x0100000C if target.startswith("aarch64") else 0x01000007
    packed = version[0] << 16 | version[1] << 8 | version[2]
    command = (
        struct.pack("<4I", 0x24, 16, packed, packed)
        if legacy
        else struct.pack("<6I", 0x32, 24, 1, packed, packed, 0)
    )
    return struct.pack("<8I", 0xFEEDFACF, cpu, 0, 2, 1, len(command), 0, 0) + command


class MetadataTests(unittest.TestCase):
    def test_both_known_load_commands_and_homebrew_floor(self):
        arm, intel = homebrew.TARGETS.values()
        self.assertEqual(minimum_system(binary(arm), arm), (11, 0, 0))
        self.assertEqual(
            minimum_system(binary(intel, (10, 12, 0), True), intel), (10, 12, 0)
        )
        self.assertEqual(requirement((10, 12, 0)), "depends_on :macos")
        self.assertEqual(requirement((11, 0, 0)), "depends_on :macos")
        self.assertEqual(requirement((14, 0, 0)), 'depends_on macos: ">= 14"')
        with self.assertRaisesRegex(
            authenticate.VerificationError, "homebrew_minimum_requires_review"
        ):
            requirement((14, 1, 0))

    def test_hostile_cpu_headers_platforms_commands_and_duplicate_minimum(self):
        target = homebrew.TARGETS["arm"]
        original = binary(target)
        hostile = [b"", original[:31], original[:-1], binary(homebrew.TARGETS["intel"])]
        # Documented header fields and LC_BUILD_VERSION offsets.
        for offset, value in (
            (0, 0xCAFEBABE),
            (12, 6),
            (16, 1025),
            (20, 1024 * 1024 + 1),
            (28, 1),
            (36, 0),
            (36, 23),
            (36, 32),
            (40, 2),
            (44, 0),
            (52, 1),
        ):
            changed = bytearray(original)
            struct.pack_into("<I", changed, offset, value)
            hostile.append(bytes(changed))
        duplicate = bytearray(original + original[32:])
        struct.pack_into("<2I", duplicate, 16, 2, 48)
        hostile.append(bytes(duplicate))
        for data in hostile:
            with self.subTest(length=len(data)), self.assertRaisesRegex(
                authenticate.VerificationError, "release_macho"
            ):
                minimum_system(data, target)


class CaskTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mitigate-homebrew-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directories = {}
        for arch, target in homebrew.TARGETS.items():
            root = self.root / arch
            root.mkdir()
            incoming = candidate(root, target, root / "candidate")
            temporary_path = root / "temporary"
            temporary_path.mkdir()
            manifest, prefix, name, files = read_candidate(
                incoming, temporary_path, target, COMMIT, TAG
            )
            files[name] = binary(target)
            output = root / "release"
            finalize(manifest, prefix, name, files, output, COMMIT, TAG)
            (output / "attestation.jsonl").write_bytes(
                b"synthetic invalid signature fixture"
            )
            self.directories[arch] = output
        self.output = self.root / "mitigate.rb"

    def draft(self):
        return homebrew.draft(
            self.directories["arm"],
            self.directories["intel"],
            COMMIT,
            TAG,
            "AAAAAAAAAA",
            self.output,
        )

    def verification(self):
        stack = ExitStack()
        stack.enter_context(
            patch.object(homebrew.platform, "system", return_value="Darwin")
        )
        self.signatures = stack.enter_context(
            patch.object(authenticate, "verify_signature")
        )
        self.apple = stack.enter_context(patch.object(apple_verify, "verify"))
        return stack

    def test_requires_all_assets_and_both_native_identities_then_writes_exclusively(
        self,
    ):
        with self.verification():
            report = self.draft()
            self.assertEqual(self.signatures.call_count, 8)
            self.assertEqual(self.apple.call_count, 2)
            for call in self.apple.call_args_list:
                self.assertEqual(call.args[1], "AAAAAAAAAA")
                self.assertFalse(call.args[0].exists())
            self.assertTrue(report["drafted"])
            self.assertFalse(report["published"])
            text = self.output.read_text()
            self.assertIn("releases/download/v#{version}", text)
            self.assertIn(
                'binary "mitigate-#{version}-#{arch}-apple-darwin/mitigate"', text
            )
            self.assertNotIn("latest", text)
            self.assertNotIn("system ", text)
            with self.assertRaisesRegex(
                authenticate.VerificationError, "homebrew_output"
            ):
                self.draft()
            self.assertEqual(self.output.read_text(), text)

    def test_each_publisher_or_apple_failure_prevents_any_output(self):
        with self.verification():
            for position in range(8):
                self.signatures.side_effect = [None] * position + [
                    authenticate.VerificationError("verification_failed")
                ]
                with self.assertRaisesRegex(
                    authenticate.VerificationError, "verification_failed"
                ):
                    self.draft()
                self.assertFalse(self.output.exists())
            self.signatures.side_effect = None
            for position in range(2):
                self.apple.side_effect = [None] * position + [
                    authenticate.VerificationError("apple_verification_failed")
                ]
                with self.assertRaisesRegex(
                    authenticate.VerificationError, "apple_verification_failed"
                ):
                    self.draft()
                self.assertFalse(self.output.exists())

    def test_wrong_architecture_source_and_unsafe_render_inputs_fail(self):
        manifest_path = next(self.directories["intel"].glob("*.manifest.json"))
        original = manifest_path.read_bytes()
        manifest = json.loads(original)
        manifest["source_commit"] = "b" * 40
        manifest_path.write_text(json.dumps(manifest))
        with self.verification(), self.assertRaisesRegex(
            authenticate.VerificationError, "release_contract"
        ):
            self.draft()
        self.assertFalse(self.output.exists())
        manifest_path.write_bytes(original)
        with self.verification():
            self.directories["intel"] = self.directories["arm"]
            with self.assertRaises(authenticate.VerificationError):
                self.draft()
        self.assertFalse(self.output.exists())
        artifacts = {arch: ("a" * 64, (11, 0, 0)) for arch in homebrew.TARGETS}
        for tag in ('v0.1.0";system("bad")', "v0.1.0-beta", "latest"):
            with self.assertRaises(authenticate.VerificationError):
                homebrew.render(COMMIT, tag, artifacts)
        artifacts["arm"] = ('a"\n', (11, 0, 0))
        with self.assertRaises(authenticate.VerificationError):
            homebrew.render(COMMIT, TAG, artifacts)

    def test_wrong_host_or_team_rejected_without_verification(self):
        with patch.object(authenticate, "verify_signature") as verify:
            with self.assertRaisesRegex(
                authenticate.VerificationError, "unsupported_platform"
            ):
                with verified_release(
                    self.root,
                    self.root / "absent",
                    COMMIT,
                    TAG,
                    target="unknown-target",
                ):
                    self.fail("Unsupported target was admitted")
            verify.assert_not_called()
        with patch.object(
            homebrew.platform, "system", return_value="Windows"
        ), patch.object(authenticate, "verify_signature") as verify:
            with self.assertRaisesRegex(
                authenticate.VerificationError, "apple_verification_unavailable"
            ):
                self.draft()
            verify.assert_not_called()
        with self.verification():
            with self.assertRaisesRegex(
                authenticate.VerificationError, "apple_identity_required"
            ):
                homebrew.draft(
                    self.directories["arm"],
                    self.directories["intel"],
                    COMMIT,
                    TAG,
                    "unsafe-team",
                    self.output,
                )
            self.signatures.assert_not_called()

    @unittest.skipUnless(
        platform.system() == "Darwin", "actual Homebrew cask loader needs macOS"
    )
    def test_draft_loads_in_actual_homebrew_without_installing(self):
        with self.verification():
            self.draft()
        self.assertIsNotNone(
            shutil.which("brew"), "Homebrew must be available on native CI"
        )
        environment = dict(os.environ)
        environment.update(HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1")
        result = subprocess.run(
            ["brew", "info", "--cask", "--json=v2", str(self.output)],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=90,
        )
        self.assertEqual(
            result.returncode, 0, "Homebrew rejected the synthetic cask draft"
        )
        casks = json.loads(result.stdout)["casks"]
        self.assertEqual(len(casks), 1)
        self.assertEqual(casks[0]["token"], "mitigate")
        self.assertEqual(casks[0]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
