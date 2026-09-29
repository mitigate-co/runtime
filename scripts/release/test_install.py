"""Hostile installer inputs with mocked publisher verification, never fixture execution."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

import apple_verify
import authenticate
import install
from package import archive_bytes

COMMIT = "a" * 40
TAG = "v0.1.0"
TARGET = "x86_64-unknown-linux-gnu"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mitigate-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "mitigate-0.1.0"
        self.manifest_path = self.root / "manifest.json"
        self.archive_path = self.root / "release.zip"
        self.bundle = self.root / "bundle.jsonl"
        self.bundle.write_bytes(b"synthetic, never a valid attestation")
        self.fixture(TARGET)

    def fixture(self, target):
        self.info = {
            "schema_version": 1,
            "kind": "signed_release",
            "version": "0.1.0",
            "source_commit": COMMIT,
            "target": target,
            "rustc": "synthetic compiler",
            "cargo_lock_sha256": "b" * 64,
            "toolchain_file_sha256": "c" * 64,
        }
        self.prefix = f"mitigate-0.1.0-{target}"
        self.binary = "mitigate.exe" if target.endswith("windows-msvc") else "mitigate"
        self.contents = {
            name: (b"synthetic non-executable fixture", name == self.binary)
            for name in (
                self.binary,
                "LICENSE",
                "NOTICE",
                "THIRD_PARTY_NOTICES.txt",
                "RUST_NOTICES.html",
                "sbom.spdx.json",
                "INSTALL.txt",
            )
        }
        self.contents["build-info.json"] = (json.dumps(self.info).encode(), False)
        if self.archive_path.exists():
            self.archive_path.unlink()
        archive_bytes(
            self.archive_path,
            {f"{self.prefix}/{key}": value for key, value in self.contents.items()},
        )
        self.manifest = {
            **self.info,
            "archive": self.prefix + ".zip",
            "files": {
                name: {"size": len(data), "sha256": digest(data), "executable": mode}
                for name, (data, mode) in self.contents.items()
            },
        }
        self.rehash()

    def rehash(self):
        self.manifest["archive_size"] = self.archive_path.stat().st_size
        self.manifest["archive_sha256"] = digest(self.archive_path.read_bytes())
        self.write_manifest()

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def run_install(self, team=None):
        return install.install(
            self.manifest_path,
            self.bundle,
            self.archive_path,
            self.bundle,
            COMMIT,
            TAG,
            self.destination,
            team,
        )

    def verified(self, target=TARGET):
        target_patch = patch.object(install, "native_target", return_value=target)
        signer_patch = patch.object(authenticate, "verify_signature")
        target_patch.start()
        verifier = signer_patch.start()
        self.addCleanup(target_patch.stop)
        self.addCleanup(signer_patch.stop)
        return verifier

    def test_every_native_layout_installs_only_verified_bytes_without_activation(self):
        for target in (
            TARGET,
            "x86_64-pc-windows-msvc",
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
        ):
            self.fixture(target)
            self.destination = self.root / target
            team = "AAAAAAAAAA" if target.endswith("apple-darwin") else None
            with patch.object(
                install, "native_target", return_value=target
            ), patch.object(
                authenticate, "verify_signature"
            ) as signatures, patch.object(
                apple_verify, "verify"
            ) as apple:
                receipt = self.run_install(team)
            self.assertEqual(signatures.call_count, 2)
            self.assertEqual(apple.call_count, int(team is not None))
            for call in signatures.call_args_list:
                self.assertEqual(call.args[2:], (COMMIT, TAG))
                self.assertNotIn(call.args[0], (self.manifest_path, self.archive_path))
            self.assertTrue(receipt["installed"])
            self.assertFalse(receipt["activated"])
            self.assertEqual(receipt["target"], target)
            self.assertEqual(
                set(p.name for p in self.destination.iterdir()),
                {*self.contents, "release.manifest.json", "install-receipt.json"},
            )
            for name, (data, _) in self.contents.items():
                self.assertEqual((self.destination / name).read_bytes(), data)
            self.assertEqual(
                json.loads((self.destination / "install-receipt.json").read_bytes()),
                receipt,
            )
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
                self.assertEqual(
                    stat.S_IMODE((self.destination / self.binary).stat().st_mode), 0o700
                )
                self.assertEqual(
                    stat.S_IMODE((self.destination / "LICENSE").stat().st_mode), 0o600
                )

    def test_either_signature_failure_leaves_no_install_directory(self):
        verifier = self.verified()
        for failures in (
            [authenticate.VerificationError("verification_failed")],
            [None, authenticate.VerificationError("verification_failed")],
        ):
            verifier.side_effect = failures
            with self.assertRaisesRegex(
                authenticate.VerificationError, "^verification_failed$"
            ):
                self.run_install()
            self.assertFalse(self.destination.exists())

    def test_unsigned_wrong_build_or_unknown_manifest_fields_are_not_installable(self):
        self.verified()
        original = copy.deepcopy(self.manifest)
        mutations = [
            ("kind", "unsigned_candidate"),
            ("schema_version", True),
            ("version", "0.0.9"),
            ("source_commit", "d" * 40),
            ("target", "aarch64-apple-darwin"),
            ("archive", "../mitigate.zip"),
            ("archive_size", 134217729),
            ("archive_sha256", "invalid"),
            ("future", "private-input-canary"),
            ("files", {"../mitigate": {}}),
        ]
        for key, value in mutations:
            self.manifest = copy.deepcopy(original)
            self.manifest[key] = value
            self.write_manifest()
            with self.subTest(field=key), self.assertRaises(
                authenticate.VerificationError
            ):
                self.run_install()
            self.assertFalse(self.destination.exists())

    def test_manifest_ambiguity_types_and_expansion_limits_fail_before_writes(self):
        self.verified()
        original = self.manifest_path.read_bytes()
        for data in [
            original.replace(
                b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'
            ),
            b"[" * 1000 + b"0" + b"]" * 1000,
            b"{" + b" " * 16384 + b"}",
            original.decode().encode("utf-16"),
            b"\xef\xbb\xbf" + original,
        ]:
            self.manifest_path.write_bytes(data)
            with self.assertRaises(authenticate.VerificationError):
                self.run_install()
            self.assertFalse(self.destination.exists())
        for key, value in [
            ("size", True),
            ("size", 268435457),
            ("executable", "yes"),
            ("sha256", "bad"),
            ("future", 1),
        ]:
            record = self.manifest["files"][self.binary]
            saved = dict(record)
            record[key] = value
            self.write_manifest()
            with self.assertRaises(authenticate.VerificationError):
                self.run_install()
            self.manifest["files"][self.binary] = saved
            self.assertFalse(self.destination.exists())

    def test_archive_mismatch_member_content_and_build_info_conflicts_are_refused(self):
        self.verified()
        self.archive_path.write_bytes(self.archive_path.read_bytes() + b"trailing")
        with self.assertRaisesRegex(
            authenticate.VerificationError, "^archive_mismatch$"
        ):
            self.run_install()
        self.rehash()
        with self.assertRaises(authenticate.VerificationError):
            self.run_install()
        self.fixture(TARGET)
        self.manifest["files"][self.binary]["sha256"] = "d" * 64
        self.write_manifest()
        with self.assertRaisesRegex(authenticate.VerificationError, "^file_mismatch$"):
            self.run_install()
        self.fixture(TARGET)
        self.manifest["rustc"] = "different compiler than packaged build-info"
        self.write_manifest()
        with self.assertRaises(authenticate.VerificationError):
            self.run_install()
        self.assertFalse(self.destination.exists())

    def test_archive_names_duplicates_symlinks_modes_and_directory_bombs_are_refused(
        self,
    ):
        self.verified()
        original = self.archive_path.read_bytes()
        for member in [
            "../outside",
            f"{self.prefix}/../outside",
            f"{self.prefix}/{self.binary}",
        ]:
            self.archive_path.write_bytes(original)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(self.archive_path, "a") as archive:
                    archive.writestr(member, b"synthetic")
            self.rehash()
            with self.assertRaises(authenticate.VerificationError):
                self.run_install()
        for mode in [0o120777, 0o104755, 0o100777]:
            with zipfile.ZipFile(self.archive_path, "w") as archive:
                for name, (data, executable) in self.contents.items():
                    info = zipfile.ZipInfo(f"{self.prefix}/{name}")
                    info.create_system = 3
                    info.external_attr = (mode if executable else 0o100644) << 16
                    archive.writestr(info, data)
            self.rehash()
            with self.assertRaises(authenticate.VerificationError):
                self.run_install()
        data = bytearray(original)
        struct.pack_into("<HH", data, len(data) - 14, 65535, 65535)
        self.archive_path.write_bytes(data)
        self.rehash()
        with patch("install_contract.zipfile.ZipFile") as reader:
            with self.assertRaises(authenticate.VerificationError):
                self.run_install()
            reader.assert_not_called()
        self.assertFalse(self.destination.exists())
        self.assertFalse((self.root / "outside").exists())

    def test_source_replacement_after_verification_cannot_change_install_bytes(self):
        verifier = self.verified()
        calls = 0

        def replace(*_args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.archive_path.write_bytes(b"private-replacement-canary")
                self.manifest_path.write_bytes(b"private-replacement-canary")

        verifier.side_effect = replace
        self.run_install()
        self.assertEqual(
            (self.destination / self.binary).read_bytes(), self.contents[self.binary][0]
        )

    def test_existing_targets_and_unsafe_names_are_preserved_before_verification(self):
        verifier = self.verified()
        self.destination.mkdir()
        marker = self.destination / "preserve"
        marker.write_bytes(b"private-existing-canary")
        for path in [
            self.destination,
            marker,
            self.root / "CON",
            self.root / "report:stream",
            self.root / "trailing.",
            self.root / "absent" / "install",
        ]:
            self.destination = path
            with self.assertRaisesRegex(
                authenticate.VerificationError, "^install_destination$"
            ):
                self.run_install()
            verifier.assert_not_called()
        self.assertEqual(marker.read_bytes(), b"private-existing-canary")

    def test_partial_write_failure_leaves_no_completion_receipt_and_no_prior_install_change(
        self,
    ):
        self.verified()
        prior = self.root / "existing-version"
        prior.mkdir()
        (prior / "mitigate").write_bytes(b"private-existing-canary")
        writer = install.write_new

        def fail(path, data, *args):
            if path.name == self.binary:
                raise OSError("private-write-error-canary")
            return writer(path, data, *args)

        with patch.object(install, "write_new", side_effect=fail):
            with self.assertRaisesRegex(authenticate.VerificationError, "^install_io$"):
                self.run_install()
        self.assertTrue(self.destination.is_dir())
        self.assertFalse((self.destination / "install-receipt.json").exists())
        self.assertFalse((self.destination / self.binary).exists())
        self.assertEqual((prior / "mitigate").read_bytes(), b"private-existing-canary")

    def test_destination_created_during_verification_is_never_replaced(self):
        verifier = self.verified()
        calls = 0

        def race(*_args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.destination.mkdir()
                (self.destination / "preserve").write_bytes(b"private-race-canary")

        verifier.side_effect = race
        with self.assertRaisesRegex(authenticate.VerificationError, "^install_io$"):
            self.run_install()
        self.assertEqual(list(p.name for p in self.destination.iterdir()), ["preserve"])
        self.assertEqual(
            (self.destination / "preserve").read_bytes(), b"private-race-canary"
        )

    def test_destination_link_is_refused_without_touching_its_target(self):
        verifier = self.verified()
        target = self.root / "existing"
        target.mkdir()
        try:
            self.destination.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("OS does not allow the fixture symlink")
        with self.assertRaisesRegex(
            authenticate.VerificationError, "^install_destination$"
        ):
            self.run_install()
        verifier.assert_not_called()
        self.assertEqual(list(target.iterdir()), [])
        self.assertTrue(self.destination.is_symlink())

    def test_cli_does_not_report_success_when_a_final_flush_fails(self):
        self.verified()
        real_sync = install.os.fsync
        calls = 0

        def fail(descriptor):
            nonlocal calls
            calls += 1
            if calls == 10:
                raise OSError("private-flush-error-canary")
            return real_sync(descriptor)

        args = [
            "install.py",
            "--manifest",
            str(self.manifest_path),
            "--manifest-bundle",
            str(self.bundle),
            "--archive",
            str(self.archive_path),
            "--archive-bundle",
            str(self.bundle),
            "--commit",
            COMMIT,
            "--tag",
            TAG,
            "--install-dir",
            str(self.destination),
        ]
        with patch("sys.argv", args), patch.object(
            install.os, "fsync", side_effect=fail
        ), patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(install.main(), 2)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"schema_version": 1, "installed": False, "error": "install_io"},
        )
        # Complete-looking receipt bytes can exist after an uncertain flush.
        # Success requires the command result, never only a file's presence.
        self.assertTrue((self.destination / "install-receipt.json").exists())

    def test_apple_checks_are_mandatory_and_failure_precedes_install_directory(self):
        self.fixture("aarch64-apple-darwin")
        verifier = self.verified("aarch64-apple-darwin")
        for team in (None, "bad", 'AAAAAAAAA"'):
            with self.assertRaisesRegex(
                authenticate.VerificationError, "^apple_identity_required$"
            ):
                self.run_install(team)
            verifier.assert_not_called()
        with patch.object(
            apple_verify,
            "verify",
            side_effect=authenticate.VerificationError("apple_verification_failed"),
        ):
            with self.assertRaisesRegex(
                authenticate.VerificationError, "^apple_verification_failed$"
            ):
                self.run_install("AAAAAAAAAA")
        self.assertFalse(self.destination.exists())

    def test_cli_errors_never_echo_provider_text_or_paths(self):
        with patch(
            "sys.argv", ["install.py", "--unknown", "private-path-canary"]
        ), patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(install.main(), 2)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"schema_version": 1, "installed": False, "error": "install_arguments"},
        )


class AppleTests(unittest.TestCase):
    def test_system_verifier_pins_developer_id_team_and_notarization_without_execution(
        self,
    ):
        with patch.dict(
            os.environ, {"DYLD_INSERT_LIBRARIES": "private-env-canary"}
        ), patch.object(apple_verify.subprocess, "run") as run:
            run.return_value.returncode = 0
            apple_verify.verify(Path("synthetic-binary"), "AAAAAAAAAA")
        command = run.call_args.args[0]
        self.assertEqual(
            command[:4],
            ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures"],
        )
        self.assertIn(
            'certificate leaf[subject.OU] = "AAAAAAAAAA" and notarized', command[4]
        )
        self.assertIn("anchor apple generic", command[4])
        self.assertIn("100.6.1.13", command[4])
        self.assertNotIn("DYLD_INSERT_LIBRARIES", run.call_args.kwargs["env"])
        self.assertEqual(run.call_args.kwargs["timeout"], 45)
        for failure in (
            subprocess.CompletedProcess([], 1),
            FileNotFoundError(),
            subprocess.TimeoutExpired("codesign", 45),
        ):
            kwargs = (
                {"side_effect": failure}
                if isinstance(failure, Exception)
                else {"return_value": failure}
            )
            with patch.object(apple_verify.subprocess, "run", **kwargs):
                with self.assertRaises(authenticate.VerificationError):
                    apple_verify.verify(Path("synthetic-binary"), "AAAAAAAAAA")

    @unittest.skipUnless(
        platform.system() == "Darwin", "native Apple negative acceptance"
    )
    def test_real_codesign_refuses_unsigned_synthetic_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "unsigned"
            binary.write_bytes(b"synthetic bytes must never satisfy Apple trust")
            with self.assertRaisesRegex(
                authenticate.VerificationError, "^apple_verification_failed$"
            ):
                apple_verify.verify(binary, "AAAAAAAAAA")


if __name__ == "__main__":
    unittest.main()
