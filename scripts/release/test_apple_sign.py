"""Native command contract with a mocked Apple boundary; no real signing keys."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import apple_sign
from authenticate import VerificationError

IDENTITY = "1" * 40
TEAM = "A" * 10
SUBMISSION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class AppleSignTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mitigate-apple-sign-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "mitigate"
        self.binary.write_bytes(b"synthetic binary, not executable code")
        self.keychain = self.root / "synthetic.keychain-db"
        self.keychain.write_bytes(b"synthetic keychain, no secrets")
        self.platform = patch.object(
            apple_sign.platform, "system", return_value="Darwin"
        )
        self.platform.start()
        self.addCleanup(self.platform.stop)

    def sign(self, **kwargs):
        values = dict(
            identity=IDENTITY,
            team=TEAM,
            keychain=self.keychain,
            profile="release-notary",
        )
        values.update(kwargs)
        apple_sign.sign_and_notarize(self.binary, **values)

    def accepted(self):
        return subprocess.CompletedProcess(
            [], 0, json.dumps({"status": "Accepted", "id": SUBMISSION}).encode(), b""
        )

    def test_fixed_commands_isolate_credentials_and_verify_notarized_result(self):
        def run(command, **_kwargs):
            if command[0] == "/usr/bin/codesign":
                self.binary.write_bytes(b"synthetic signed bytes")
            return self.accepted()

        with patch.dict(
            os.environ,
            {
                "PRIVATE_WORKLOAD_SECRET": "private-secret-canary",
                "DYLD_INSERT_LIBRARIES": "/private/hook",
                "DEVELOPER_DIR": "/private/tools",
            },
        ), patch.object(
            apple_sign.subprocess, "run", side_effect=run
        ) as execute, patch.object(
            apple_sign.apple_verify, "verify"
        ) as verify:
            self.sign()
        signing, notary = execute.call_args_list
        self.assertEqual(
            signing.args[0],
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                IDENTITY,
                "--keychain",
                str(self.keychain),
                "--identifier",
                "co.mitigate.runtime",
                "--options",
                "runtime",
                "--timestamp",
                str(self.binary),
            ],
        )
        self.assertEqual(
            notary.args[0],
            [
                "/usr/bin/xcrun",
                "notarytool",
                "submit",
                str(self.root / "notary-submission.zip"),
                "--keychain-profile",
                "release-notary",
                "--keychain",
                str(self.keychain),
                "--wait",
                "--timeout",
                "15m",
                "--output-format",
                "json",
            ],
        )
        self.assertEqual(notary.kwargs["timeout"], 16 * 60)
        for call in execute.call_args_list:
            env = call.kwargs["env"]
            self.assertEqual(env["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
            self.assertTrue(set(env) <= {"HOME", "TMPDIR", "LANG", "LC_ALL", "PATH"})
            self.assertEqual(call.kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(call.kwargs["stderr"], subprocess.DEVNULL)
        with zipfile.ZipFile(self.root / "notary-submission.zip") as archive:
            self.assertEqual(archive.namelist(), ["mitigate"])
            self.assertEqual(archive.read("mitigate"), b"synthetic signed bytes")
        verify.assert_called_once_with(self.binary, TEAM)

    def test_bad_identity_profile_team_or_keychain_never_invokes_a_tool(self):
        for change in (
            {"identity": "Developer ID name"},
            {"identity": "-"},
            {"identity": "1" * 41},
            {"team": "UNKNOWN"},
            {"profile": "--other"},
            {"profile": "x\nsecret"},
            {"keychain": Path("relative.keychain")},
            {"keychain": self.root},
            {"keychain": self.root / "missing"},
        ):
            with self.subTest(change=change), patch.object(
                apple_sign.subprocess, "run"
            ) as run:
                with self.assertRaises(VerificationError):
                    self.sign(**change)
                run.assert_not_called()

    def test_non_apple_host_fails_without_tools(self):
        with patch.object(
            apple_sign.platform, "system", return_value="Linux"
        ), patch.object(apple_sign.subprocess, "run") as run:
            with self.assertRaisesRegex(VerificationError, "apple_signing_platform"):
                self.sign()
            run.assert_not_called()

    def test_signing_error_missing_tool_and_timeout_never_upload(self):
        for value in (
            FileNotFoundError("private-path-canary"),
            subprocess.TimeoutExpired("secret", 120),
            subprocess.CompletedProcess(
                [], 1, b"private-secret-canary", b"private-error-canary"
            ),
        ):
            with patch.object(
                apple_sign.subprocess,
                "run",
                side_effect=value if isinstance(value, Exception) else None,
                return_value=value,
            ) as run:
                with self.assertRaisesRegex(
                    VerificationError, "^apple_signing_failed$"
                ):
                    self.sign()
                self.assertEqual(run.call_count, 1)
        self.assertFalse((self.root / "notary-submission.zip").exists())

    def test_invalid_pending_rejected_duplicate_and_oversized_notary_results_block(
        self,
    ):
        for response in (
            b"not json private-canary",
            b"[]",
            b'{"status":"In Progress"}',
            b'{"status":"Rejected"}',
            b'{"status":"Accepted","id":"bad"}',
            b'{"status":"Accepted","status":"Rejected"}',
            b"x" * (16 * 1024 + 1),
            b"\xff",
            b"",
        ):
            submission = self.root / "notary-submission.zip"
            if submission.exists():
                submission.unlink()
            with patch.object(
                apple_sign.subprocess,
                "run",
                side_effect=[
                    self.accepted(),
                    subprocess.CompletedProcess([], 0, response, b"private-canary"),
                ],
            ), patch.object(apple_sign.apple_verify, "verify") as verify:
                with self.assertRaisesRegex(
                    VerificationError, "^apple_notarization_failed$"
                ):
                    self.sign()
                verify.assert_not_called()

    def test_notary_timeout_and_native_trust_failure_do_not_return_success(self):
        with patch.object(
            apple_sign.subprocess,
            "run",
            side_effect=[self.accepted(), subprocess.TimeoutExpired("notarytool", 960)],
        ):
            with self.assertRaisesRegex(
                VerificationError, "^apple_notarization_failed$"
            ):
                self.sign()
        (self.root / "notary-submission.zip").unlink()
        with patch.object(
            apple_sign.subprocess, "run", return_value=self.accepted()
        ), patch.object(
            apple_sign.apple_verify,
            "verify",
            side_effect=VerificationError("apple_verification_failed"),
        ):
            with self.assertRaisesRegex(
                VerificationError, "^apple_verification_failed$"
            ):
                self.sign()


if __name__ == "__main__":
    unittest.main()
