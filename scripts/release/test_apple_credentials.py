"""Synthetic protected-environment inputs; never imports or uses a real key."""

import base64
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import apple_credentials as credentials
from authenticate import VerificationError


def inputs():
    return {
        "APPLE_CERTIFICATE_P12_BASE64": base64.b64encode(
            b"synthetic certificate"
        ).decode(),
        "APPLE_CERTIFICATE_PASSWORD": "synthetic-import-password",
        "APPLE_NOTARY_KEY_P8_BASE64": base64.b64encode(
            b"synthetic notary key"
        ).decode(),
        "APPLE_NOTARY_KEY_ID": "A" * 10,
        "APPLE_NOTARY_ISSUER_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "APPLE_SIGNING_IDENTITY": "1" * 40,
        "APPLE_TEAM_ID": "B" * 10,
    }


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {**inputs(), "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_JOB": "sign"},
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.platform = patch.object(
            credentials.platform, "system", return_value="Darwin"
        )
        self.platform.start()
        self.addCleanup(self.platform.stop)

    def test_consumed_inputs_do_not_remain_in_child_environment(self):
        values = inputs()
        decoded = credentials.consume(values)
        self.assertEqual(values, {})
        self.assertEqual(
            decoded["APPLE_CERTIFICATE_P12_BASE64"], b"synthetic certificate"
        )
        self.assertEqual(decoded["APPLE_NOTARY_KEY_P8_BASE64"], b"synthetic notary key")

    def test_missing_or_invalid_inputs_are_all_consumed_before_failure(self):
        for key, value in (
            ("APPLE_TEAM_ID", "invalid"),
            ("APPLE_NOTARY_ISSUER_ID", "--option"),
            ("APPLE_SIGNING_IDENTITY", "-"),
            ("APPLE_NOTARY_KEY_ID", "bad"),
            ("APPLE_CERTIFICATE_PASSWORD", "bad\x00password"),
            ("APPLE_CERTIFICATE_PASSWORD", "x" * 4097),
            ("APPLE_CERTIFICATE_P12_BASE64", "not-base64"),
            ("APPLE_NOTARY_KEY_P8_BASE64", ""),
            ("APPLE_NOTARY_KEY_P8_BASE64", "x" * 100000),
            ("APPLE_TEAM_ID", None),
        ):
            values = inputs()
            values[key] = value
            with self.subTest(key=key), self.assertRaises(VerificationError):
                credentials.consume(values)
            self.assertEqual(values, {})

    def test_public_references_only_and_cleanup_after_success(self):
        commands = []

        def invoke(command, *_args):
            commands.append(command)
            self.assertFalse(credentials.INPUTS & set(os.environ))
            if command[1] == "import":
                path = Path(command[2])
                self.assertEqual(path.read_bytes(), b"synthetic certificate")
                if os.name != "nt":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            if command[1] == "notarytool":
                self.assertEqual(Path(command[5]).read_bytes(), b"synthetic notary key")

        with patch.object(credentials, "invoke", side_effect=invoke):
            with credentials.prepared_keychain(os.environ) as references:
                root = references["keychain"].parent
                self.assertEqual(
                    set(references), {"identity", "team", "keychain", "profile"}
                )
                self.assertFalse((root / "certificate.p12").exists())
                self.assertFalse((root / "notary.p8").exists())
                self.assertEqual(references["profile"], "mitigate-release")
            self.assertFalse(root.exists())
        self.assertEqual(
            commands[-1],
            ["/usr/bin/security", "delete-keychain", str(references["keychain"])],
        )
        self.assertEqual(len(commands), 7)
        self.assertFalse(
            any("default-keychain" in c or "list-keychains" in c for c in commands)
        )

    def test_every_native_setup_failure_still_attempts_cleanup(self):
        for failing_step in range(6):
            calls = []

            def invoke(command, *_args):
                calls.append(command)
                if len(calls) == failing_step + 1:
                    raise VerificationError("synthetic_setup_failure")

            with patch.dict(os.environ, inputs()), patch.object(
                credentials, "invoke", side_effect=invoke
            ):
                with self.assertRaisesRegex(
                    VerificationError, "^synthetic_setup_failure$"
                ):
                    with credentials.prepared_keychain(os.environ):
                        self.fail("setup should not reach signing")
            self.assertEqual(calls[-1][1], "delete-keychain")
            self.assertFalse(Path(calls[-1][2]).parent.exists())

    def test_signer_failure_still_deletes_owned_keychain(self):
        with patch.object(credentials, "invoke") as invoke:
            with self.assertRaisesRegex(VerificationError, "signer_failed"):
                with credentials.prepared_keychain(os.environ):
                    raise VerificationError("signer_failed")
            self.assertEqual(invoke.call_args.args[0][1], "delete-keychain")

    def test_cleanup_failure_prevents_success(self):
        def invoke(command, *_args):
            if command[1] == "delete-keychain":
                raise VerificationError("apple_keychain_cleanup")

        with patch.object(credentials, "invoke", side_effect=invoke):
            with self.assertRaisesRegex(VerificationError, "apple_keychain_cleanup"):
                with credentials.prepared_keychain(os.environ):
                    pass

    def test_non_hosted_or_wrong_job_never_reads_credentials_or_calls_tools(self):
        for change in ({"GITHUB_JOB": "build"}, {"RUNNER_ENVIRONMENT": "self-hosted"}):
            with patch.dict(os.environ, change), patch.object(
                credentials, "consume"
            ) as consume, patch.object(credentials, "invoke") as invoke:
                with self.assertRaisesRegex(
                    VerificationError, "apple_credentials_context"
                ):
                    with credentials.prepared_keychain(os.environ):
                        pass
                consume.assert_not_called()
                invoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
