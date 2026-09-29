"""Credential isolation and failure ordering for the protected signing entrypoint."""

from contextlib import contextmanager
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import ci_stage
from authenticate import VerificationError
from test_apple_credentials import inputs
from test_stage_release import COMMIT, TAG, context


class CiStageTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {**context(), **inputs()}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def prepare(self):
        return ci_stage.prepare(
            Path("."), Path("candidate"), COMMIT, TAG, Path("release")
        )

    def test_blocked_gate_cannot_import_a_key_and_never_inherits_credentials(self):
        def blocked(*_args, **_kwargs):
            self.assertFalse(ci_stage.apple_credentials.INPUTS & set(os.environ))
            return {"signing_prerequisites_met": False}

        with patch.object(ci_stage, "signing_gate", side_effect=blocked), patch.object(
            ci_stage.apple_credentials, "prepared_keychain"
        ) as keychain, patch.object(ci_stage, "stage") as stage:
            with self.assertRaisesRegex(VerificationError, "release_signing_gates"):
                self.prepare()
            keychain.assert_not_called()
            stage.assert_not_called()

    def test_cleanup_completes_before_success_returns(self):
        events = []

        @contextmanager
        def keychain(values):
            self.assertFalse(ci_stage.apple_credentials.INPUTS & set(os.environ))
            self.assertEqual(values, inputs())
            events.append("setup")
            yield {
                "identity": "1" * 40,
                "team": "B" * 10,
                "keychain": Path("synthetic"),
                "profile": "mitigate-release",
            }
            events.append("cleanup")

        def stage(*_args, **kwargs):
            events.append("stage")
            self.assertNotIn("APPLE_CERTIFICATE_PASSWORD", kwargs)
            return {"staged": True}

        with patch.object(
            ci_stage, "signing_gate", return_value={"signing_prerequisites_met": True}
        ), patch.object(
            ci_stage, "native_target", return_value="aarch64-apple-darwin"
        ), patch.object(
            ci_stage.apple_credentials, "prepared_keychain", side_effect=keychain
        ), patch.object(
            ci_stage, "stage", side_effect=stage
        ):
            result = self.prepare()
            events.append("returned")
        self.assertEqual(events, ["setup", "stage", "cleanup", "returned"])
        self.assertTrue(result["staged"])

    def test_non_apple_job_rejects_accidental_apple_secret_configuration(self):
        with patch.object(
            ci_stage, "signing_gate", return_value={"signing_prerequisites_met": True}
        ), patch.object(
            ci_stage, "native_target", return_value="x86_64-pc-windows-msvc"
        ), patch.object(
            ci_stage, "stage"
        ) as stage:
            with self.assertRaisesRegex(
                VerificationError, "unexpected_apple_credentials"
            ):
                self.prepare()
            stage.assert_not_called()

    def test_non_apple_job_stages_without_preparing_any_keychain(self):
        for key in ci_stage.apple_credentials.INPUTS:
            os.environ.pop(key)
        with patch.object(
            ci_stage, "signing_gate", return_value={"signing_prerequisites_met": True}
        ), patch.object(
            ci_stage, "native_target", return_value="x86_64-unknown-linux-gnu"
        ), patch.object(
            ci_stage.apple_credentials, "prepared_keychain"
        ) as keychain, patch.object(
            ci_stage, "stage", return_value={"staged": True}
        ) as stage:
            self.assertTrue(self.prepare()["staged"])
            keychain.assert_not_called()
            stage.assert_called_once()


if __name__ == "__main__":
    unittest.main()
