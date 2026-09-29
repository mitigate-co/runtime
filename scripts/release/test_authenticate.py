"""Test the publisher-policy wrapper; mocked CLI success is not signature proof."""

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import authenticate as auth

COMMIT = "a" * 40
TAG = "v0.1.0"


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mitigate-auth-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "candidate.zip"
        self.bundle = self.root / "attestation.jsonl"
        self.artifact.write_bytes(b"synthetic candidate, never an executable")
        self.bundle.write_text('{"synthetic":true}', encoding="utf-8")

    def verified(self, commit=COMMIT, tag=TAG):
        return auth.authenticated_snapshot(self.artifact, self.bundle, commit, tag)

    def test_identity_is_exact_and_cannot_be_weakened_by_caller_environment(self):
        with patch.dict(
            os.environ,
            {
                "GH_HOST": "elsewhere.example",
                "GH_DEBUG": "api",
                "SIGSTORE_ROOT_FILE": "untrusted-root.json",
                "PRIVATE_WORKLOAD": "canary",
            },
        ):
            with patch.object(auth.subprocess, "run") as run:
                run.return_value.returncode = 0
                with self.verified() as verified:
                    (command,) = run.call_args.args
                    self.assertEqual(command[:3], ["gh", "attestation", "verify"])
                    self.assertEqual(Path(command[3]), verified.path)
                    options = dict(zip(command[4:-1:2], command[5:-1:2]))
                    self.assertEqual(command[-1], "--deny-self-hosted-runners")
                    self.assertEqual(
                        options,
                        {
                            "--bundle": str(verified.path.parent / "bundle.jsonl"),
                            "--hostname": "github.com",
                            "--repo": "mitigate-co/runtime",
                            "--signer-repo": "mitigate-co/runtime",
                            "--signer-workflow": "mitigate-co/runtime/.github/workflows/release.yml",
                            "--signer-digest": COMMIT,
                            "--source-digest": COMMIT,
                            "--source-ref": "refs/tags/v0.1.0",
                            "--cert-identity": "https://github.com/mitigate-co/runtime/.github/workflows/release.yml@refs/tags/v0.1.0",
                            "--cert-oidc-issuer": "https://token.actions.githubusercontent.com",
                            "--predicate-type": "https://slsa.dev/provenance/v1",
                            "--digest-alg": "sha256",
                        },
                    )
                    kwargs = run.call_args.kwargs
                    self.assertEqual(kwargs["timeout"], 45)
                    self.assertFalse(kwargs["check"])
                    for pipe in ("stdin", "stdout", "stderr"):
                        self.assertEqual(kwargs[pipe], subprocess.DEVNULL)
                    self.assertNotIn("shell", kwargs)
                    self.assertEqual(kwargs["env"]["GH_HOST"], "github.com")
                    self.assertNotIn("GH_DEBUG", kwargs["env"])
                    self.assertNotIn("SIGSTORE_ROOT_FILE", kwargs["env"])
                    self.assertNotIn("PRIVATE_WORKLOAD", kwargs["env"])
                    self.assertEqual(kwargs["env"]["GH_PROMPT_DISABLED"], "1")

    def test_consumer_uses_verified_snapshot_even_if_original_is_replaced(self):
        original = self.artifact.read_bytes()

        def changed(command, **_kwargs):
            self.artifact.write_bytes(b"replacement must never be consumed")
            self.bundle.write_bytes(b"replacement bundle")
            self.assertEqual(Path(command[3]).read_bytes(), original)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(auth.subprocess, "run", side_effect=changed):
            with self.verified() as verified:
                copied = verified.path
                self.assertEqual(copied.read_bytes(), original)
                self.assertEqual(verified.sha256, hashlib.sha256(original).hexdigest())
                self.assertEqual(verified.size, len(original))
                self.assertNotEqual(copied.parent, self.root)
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
                    self.assertEqual(stat.S_IMODE(copied.parent.stat().st_mode), 0o700)
            self.assertFalse(copied.exists())

    def test_wrong_version_revision_and_malformed_identity_fail_before_cli(self):
        for commit, tag in [
            ("a" * 39, TAG),
            (COMMIT.upper(), TAG),
            (COMMIT, "latest"),
            (COMMIT, "v01.0.0"),
            (COMMIT, "v0.1.0;echo unsafe"),
            (COMMIT, "v" + "1" * 64 + ".0.0"),
        ]:
            with self.subTest(commit=commit, tag=tag), patch.object(
                auth.subprocess, "run"
            ) as run:
                with self.assertRaisesRegex(auth.VerificationError, "^invalid_source$"):
                    with self.verified(commit, tag):
                        self.fail("invalid source yielded bytes")
                run.assert_not_called()

    def test_missing_empty_oversize_and_nonregular_inputs_never_reach_verifier(self):
        for which, category in [
            ("artifact", "artifact_input"),
            ("bundle", "attestation_input"),
        ]:
            source = getattr(self, which)
            original = source.read_bytes()
            for content in [None, b"", b"x" * 65]:
                with self.subTest(
                    which=which, size=None if content is None else len(content)
                ):
                    if source.exists():
                        source.unlink()
                    if content is not None:
                        source.write_bytes(content)
                    with patch.object(auth, "MAX_ARTIFACT", 64), patch.object(
                        auth, "MAX_BUNDLE", 64
                    ):
                        with patch.object(auth.subprocess, "run") as run:
                            with self.assertRaisesRegex(
                                auth.VerificationError, "^" + category + "$"
                            ):
                                with self.verified():
                                    self.fail("bad input yielded bytes")
                            run.assert_not_called()
            source.unlink()
            source.mkdir()
            with self.assertRaisesRegex(auth.VerificationError, "^" + category + "$"):
                with self.verified():
                    self.fail("directory yielded bytes")
            source.rmdir()
            source.write_bytes(original)

    def test_symlinks_are_not_release_inputs(self):
        link = self.root / "linked.zip"
        try:
            link.symlink_to(self.artifact)
        except OSError:
            self.skipTest("OS does not allow a test symlink")
        self.artifact = link
        with patch.object(auth.subprocess, "run") as run:
            with self.assertRaisesRegex(auth.VerificationError, "^artifact_input$"):
                with self.verified():
                    self.fail("symlink yielded bytes")
            run.assert_not_called()

    def test_file_replacement_between_stat_and_open_is_refused(self):
        open_file = os.open

        def replace(path, flags, *args, **kwargs):
            if Path(path) == self.artifact:
                self.artifact.rename(self.root / "original.zip")
                self.artifact.write_bytes(b"substituted regular file")
            return open_file(path, flags, *args, **kwargs)

        with patch.object(auth.os, "open", side_effect=replace):
            with patch.object(auth.subprocess, "run") as run:
                with self.assertRaisesRegex(auth.VerificationError, "^artifact_input$"):
                    with self.verified():
                        self.fail("switched file yielded bytes")
                run.assert_not_called()

    def test_growth_after_initial_size_check_cannot_exceed_read_budget(self):
        open_file = os.open

        def grow(path, flags, *args, **kwargs):
            if Path(path) == self.artifact:
                with self.artifact.open("ab") as stream:
                    stream.write(b"x" * 256)
            return open_file(path, flags, *args, **kwargs)

        with patch.object(auth, "MAX_ARTIFACT", 64), patch.object(
            auth.os, "open", side_effect=grow
        ):
            with patch.object(auth.subprocess, "run") as run:
                with self.assertRaisesRegex(auth.VerificationError, "^artifact_input$"):
                    with self.verified():
                        self.fail("growing file yielded bytes")
                run.assert_not_called()

    def test_reparse_points_are_refused_even_when_mode_is_regular(self):
        class Reparse:
            st_mode = stat.S_IFREG | 0o600
            st_file_attributes = 0x400

        with patch.object(
            auth.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True
        ):
            self.assertFalse(auth.regular(Reparse()))

    def test_nonzero_missing_cli_and_timeout_never_yield_verified_bytes(self):
        cases = [subprocess.CompletedProcess([], code) for code in (1, 2, 130)]
        cases += [
            FileNotFoundError("private-path"),
            subprocess.TimeoutExpired("private-command", 45),
        ]
        for failure in cases:
            with self.subTest(failure=type(failure).__name__):
                kwargs = (
                    {"side_effect": failure}
                    if isinstance(failure, Exception)
                    else {"return_value": failure}
                )
                category = (
                    "verification_unavailable"
                    if isinstance(failure, Exception)
                    else "verification_failed"
                )
                with patch.object(auth.subprocess, "run", **kwargs):
                    with self.assertRaisesRegex(
                        auth.VerificationError, "^" + category + "$"
                    ):
                        with self.verified():
                            self.fail("failed verification yielded bytes")

    def test_cli_report_contains_no_paths_provider_text_or_install_authority(self):
        args = [
            "authenticate.py",
            str(self.artifact),
            "--bundle",
            str(self.bundle),
            "--commit",
            COMMIT,
            "--tag",
            TAG,
        ]
        for code in (0, 1):
            with patch("sys.argv", args), patch(
                "sys.stdout", new_callable=io.StringIO
            ) as output:
                with patch.object(
                    auth.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], code),
                ):
                    self.assertEqual(auth.main(), 0 if code == 0 else 2)
                result = json.loads(output.getvalue())
            self.assertEqual(result["publisher_verified"], code == 0)
            self.assertNotIn(str(self.root), json.dumps(result))
            self.assertNotIn("production_ready", result)
            self.assertNotIn("installed", result)
            if code == 1:
                self.assertEqual(result["error"], "verification_failed")

    def test_consumer_exception_cleans_up_private_snapshot(self):
        with patch.object(
            auth.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic consumer failure"):
                with self.verified() as verified:
                    copied = verified.path
                    raise RuntimeError("synthetic consumer failure")
            self.assertFalse(copied.parent.exists())


if __name__ == "__main__":
    unittest.main()
