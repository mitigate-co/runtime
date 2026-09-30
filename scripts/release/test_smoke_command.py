"""Synthetic process failures must not expose paths, output or credentials."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import smoke
import smoke_command as command


class SmokeCommandTests(unittest.TestCase):
    def invoke(self):
        return command.run(Path("private-path-canary"), "privacy",
                           ("privacy", "self-test", "--work-dir", "private-work-canary"),
                           Path("private-directory-canary"), {"PATH": "private-env-canary"})

    def test_exited_is_not_success_and_child_data_is_not_projected(self):
        result = subprocess.CompletedProcess([], 2, b"private-output-canary", b"private-error-canary")
        output = io.StringIO()
        with patch.object(command.subprocess, "run", return_value=result) as process, \
                patch.object(command.time, "monotonic", side_effect=[10.0, 11.25]), \
                redirect_stdout(output):
            self.assertIs(self.invoke(), result)
        self.assertEqual(json.loads(output.getvalue()), {
            "check": "packaged_cli", "step": "privacy", "outcome": "exited", "elapsed_ms": 1250,
        })
        self.assertNotIn("canary", output.getvalue())
        self.assertEqual(process.call_count, 1)
        self.assertEqual(process.call_args.kwargs["timeout"], 30)
        self.assertEqual(process.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(process.call_args.kwargs["capture_output"])

    def test_timeout_and_launch_failure_are_fixed_without_retry_or_exception_payload(self):
        for failure, outcome, elapsed in [
            (subprocess.TimeoutExpired("private-command-canary", 30,
                                       output=b"private-output-canary", stderr=b"private-error-canary"),
             "timeout", 30_500),
            (OSError("private-error-canary"), "unavailable", 0),
        ]:
            with self.subTest(outcome=outcome):
                output = io.StringIO()
                with patch.object(command.subprocess, "run", side_effect=failure) as process, \
                        patch.object(command.time, "monotonic", side_effect=[10, 10 + elapsed / 1000]), \
                        redirect_stdout(output), self.assertRaises(ValueError) as caught:
                    self.invoke()
                self.assertEqual(json.loads(output.getvalue()), {
                    "check": "packaged_cli", "step": "privacy", "outcome": outcome, "elapsed_ms": elapsed,
                })
                self.assertEqual(process.call_count, 1)
                self.assertNotIn("canary", str(caught.exception) + output.getvalue())
                self.assertTrue(caught.exception.__suppress_context__)

    def test_diagnostic_duration_is_bounded_and_unknown_step_never_runs(self):
        for end, expected in [(9, 0), (1000, 120_000)]:
            output = io.StringIO()
            with patch.object(command.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                    patch.object(command.time, "monotonic", side_effect=[10, end]), redirect_stdout(output):
                self.invoke()
            self.assertEqual(json.loads(output.getvalue())["elapsed_ms"], expected)
        with patch.object(command.subprocess, "run") as process, self.assertRaises(ValueError):
            command.run(Path("fixture"), "private-step-canary", (), Path("."), {})
        process.assert_not_called()

    def test_privacy_assertions_still_fail_and_stop_later_checks(self):
        replies = [
            {"version": "0.1.0"}, {"valid": True}, {"servers": []},
            {"passed": False, "positive_control": True, "queue_isolation": True,
             "persisted_canaries_absent": True, "network_requests": 0},
        ]
        results = [subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b"") for value in replies]
        with patch.object(smoke, "run_command", side_effect=results) as process, \
                self.assertRaisesRegex(ValueError, "Privacy probe failed"):
            smoke.exercise(Path("unused-synthetic-binary"), "0.1.0")
        self.assertEqual([call.args[1] for call in process.call_args_list],
                         ["version", "config", "scan", "privacy"])


if __name__ == "__main__":
    unittest.main()
