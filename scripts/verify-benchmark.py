#!/usr/bin/env python3
"""Check the real synthetic harness and its export contract, never timing SLOs."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

CASES = [
    "canonicalize_32_fields",
    "fingerprint_32_fields",
    "scan_1_server",
    "scan_32_servers",
    "scan_128_servers",
    "policy_compile",
    "policy_evaluate",
    "egress_validate_decision",
    "audit_append_growing_history",
    "direct_stdio_roundtrip",
    "classify_one_tool",
    "managed_stdio_roundtrip",
    "listener_managed_stdio_roundtrip",
]


def invoke(binary, args, root, env, deadline):
    # Only a trusted locally built fixture is accepted. Own its process group so
    # an outer timeout also terminates synthetic children before workspace cleanup.
    with subprocess.Popen(
        [str(binary), "benchmark", *args],
        cwd=root,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    ) as child:
        try:
            stdout, stderr = child.communicate(timeout=deadline)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(
                    [
                        str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                        "/T",
                        "/F",
                        "/PID",
                        str(child.pid),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                os.killpg(child.pid, signal.SIGKILL)
            child.kill()
            child.communicate(timeout=5)
            raise AssertionError(
                "synthetic benchmark exceeded the process deadline"
            ) from None
        return subprocess.CompletedProcess([], child.returncode, stdout, stderr)


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="mitigate-benchmark-contract-") as owned:
        root = Path(owned)
        sentinel = root / "preserved.txt"
        sentinel.write_text("preserve", encoding="utf-8")
        env = {
            key: os.environ[key]
            for key in ("SystemRoot", "WINDIR")
            if key in os.environ
        }
        env.update({"TMPDIR": owned, "TEMP": owned, "TMP": owned})
        result = invoke(binary, ["--samples", "5", "--warmup", "2"], root, env, 180)
        assert (
            result.returncode == 0
        ), "benchmark operation failed; retain closed stdout locally"
        assert result.stderr == b"", "unexpected benchmark stderr"
        assert len(result.stdout) <= 131072, "oversized benchmark report"
        report = json.loads(result.stdout)
        assert set(report) == {
            "schema_version",
            "fixture",
            "runtime_version",
            "os",
            "arch",
            "build",
            "status",
            "harness_failed",
            "cases",
        }
        assert report["schema_version"] == 1
        assert report["fixture"] == "runtime-synthetic-v1"
        assert report["build"] in ("debug", "release")
        assert report["status"] == "ok" and report["harness_failed"] is False
        assert [item["case"] for item in report["cases"]] == CASES
        for item in report["cases"]:
            assert set(item) == {
                "case",
                "status",
                "warmup_requested",
                "warmup_completed",
                "samples_requested",
                "samples_ns",
                "failure",
                "min_ns",
                "median_ns",
                "p95_ns",
                "max_ns",
            }
            assert item["status"] == "ok" and item["failure"] is None
            assert item["samples_requested"] == 5
            assert item["warmup_requested"] == item["warmup_completed"] == 2
            samples = item["samples_ns"]
            assert len(samples) == 5
            assert all(type(n) is int and 0 <= n <= 2**64 - 1 for n in samples)
            ordered = sorted(samples)
            assert [
                item[key] for key in ("min_ns", "median_ns", "p95_ns", "max_ns")
            ] == [ordered[0], ordered[2], ordered[4], ordered[4]]
        assert b"canary" not in result.stdout and b"ref_" not in result.stdout
        assert str(root).encode() not in result.stdout
        assert sentinel.read_text(encoding="utf-8") == "preserve"
        assert list(root.iterdir()) == [
            sentinel
        ], "owned synthetic workspace must be cleaned"
        for args in [("--root", "private"), ("--samples", "501", "--warmup", "0")]:
            invalid = invoke(binary, args, root, env, 5)
            assert invalid.returncode == 2 and invalid.stderr == b""
            assert json.loads(invalid.stdout) == {
                "schema_version": 1,
                "error": "benchmark_arguments",
            }
            assert list(root.iterdir()) == [sentinel]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: verify-benchmark.py PATH_TO_BUILT_FIXTURE")
    verify(Path(sys.argv[1]).resolve(strict=True))
    print(
        "Synthetic benchmark verified: 13 cases, bounded safe output, samples and cleanup; no timing SLO."
    )
