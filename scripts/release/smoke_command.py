"""Closed process timing for trusted candidate fixtures, never command output."""

import json
import subprocess
import time

STEPS = {"version", "config", "scan", "privacy", "egress", "invalid_config"}


def run(executable, step, arguments, directory, environment):
    if step not in STEPS:
        raise ValueError("Unknown packaged CLI check")
    started = time.monotonic()

    def report(outcome):
        print(json.dumps({
            "check": "packaged_cli",
            "step": step,
            "outcome": outcome,
            "elapsed_ms": min(120_000, max(0, int((time.monotonic() - started) * 1000))),
        }), flush=True)

    try:
        result = subprocess.run(
            [str(executable), *arguments, "--json"],
            cwd=directory, env=environment, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        report("timeout")
        raise ValueError("Packaged CLI command timed out") from None
    except OSError:
        report("unavailable")
        raise ValueError("Packaged CLI command unavailable") from None
    # Exited is process completion, not a passing CLI/JSON/privacy assertion.
    report("exited")
    return result
