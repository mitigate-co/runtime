"""Review/check and inventory gateway contracts with synthetic local code only."""
import copy
import json
import os
import pathlib
import queue
import subprocess
import sys
import tempfile
import threading

cli = pathlib.Path(sys.argv[1]).resolve()
fixture = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
canary = "launch-review-content-canary"


def run(*args, expected=0, environment=None):
    result = subprocess.run([str(cli), *map(str, args), "--json"], capture_output=True,
                            text=True, timeout=45, env=environment)
    assert result.returncode == expected, "unexpected launch-review CLI exit"
    assert canary not in result.stdout + result.stderr, "launch input leaked"
    if expected:
        assert not result.stdout, "partial output on rejected review"
        return json.loads(result.stderr)
    assert not result.stderr, "success wrote stderr"
    return json.loads(result.stdout)


with tempfile.TemporaryDirectory(prefix="mitigate-launch-cli-") as tmp:
    directory = pathlib.Path(tmp)
    executable, artifact = directory / "synthetic.exe", directory / "entry.js"
    executable.write_bytes(b"synthetic non-executed binary")
    artifact.write_text(canary, encoding="utf-8")
    config, review = directory / "launch.json", directory / "review.json"
    value = {"schema_version": 1, "executable_path": str(executable), "working_directory": str(directory),
             "argv": [canary], "artifact_paths": [str(artifact)],
             "allowed_environment_keys": ["MITIGATE_REVIEW_FIXTURE_VALUE"]}
    config.write_text(json.dumps(value), encoding="utf-8")
    environment = {**os.environ, "MITIGATE_REVIEW_FIXTURE_VALUE": canary}
    receipt = run("mcp", "launch", "review", "--launch-config", config, "--out", review, environment=environment)
    assert receipt["artifact_count"] == 1 and len(receipt["launch_ref"]) == 64
    assert canary not in review.read_text(), "configuration persisted in review"
    assert "salt" not in receipt
    assert run("mcp", "launch", "check", "--launch-config", config, "--review", review, environment=environment) == receipt
    run("mcp", "launch", "review", "--launch-config", config, "--out", review, environment=environment, expected=2)
    assert run("mcp", "launch", "check", "--launch-config", config, "--review", review,
               environment={**environment, "MITIGATE_REVIEW_FIXTURE_VALUE": "changed"}, expected=2)["error"] == "mcp_launch_changed"
    # Native values are never read by review; reference changes are still bound.
    changed = copy.deepcopy(value)
    changed["secret_references"] = [{"environment_key": "KEY", "secret_ref": "sec_0123456789abcdef0123456789abcdef"}]
    config.write_text(json.dumps(changed), encoding="utf-8")
    run("mcp", "launch", "check", "--launch-config", config, "--review", review, environment=environment, expected=2)
    config.write_text(json.dumps(value), encoding="utf-8")
    artifact.write_text("modified code", encoding="utf-8")
    assert run("mcp", "launch", "check", "--launch-config", config, "--review", review, environment=environment, expected=2)["error"] == "mcp_launch_changed"
    assert canary not in json.dumps(run("mcp", "launch", "check", "--launch-config", config,
                                       "--review", directory / canary, environment=environment, expected=2))
    if hasattr(os, "mkfifo"):
        fifo = directory / "not-code.fifo"
        os.mkfifo(fifo)
        invalid = copy.deepcopy(value)
        invalid["artifact_paths"] = [str(fifo)]
        config.write_text(json.dumps(invalid), encoding="utf-8")
        run("mcp", "launch", "review", "--launch-config", config, "--out", directory / "fifo-review.json",
            environment=environment, expected=2)

    if fixture:
        artifact.write_text("synthetic reviewed code", encoding="utf-8")
        value = {"schema_version": 1, "executable_path": str(fixture), "working_directory": str(directory),
                 "argv": ["relay", str(directory / "child-address"), str(directory / "call-marker")],
                 "artifact_paths": [str(artifact)], "timeout_ms": 30000}
        config.write_text(json.dumps(value), encoding="utf-8")
        active = directory / "active-review.json"
        receipt = run("mcp", "launch", "review", "--launch-config", config, "--out", active)
        audit = directory / "audit.db"
        run("mcp", "audit", "init", "--db", audit)
        process = subprocess.Popen([str(cli), "mcp", "serve", "--launch-config", str(config),
                                    "--launch-review", str(active), "--allow-exec", "--inventory-only", "--audit-db", str(audit)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        responses = queue.Queue(maxsize=8)

        def receive():
            try:
                for line in process.stdout:
                    responses.put(line, timeout=2)
            finally:
                responses.put(None, timeout=2)

        thread = threading.Thread(target=receive, daemon=True)
        thread.start()

        def send(message):
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()

        def response():
            line = responses.get(timeout=40)
            assert line and canary not in line, "missing or unsafe gateway response"
            return json.loads(line)

        try:
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}})
            assert "result" in response()
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            assert response()["result"]["tools"][0]["name"] == "read_status"
            send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_status", "arguments": {}}})
            assert response()["error"]["code"] == -32006, "inventory mode allowed a call"
            artifact.write_text("changed while connected", encoding="utf-8")
            send({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}})
            assert response()["error"]["code"] == -32004, "code drift was not detected"
            assert not (directory / "call-marker").exists()
            process.stdin.close()
            process.wait(timeout=10)
            assert process.returncode == 0 and not process.stderr.read(), "gateway exit failed"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            for pipe in [process.stdin, process.stdout, process.stderr]:
                pipe.close()
            thread.join(timeout=2)
        history = run("mcp", "audit", "list", "--db", audit)
        assert receipt["launch_ref"] in json.dumps(history), "reviewed launch identity missing from audit"

print("Launch review CLI passed: private binding, environment drift, code drift, denied calls and audited identity.")
