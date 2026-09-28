"""Actual local control CLI contracts; synthetic metadata, no upstream calls."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile

cli = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(__file__).resolve().parents[1]
context_fixture = json.loads((root / "examples/controls/context.json").read_text())
canary = "control-raw-content-canary"
operator = "e" * 64


def run(*args, expected=0, machine=True):
    result = subprocess.run([str(cli), "mcp", "controls", *map(str, args), *(["--json"] if machine else [])],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == expected, "unexpected controls CLI exit"
    assert canary not in result.stdout + result.stderr, "control input leaked"
    if expected:
        assert not result.stdout, "partial success output"
        error = json.loads(result.stderr)
        assert error["error"].startswith(("control_", "cli_")), "unexpected error contract"
        return error
    assert not result.stderr, "success wrote stderr"
    return json.loads(result.stdout) if machine else result.stdout


with tempfile.TemporaryDirectory(prefix="mitigate-controls-cli-") as tmp:
    directory = pathlib.Path(tmp)
    db, context, change = directory / "controls.db", directory / "context.json", directory / "change.json"
    context.write_text(json.dumps(context_fixture), encoding="utf-8")
    initial = run("init", "--db", db)
    assert initial == {"schema_version": 1, "revision": 0, "emergency_stop": False, "disabled": [], "limits": []}
    run("init", "--db", db, expected=2)
    admin = ["--db", db, "--operator-ref", operator]
    assert "--confirm" in run("stop", *admin, expected=2)["message"]
    run("resume", *admin, expected=2)
    assert run("status", "--db", db) == initial
    assert run("stop", *admin, "--confirm")["emergency_stop"]
    stopped = run("test", "--db", db, "--context", context)
    assert stopped["mode"] == "preview" and stopped["result"]["decision"] == "disabled"
    assert run("resume", *admin, "--confirm")["revision"] == 2
    change.write_text((root / "examples/controls/limit.json").read_text(), encoding="utf-8")
    run("apply", *admin, "--change", change, expected=2)
    assert run("apply", *admin, "--change", change, "--confirm")["revision"] == 3
    assert run("apply", *admin, "--change", change, "--confirm")["revision"] == 3, "no-op edit changed revision"
    assert "No quota consumed or tool invoked" in run("test", "--db", db, "--context", context, machine=False)
    for _ in range(12):
        assert run("test", "--db", db, "--context", context)["result"]["decision"] == "allowed", "preview consumed quota"
    change.write_text((root / "examples/controls/disable.json").read_text(), encoding="utf-8")
    assert len(run("apply", *admin, "--change", change, "--confirm")["disabled"]) == 1
    assert run("test", "--db", db, "--context", context)["result"]["decision"] == "disabled"
    history = run("history", "--db", db)["changes"]
    assert [h["revision"] for h in history] == [1, 2, 3, 4]
    assert all(h["operator_ref"] == operator and h["source"] == "declared_local" for h in history)
    assert "Declared local operator" in run("history", "--db", db, machine=False)
    for bad in [
        {"action": "stop", "metadata": canary},
        {"action": "resume", "arguments": canary},
        {"action": "disable", "target": {"kind": "server", "reference": canary}},
        {"action": "set_limit", "target": {"kind": "global", "metadata": canary},
         "rate": {"capacity": 1, "refill_tokens": 1, "period_ms": 1}},
        {"action": "set_limit", "target": {"kind": "global"},
         "rate": {"capacity": 1, "refill_tokens": 0, "period_ms": 1}},
    ]:
        change.write_text(json.dumps(bad), encoding="utf-8")
        run("apply", *admin, "--change", change, "--confirm", expected=2)
    for field in ["arguments", "result", "metadata", "token"]:
        bad = copy.deepcopy(context_fixture)
        bad[field] = canary
        context.write_text(json.dumps(bad), encoding="utf-8")
        run("test", "--db", db, "--context", context, expected=2)
    run("stop", "--db", db, "--operator-ref", canary, "--confirm", expected=2)
    run("status", "--db", directory / canary, expected=2)
    assert run("status", "--db", db)["revision"] == 4
    assert canary.encode() not in db.read_bytes(), "rejected content persisted"

print("Control CLI passed: stop/resume, exact disables, quota configuration, restart, confirmation and privacy.")
