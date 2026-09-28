"""Local approval CLI contract; all references are synthetic, no tool is invoked."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile

cli = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(__file__).resolve().parents[1]
fixture = json.loads((root / "examples/approvals/context.json").read_text())
canary = "approval-raw-content-canary"


def run(*args, expected=0, machine=True):
    result = subprocess.run([str(cli), "mcp", "approvals", *map(str, args), *(["--json"] if machine else [])],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == expected, "unexpected approval CLI exit"
    assert canary not in result.stdout + result.stderr, "approval input leaked"
    if expected:
        assert not result.stdout, "partial output on rejection"
        error = json.loads(result.stderr)
        assert error["error"].startswith(("approval_", "cli_")), "unexpected error contract"
        return error
    assert not result.stderr, "success wrote stderr"
    return json.loads(result.stdout) if machine else result.stdout


with tempfile.TemporaryDirectory(prefix="mitigate-approvals-cli-") as tmp:
    directory = pathlib.Path(tmp)
    db, context = directory / "approvals.db", directory / "context.json"
    context.write_text(json.dumps(fixture), encoding="utf-8")
    assert run("init", "--db", db)["action"] == "approval_store_created"
    assert run("list", "--db", db) == {"schema_version": 1, "records": []}
    run("init", "--db", db, expected=2)
    request = run("request", "--db", db, "--context", context)
    ref = request["approval_ref"]
    assert request["state"] == "requested" and request["decisions"] == []
    assert request["expires_at_ms"] - request["created_at_ms"] == 60000
    assert request["binding"]["principal"] is None
    assert request["binding"]["policy_version"] == 1
    assert len(ref) == 64 and ref != fixture["call_ref"]
    run("request", "--db", db, "--context", context, expected=2)
    assert run("show", "--db", db, "--reference", ref)["state"] == "requested"
    assert "No tool invoked" in run("show", "--db", db, "--reference", ref, machine=False)
    run("approve", "--db", db, "--reference", ref, "--operator-ref", "e" * 64, expected=2)
    assert run("show", "--db", db, "--reference", ref)["state"] == "requested"
    approved = run("approve", "--db", db, "--reference", ref, "--operator-ref", "e" * 64, "--confirm")
    assert approved["state"] == "approved"
    assert approved["decisions"][0]["source"] == "declared_local"
    assert approved["decisions"][0]["operator_ref"] == "e" * 64
    run("approve", "--db", db, "--reference", ref, "--operator-ref", "e" * 64, "--confirm", expected=2)
    denied = run("deny", "--db", db, "--reference", ref, "--operator-ref", "f" * 64, "--confirm")
    assert denied["state"] == "denied"
    assert [d["choice"] for d in denied["decisions"]] == ["approve", "deny"]
    assert denied["decisions"][0]["operator_ref"] == "e" * 64
    assert denied["decisions"][1]["operator_ref"] == "f" * 64
    run("approve", "--db", db, "--reference", ref, "--operator-ref", "e" * 64, "--confirm", expected=2)
    assert run("list", "--db", db)["records"][0]["state"] == "denied"
    for field, value in [("arguments", {"secret": canary}), ("results", canary), ("metadata", canary),
                         ("client", None), ("policy_version", 0), ("capabilities", [])]:
        invalid = copy.deepcopy(fixture)
        invalid[field] = value
        context.write_text(json.dumps(invalid), encoding="utf-8")
        run("request", "--db", db, "--context", context, expected=2)
    context.write_text(json.dumps(fixture), encoding="utf-8")
    for seconds in [0, 301]:
        run("request", "--db", db, "--context", context, "--expires-in-seconds", seconds, expected=2)
    run("show", "--db", db, "--reference", canary, expected=2)
    run("show", "--db", db, "--reference", "0" * 64, expected=2)
    run("list", "--db", directory / "missing.db", expected=2)
    run("list", "--db", directory, expected=2)
    assert canary.encode() not in db.read_bytes(), "rejected content reached local database"

print("Approval CLI contract passed: request, review, approval, revocation, restart and privacy.")
