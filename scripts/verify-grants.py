"""Actual-CLI grant contract. Synthetic metadata only; no server is launched."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile

cli = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(__file__).resolve().parents[1]
rules = json.loads((root / "examples/grants/read-development.json").read_text())
context = json.loads((root / "examples/grants/read-context.json").read_text())
canary = "private-grant-fixture-canary"


def run(*args, expected=0, machine=True):
    result = subprocess.run(
        [str(cli), "mcp", "grants", *map(str, args), *(["--json"] if machine else [])],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == expected, "unexpected grant CLI exit"
    assert canary not in result.stdout + result.stderr, "input leaked into a diagnostic"
    if expected:
        assert not result.stdout, "error wrote partial stdout"
        error = json.loads(result.stderr)
        assert error["error"].startswith("grant_"), "unexpected error contract"
        return error
    assert not result.stderr, "successful command wrote stderr"
    return json.loads(result.stdout) if machine else result.stdout


with tempfile.TemporaryDirectory(prefix="mitigate-grants-") as tmp:
    directory = pathlib.Path(tmp)
    rule_path, input_path = directory / "rules.json", directory / "context.json"

    def write(rule_document=rules, input_document=context):
        rule_path.write_text(json.dumps(rule_document), encoding="utf-8")
        input_path.write_text(json.dumps(input_document), encoding="utf-8")

    def evaluate():
        return run("test", "--rules", rule_path, "--input", input_path)

    write()
    assert run("check", "--rules", rule_path) == {"schema_version": 1, "valid": True, "rules": 2}
    expected = {"schema_version": 1, "state": "explicit", "reason": "explicit_allow", "matched_grants": ["a" * 64]}
    assert evaluate() == expected
    assert "No tool invoked" in run("test", "--rules", rule_path, "--input", input_path, machine=False)
    cases = [
        ("client", None, "none", "unknown_client"),
        ("client", "f" * 64, "none", "no_matching_grant"),
        ("server", "f" * 64, "none", "no_matching_grant"),
        ("environment", "production", "none", "no_matching_grant"),
        ("environment", None, "none", "no_matching_grant"),
        ("capabilities", ["read_data", "write_data"], "none", "no_matching_grant"),
        ("capabilities", ["read_data", "delete_data"], "denied", "explicit_deny"),
        ("capabilities", ["credential_access"], "denied", "explicit_deny"),
        ("capabilities", ["unknown"], "none", "no_matching_grant"),
    ]
    for field, value, state, reason in cases:
        changed = copy.deepcopy(context)
        changed[field] = value
        write(input_document=changed)
        result = evaluate()
        assert result["state"] == state and result["reason"] == reason, "scope resolution mismatch"
    reversed_rules = copy.deepcopy(rules)
    reversed_rules["grants"].reverse()
    write(reversed_rules)
    assert evaluate() == expected
    window = copy.deepcopy(rules)
    window["grants"][0]["scope"].update(not_before_ms=1000, expires_at_ms=2000)
    for time, state in [(999, "none"), (1000, "explicit"), (1999, "explicit"), (2000, "none")]:
        changed = copy.deepcopy(context)
        changed["time_ms"] = time
        write(window, changed)
        assert evaluate()["state"] == state, "incorrect time boundary"
    for field in ["client", "principal", "agent", "server", "tool", "capabilities", "environment", "not_before_ms", "expires_at_ms"]:
        invalid = copy.deepcopy(rules)
        del invalid["grants"][0]["scope"][field]
        write(invalid)
        run("check", "--rules", rule_path, expected=2)
    for field, value in [("metadata", canary), ("capabilities", []), ("capabilities", ["read_data", "read_data"]), ("time_ms", -1)]:
        invalid = copy.deepcopy(context)
        invalid[field] = value
        write(input_document=invalid)
        run("test", "--rules", rule_path, "--input", input_path, expected=2)
    rule_path.write_text('{"schema_version":1,"grants":[],"grants":[]}', encoding="utf-8")
    run("check", "--rules", rule_path, expected=2)
    run("check", "--rules", directory / "missing.json", expected=2)
    run("check", "--rules", directory, expected=2)
    rule_path.write_bytes(b" " * 32769)
    run("check", "--rules", rule_path, expected=2)
    write({"schema_version": 1, "grants": []})
    assert evaluate()["state"] == "none"

print("Grant CLI contract passed: scope, precedence, expiry, strict input and privacy fixtures.")
