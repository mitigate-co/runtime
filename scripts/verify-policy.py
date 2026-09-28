#!/usr/bin/env python3
"""Actual CLI policy contracts; optional checksum-pinned OPA/native-store checks."""
import argparse
import copy
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/policies/read-and-review.rego"


def run(cli, args, code=0):
    result = subprocess.run([str(cli), "mcp", "policy", *map(str, args), "--json"],
                            capture_output=True, timeout=20)
    assert result.returncode == code, "Unexpected policy command exit status"
    if code:
        assert not result.stdout, "Failure emitted partial output"
        error = json.loads(result.stderr)
        assert "source-canary" not in result.stderr.decode(), "Source leaked into errors"
        return error
    assert not result.stderr, "Success emitted diagnostics"
    return json.loads(result.stdout)


def base_input():
    return dict(schema_version=1, client=None, principal="a" * 64, agent=None,
                server="b" * 64, tool="c" * 64, schema_fingerprint="d" * 64,
                capabilities=["read_data"], schema_changed=False, grant="explicit", offline=False)


def conformance(cli, opa, directory):
    cases = [({}, "allow"), ({"offline": True}, "allow"),
             ({"capabilities": ["delete_data"]}, "require_approval"),
             ({"capabilities": ["delete_data"], "grant": "denied"}, "deny"),
             ({"schema_changed": True}, "deny"), ({"principal": None}, "deny"),
             ({"grant": "none"}, "deny"), ({"capabilities": []}, "deny"),
             ({"capabilities": ["read_data", "unknown"]}, "deny")]
    data_path = directory / "input.json"
    for patch, expected in cases:
        data = base_input() | patch
        data_path.write_text(json.dumps(data), encoding="utf-8")
        actual = run(cli, ["test", "--source", EXAMPLE, "--input", data_path])["decision"]
        assert actual == expected, "Regorus decision differs from the contract"
        if opa:
            reference = subprocess.run([str(opa), "eval", "--format=json", "--strict-builtin-errors",
                                        "--data", str(EXAMPLE), "--input", str(data_path),
                                        "data.mitigate.mcp.decision"], capture_output=True, timeout=5)
            assert reference.returncode == 0, "OPA evaluation failed"
            assert json.loads(reference.stdout)["result"][0]["expressions"][0]["value"] == actual, "OPA/Regorus divergence"
    # Exercise every allowed comparison, membership collection and negation form.
    expressions = ['input.grant != "none"', 'count(input.capabilities) > 0',
                   'count(input.capabilities) >= 1', 'count(input.capabilities) < 2',
                   'count(input.capabilities) <= 1', 'input.principal != null',
                   'not input.offline', 'input.schema_version == 1',
                   'input.grant in {"explicit", "none"}', 'input.grant in ["explicit"]',
                   'not "delete_data" in input.capabilities', 'true']
    data_path.write_text(json.dumps(base_input()), encoding="utf-8")
    source_path = directory / "operators.rego"
    for expression in expressions:
        source_path.write_text('package mitigate.mcp\ndefault decision := "deny"\n'
                               'decision := "allow" if { ' + expression + ' }', encoding="utf-8")
        actual = run(cli, ["test", "--source", source_path, "--input", data_path])["decision"]
        assert actual == "allow"
        if opa:
            reference = subprocess.run([str(opa), "eval", "--format=json", "--strict-builtin-errors",
                                        "--data", str(source_path), "--input", str(data_path),
                                        "data.mitigate.mcp.decision"], capture_output=True, timeout=5)
            assert reference.returncode == 0
            assert json.loads(reference.stdout)["result"][0]["expressions"][0]["value"] == actual
    source_path.write_text('package mitigate.mcp\ndefault decision := "deny"\n'
                           'decision := "allow" if { true }\ndecision := "deny" if { true }', encoding="utf-8")
    run(cli, ["test", "--source", source_path, "--input", data_path], 2)
    if opa:
        reference = subprocess.run([str(opa), "eval", "--data", str(source_path),
                                    "data.mitigate.mcp.decision"], capture_output=True, timeout=5)
        assert reference.returncode != 0, "OPA did not reject conflicting decisions"
    source_path.write_text('package mitigate.mcp\ndefault decision := "deny"\n'
                           'decision := "allow" if { print("source-canary") }', encoding="utf-8")
    run(cli, ["check", "--source", source_path], 2)
    invalid = base_input() | {"metadata": {"secret": "source-canary"}}
    data_path.write_text(json.dumps(invalid), encoding="utf-8")
    run(cli, ["test", "--source", EXAMPLE, "--input", data_path], 2)
    print(f"Policy CLI contracts passed; OPA conformance {'passed (22 cases)' if opa else 'not requested'}.")


def native(cli, directory):
    trust, db = directory / "trust.json", directory / "policy.db"
    reference = None
    try:
        generated = run(cli, ["keygen", "--trust-out", trust])
        assert set(generated) == {"schema_version", "action", "secret_ref", "authority"}
        reference = generated["secret_ref"]
        assert json.loads(trust.read_text()) == generated["authority"]
        run(cli, ["keygen", "--trust-out", trust], 2)
        run(cli, ["init", "--db", db, "--trust", trust])
        run(cli, ["status", "--db", db, "--trust", trust], 2)
        one, two = directory / "one.json", directory / "two.json"
        for version, path in [(1, one), (2, two)]:
            run(cli, ["sign", "--source", EXAMPLE, "--trust", trust, "--key-ref", reference,
                      "--version", version, "--out", path])
        run(cli, ["activate", "--db", db, "--trust", trust, "--bundle", one])
        assert run(cli, ["status", "--db", db, "--trust", trust])["version"] == 1
        invalid = directory / "tampered.json"
        value = json.loads(two.read_text()); value["manifest"]["source"] += "\n# source-canary"
        invalid.write_text(json.dumps(value), encoding="utf-8")
        run(cli, ["activate", "--db", db, "--trust", trust, "--bundle", invalid], 2)
        assert run(cli, ["status", "--db", db, "--trust", trust])["version"] == 1
        run(cli, ["activate", "--db", db, "--trust", trust, "--bundle", two])
        run(cli, ["activate", "--db", db, "--trust", trust, "--bundle", one], 2)
        data = directory / "input.json"; data.write_text(json.dumps(base_input()), encoding="utf-8")
        result = run(cli, ["evaluate", "--db", db, "--trust", trust, "--input", data])
        assert result["decision"] == "allow" and result["policy"]["version"] == 2
        assert b"source-canary" not in db.read_bytes()
        wrong = copy.deepcopy(generated["authority"]); wrong["policy_ref"] = "f" * 64
        other = directory / "wrong-trust.json"; other.write_text(json.dumps(wrong), encoding="utf-8")
        run(cli, ["status", "--db", db, "--trust", other], 2)
        print("Native key generation, signing, restart, replacement and rollback contracts passed.")
    finally:
        if reference:
            result = subprocess.run([str(cli), "secrets", "delete", "--reference", reference,
                                     "--confirm", "--json"], capture_output=True, timeout=20)
            assert result.returncode == 0, "Synthetic signing key cleanup failed"
            check = subprocess.run([str(cli), "secrets", "check", "--reference", reference, "--json"],
                                   capture_output=True, timeout=20)
            assert check.returncode == 2 and b"secret_missing" in check.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=pathlib.Path)
    parser.add_argument("--opa", type=pathlib.Path)
    parser.add_argument("--native", action="store_true")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mitigate-policy-contract-") as tmp:
        if options.native:
            native(options.cli.resolve(), pathlib.Path(tmp))
        else:
            conformance(options.cli.resolve(), options.opa.resolve() if options.opa else None, pathlib.Path(tmp))


if __name__ == "__main__":
    main()
