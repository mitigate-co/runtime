# Mitigate Testing Standard

## Test pyramid for the MCP wedge

### Unit

- canonicalization,
- schema fingerprinting,
- capability classification,
- grant matching,
- policy input/output mapping,
- egress field validation,
- redaction/secret guard,
- config parsing.

### Contract

- MCP initialize/list/call semantics,
- Platform telemetry schemas,
- CLI JSON output stability,
- registry API shapes.

### Integration

- representative stdio MCP server,
- representative network/HTTP transport where supported,
- credential injection,
- subprocess lifecycle,
- approval timeout,
- offline cached policy,
- schema-change reapproval.

### Adversarial/security

- command injection,
- hostile paths/env values,
- malicious/oversized schemas,
- tool-description poisoning,
- malformed JSON-RPC,
- secret-bearing errors,
- egress attempts with prohibited fields,
- signature/update tampering,
- tenant isolation.

### End-to-end

- fresh install → scan,
- scan → serve → client call,
- destructive tool → approval → execute/deny,
- schema change → alert/review,
- enroll → sync → fleet view,
- Platform outage → local enforcement remains correct.

## Regression policy

Every important fixed bug gets a regression test when reasonably reproducible.

## Flaky tests

Flaky security tests are broken tests, not "known flakes." Fix/quarantine with an issue immediately; do not normalize rerun-until-green CI.

## Test data

Use synthetic fixtures only. Never copy real customer secrets/data into tests.

## Performance

Keep repeatable benchmark baselines; do not fail CI on noisy microbenchmark variance unless the environment is controlled. Use benchmarks to guide decisions and catch gross regressions.
