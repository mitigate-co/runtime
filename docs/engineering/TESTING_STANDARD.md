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

The native Verify job has a 25-minute total budget. Windows
[run 36557035465](https://github.com/mitigate-co/runtime/actions/runs/36557035465)
passed workspace tests but reached the former 15-minute limit during subsequent
CLI contracts, before native-credential verification. Its synchronous-storage
suites completed successfully but consumed most of the job time. This CI budget
change does not extend a Runtime lease, SQLite deadline, transport timeout or
fixture assertion, and does not resolve the separate failures in issues #46/#50.

The upstream gate-expiry regression uses the same five-second startup budget as
the other real-process fixtures. Only after the final gate is reached does it
advance Tokio's test clock past the configured transaction deadline. Both pending
and immediately ready gate outcomes must time out, dispatch no call and leave the
connection unusable. Real time resumes before OS process cleanup. An explicit gate
visit assertion prevents a slow startup or inventory timeout from satisfying this
test accidentally. No production clock, timeout or authorization code is changed.
The stalled-upstream case also uses the ordinary startup budget and requires its
child's call marker, proving its timeout followed dispatch rather than inventory.
