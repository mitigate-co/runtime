# Adversarial input tests

Run the deterministic JSON and event corpus with the pinned Rust toolchain:

```sh
cargo test --locked -p mitigate-json -p mitigate-egress
```

These tests are also part of every native `Verify` workspace run. They use only
synthetic data, no credentials, network, third-party servers or shell commands.
They add no dependency and change no production parser or egress behavior.

## Corpus and invariants

| Input family | Required outcome |
| --- | --- |
| Exact JSON byte, depth, node, string and key limits | At-bound controls parse; the first over-limit case is rejected. UTF-8 string limits count bytes. |
| Decoded duplicate keys, including escaped supplementary Unicode | Rejected at the strict JSON boundary, even when both values are otherwise valid. |
| Invalid UTF-8, lone/mismatched surrogates, BOM, NUL, overflow and trailing values | Fixed `InvalidJson`; source text is absent from the error. Valid surrogate pairs have a positive control. |
| Prohibited or unknown event fields, unsafe text, mismatched types/versions and bounds | Rejected by the real `CheckedEvent` constructor. Each saved attack starts from a complete valid event so a missing required field cannot hide an untested acceptance. |
| Every existing event key duplicated in plain or Unicode-escaped form | Strict JSON and event admission both reject it, including nested inventory tool objects. |
| Deterministic byte mutations of decision/inventory/control inputs | No panic. Rejected values expose only fixed errors. Admitted events are bounded, exclude the inserted content canary, and remain byte-identical with the same references when parsed again. |

Saved event mutations live in
`crates/mitigate-egress/tests/hostile-corpus.jsonl`. Each record selects a synthetic
decision or inventory example, an envelope/facts/tool object, and one member to
replace or add. Extend this corpus with a minimized reproducible case when fixing
an input-boundary bug. Keep positive controls alongside refusal assertions.

The generated campaign uses six seeds, 1,024 cases per seed and one to four
mutations per case. Its fixed xorshift32 selector is solely for repeatable test
generation, never runtime security randomness. Mutations flip/insert/delete bytes,
truncate, and insert hostile tokens or a content canary. This is bounded mutation
testing, not a coverage-guided fuzzing campaign or a proof that all hostile inputs
are safe. Domain-specific attacks must still be minimized and asserted directly.

## Wider security acceptance

This corpus complements existing actual-process MCP transport/gateway contracts,
hostile launch and schema tests, local policy/grant/approval/control tests, scoped
credential tests, the persisted privacy self-test and authenticated transport
fixtures. Run the full workspace and executable contracts from `Verify` for a
release candidate. Passing the corpus alone cannot establish gateway authorization,
secret isolation, time/lease correctness, privacy persistence or delivery safety.

Release-source and artifact-signature tests are separate build-tooling gates.
Windows governance issue [#46](https://github.com/mitigate-co/runtime/issues/46)
and delivery readiness issue [#50](https://github.com/mitigate-co/runtime/issues/50)
retain their original failure evidence. Neither is resolved by a passing corpus
or subsequent CI run. Real signed-artifact acceptance, malicious process review,
logs/telemetry review and the other [launch gates](MASTER_SPEC.md#16-launch-gates)
remain required. Do not publish operational adoption/security claims from fixture
results.

Native gateway-capture issue [#57](https://github.com/mitigate-co/runtime/issues/57)
also remains unresolved. Its [bounded failure diagnostics](SYNC_CAPTURE.md#verification)
are regression tested without forwarding arbitrary child output. The diagnostic
fix must not be represented as a fix for an unproven clock, storage or timeout cause.

Windows approval-decision issue [#67](https://github.com/mitigate-co/runtime/issues/67)
retains a generic storage failure during the governance schema-drift fixture.
The [approval storage contract](APPROVALS.md#storage-failures) now distinguishes
fixed lock and interruption categories and verifies refusal against an explicitly
held competing SQLite transaction. That deterministic refusal does not identify
the historical failure's cause or clear the release blocker.
