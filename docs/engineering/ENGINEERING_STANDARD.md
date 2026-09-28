# Mitigate Engineering Standard

## Purpose

Mitigate should read like a codebase maintained by engineers who care deeply about security, simplicity and the next person who has to change it.

The standard is not "more comments" or "more abstractions." It is coherent design with enough documentation that intent survives the original author.

## 1. Design philosophy

Prefer:

- explicit over implicit,
- boring over clever,
- a small correct module over a generic framework,
- structured types over stringly-typed maps,
- composition over inheritance,
- measured performance work over folklore,
- one clear source of truth over duplicated configuration,
- errors that explain what failed and what the operator can do.

Avoid:

- "manager", "helper", "processor", "utils" modules that own no domain concept,
- abstraction layers created before a second implementation exists,
- premature plugin systems,
- giant service classes,
- hidden global state,
- bool parameters whose meaning is unclear at call sites,
- generic `HashMap<String, Value>` at trust boundaries,
- copy/pasted validation,
- comments that restate code,
- functions that silently mutate unrelated state.

## 2. File and module shape

A file should answer one domain question.

Good examples:

```text
mcp_scan/config_sources/claude.rs
mcp_gateway/grants.rs
mcp_gateway/approval.rs
egress/event_validator.rs
policy/decision.rs
```

Poor examples:

```text
utils.rs
common.rs
helpers.rs
manager.rs
misc.rs
```

When one file repeatedly exceeds a few hundred lines, inspect whether it owns multiple concepts. Do not split mechanically by line count.

## 3. Naming

Names should carry domain meaning.

Prefer:

- `ToolSchemaFingerprint`
- `ApprovalScope`
- `PolicyDecision`
- `DiscoveredMcpServer`
- `EgressRejectionReason`

Avoid:

- `Data`
- `Info`
- `ResultData`
- `Manager`
- `Thing`
- `Handler` when a more precise role exists.

Boolean variables read as facts:

```rust
let is_destructive = ...;
let requires_approval = ...;
```

Enums beat loosely related booleans when states are mutually exclusive.

## 4. Rust

- current stable Rust unless an ADR states otherwise,
- `rustfmt` required,
- Clippy warnings treated seriously; deny warnings in release CI where practical,
- use `thiserror`-style typed errors or equivalent patterns for subsystem errors,
- use `anyhow` only at application/CLI composition boundaries, not to erase library semantics,
- avoid `unwrap()`/`expect()` in production paths unless the invariant is statically obvious and documented,
- bound external input before allocation,
- avoid unsafe Rust unless there is a measured requirement and a dedicated review/ADR,
- document public APIs and non-obvious invariants,
- cancellation/timeouts are explicit for network/process operations,
- subprocesses have deliberate lifecycle cleanup.

### Error context

An error should preserve safe operational context:

```text
failed to enumerate tools from server `github-local`: upstream process exited before initialize response
```

Do not include secret values or raw payloads.

## 5. TypeScript / React

- `strict: true`,
- no casual `any`,
- parse/validate all trust-boundary input,
- domain/business logic outside React components,
- components should mostly compose state + presentation,
- query/cache behavior centralized through a consistent data layer,
- accessible semantic HTML and keyboard behavior,
- loading/empty/error/success states are first-class,
- do not hide network errors behind a generic toast with no recovery path.

## 6. API contracts

Define canonical schema once and generate/derive secondary artifacts when practical.

Every external request/response has:

- version,
- bounded fields,
- explicit optionality,
- documented error behavior,
- examples,
- compatibility expectations.

Never accept unknown fields in security-sensitive telemetry simply for forward compatibility. Version schemas deliberately.

## 7. Comments

Use comments for:

- security invariants,
- protocol weirdness,
- non-obvious tradeoffs,
- why a seemingly simpler implementation is unsafe,
- links to issue/ADR/spec sections,
- external compatibility constraints.

Do not write:

```rust
// Increment counter
counter += 1;
```

Prefer:

```rust
// Count rejected events separately from transport failures: a rejection means
// the privacy boundary worked and should never be retried with the same body.
rejected_events += 1;
```

## 8. Function documentation

Security-sensitive or public functions should document:

- purpose,
- trusted/untrusted inputs,
- outputs/side effects,
- failure mode,
- secret/content handling,
- concurrency/lifetime assumptions when non-obvious.

Do not turn every private function into a documentation essay.

## 9. Dependency hygiene

Before adding a dependency, ask:

1. Can std/current dependencies do this clearly?
2. Is the dependency actively maintained?
3. Is the license allowed?
4. What transitive surface does it add?
5. Does it run in the trust boundary/request path?
6. Does it perform telemetry/networking?
7. Can we replace it behind a narrow interface?

Record significant dependencies in an ADR.

## 10. Performance

Benchmark actual hot paths.

Maintain benchmarks for:

- schema canonicalization,
- policy evaluation,
- gateway relay overhead,
- scanner traversal on representative trees/config sets,
- egress validation.

Performance work must not bypass validation, logging hygiene or policy checks.

## 11. Configuration

- explicit config schema,
- useful defaults,
- environment variables documented,
- secrets referenced rather than embedded,
- fail with actionable validation messages,
- config migration/version strategy once public releases exist.

## 12. Feature flags

Use sparingly. Every flag has:

- owner,
- purpose,
- default,
- removal condition/date/issue.

Delete stale flags.

## 13. TODO policy

Allowed:

```text
TODO(MIT-123): support streamed progress notifications after client compatibility matrix is complete.
```

Not allowed:

```text
TODO: fix this later
```

## 14. Review standard

Reviewers prioritize:

1. security/privacy regression,
2. correctness,
3. architecture boundary violations,
4. failure behavior,
5. test quality,
6. maintainability/readability,
7. performance,
8. style details handled by automation.

Do not approve code just because tests are green if the design is unreadable.
