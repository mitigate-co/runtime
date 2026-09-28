# ADR 0006: Explicit stdio enumeration and process lifetime

Status: accepted. Scope: MCP-003.

## Decision

Separate automatic discovery from execution. `inspect` requires a reviewed launch file and `--allow-exec`. Library callers must supply the same explicit execution intent. Normalize bounded tool definitions locally but serialize only a narrower CLI report. No tool call, Platform request, external schema fetch, stderr logging or dynamic credential helper occurs.

Stdio is the first representative transport. Protocol negotiation and inventory logic use a small internal transport trait with only send/receive; network adapters follow in MCP-008. No empty future adapters are exposed. Strict duplicate-rejecting JSON parsing is shared with discovery because both now need the same trust boundary.

Use Tokio for deadlines and cancellable pipe I/O, and process-wrap for Unix process groups and Windows job objects. The standard library lacks portable asynchronous pipe deadlines and safe group/job lifecycle primitives. Cancellation and explicit shutdown kill the wrapper, not merely its immediate child. Normal completion also terminates the group before reaping the leader, avoiding orphaned children holding pipes. The deliberate hard-stop policy sacrifices graceful server exit in this read-only enumeration command to bound cleanup of untrusted behavior; no mutating tool operation is in flight. Gateway lifecycle behavior is separate.

## Dependency review

- Exact `tokio` 1.53.1 (MIT): maintained by [Tokio](https://github.com/tokio-rs/tokio), using runtime, process, I/O, time, macros and signal features; no networking/TLS client added.
- Exact `process-wrap` 10.0.1 (Apache-2.0 OR MIT): [Watchexec](https://github.com/watchexec/process-wrap), with only Tokio, creation-flags, job-object, kill-on-drop and process-group features. Tracing and unrelated default features are disabled. Reviewed job assignment/resumption, error cleanup and group termination code in the published crate.

The lockfile adds 40 external packages (85 total external packages across targets), including futures, OS bindings and their macro dependencies. Selected manifests/licenses were inspected and cargo-deny license/source/bans checks passed; RustSec reports no advisory for this lockfile. The accepted non-failing duplicate-package warning is build-time `syn` 2/3 used by different macro dependencies. Neither version is runtime protocol code. No license exception was added. Binary-size/overhead claims await release benchmarks; this expansion is justified by cross-platform execution cleanup rather than a custom unsafe OS layer.

Process lifecycle logic adapts reviewed customer-side prototype behavior. No account coupling, private hosted code, raw history or cloud key material was imported. New fixtures test actual child/grandchild processes on each target OS. This is lifecycle management, not a process sandbox, trusted package attestation, or OS secret store.
