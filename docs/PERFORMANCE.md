# Local performance measurements

The synthetic harness measures Runtime components separately. It is part of the
unpublished test fixture, never the customer CLI, and sends no telemetry. It
reads no customer configuration, credentials, enrollment, audit or workload files.
It creates private temporary projects and an audit database, starts only its own
fixed synthetic server, and removes its workspace. No external server is called.

## Reproduce

Record the source revision, clean/dirty state, Rust version, CPU class, memory,
OS/virtualization, filesystem and competing load alongside the JSON report. Do
not record hostnames, usernames, private paths or environment dumps.

```sh
git rev-parse HEAD
git status --short
rustc --version
cargo build --release --locked -p mitigate-mcp-fixture
./target/release/mitigate-test-mcp benchmark --samples 100 --warmup 10 > benchmark.json
```

On Windows use `target/release/mitigate-test-mcp.exe`. A custom `CARGO_TARGET_DIR`
changes that executable path. Build time is excluded. A debug build is labeled
`debug` in the output and must not be reported as optimized Runtime performance.
Use a trusted native filesystem for local measurements; mounted/virtualized
filesystems and CI contention can dominate storage and pipe results.

Defaults are 100 measured operations after 10 warmups per case. Explicit counts
are bounded to 5–500 samples and 0–50 warmups. The command cannot select a project,
server, payload or existing database. Exit 0 requires every requested measurement
and cleanup to succeed; invalid arguments or a failed run exit 2. Preserve failed
reports and investigate them. The command does not retry a failed measurement.

## Cases and boundaries

| Case | Timed operation |
| --- | --- |
| `canonicalize_32_fields` | Validate and canonically serialize a fixed object schema with 32 string properties. |
| `fingerprint_32_fields` | The same validation/canonicalization plus versioned, domain-separated SHA-256. |
| `scan_1_server`, `scan_32_servers`, `scan_128_servers` | Read, parse and normalize two supported project configuration paths, splitting the stated total declarations across them. No recursion or server execution. |
| `policy_compile` | Parse and validate the example restricted Rego policy, including destruction of the compiled instance. |
| `policy_evaluate` | Validate metadata input and evaluate the already compiled policy for an explicit read grant while offline. The result must be allow. |
| `egress_validate_decision` | Parse, validate and canonicalize the fixed closed decision-event fixture. No queue or sender. |
| `audit_append_growing_history` | Construct a metadata-only event and append with the real audit transaction, retained-chain checks and production SQLite durability. Warmups remain in history; final verification checks the record count. |
| `direct_stdio_roundtrip` | Serialize one fixed call through ordinary child pipes, parse its reply and check the synthetic result. |
| `classify_one_tool` | Fingerprint/classify one already enumerated synthetic tool using the production deterministic rules. |
| `managed_stdio_roundtrip` | The same call through `StdioServer`, including input/output schema checks, fresh inventory and drift validation, bounded protocol and the fixed fixture dispatch gate. |
| `listener_managed_stdio_roundtrip` | The same managed adapter behind the production local listener, with a bounded in-process duplex client connection. The fixture service authorizes only its exact synthetic call. |

Schema/input/project construction, server spawn/initialization, audit creation and
final verification/cleanup are outside the timed operations. Scanner reads use
warm filesystem caches. Audit history grows from warmup through the last sample;
this is not a constant-history or rotation benchmark. Pipe cases include the
synthetic upstream response time and local scheduler. They run sequentially with
separate child processes; subtracting their percentiles is not a measured
per-request overhead distribution.

The relay cases intentionally isolate transport/listener costs. They are not the
complete governed CLI path: they exclude signed-policy/grant/approval/control
storage, required per-call audit, native secret resolution, reviewed executable
rehashing and optional sync. Policy and audit are measured separately, not added
into a misleading end-to-end estimate. Network providers, real MCP clients,
large inventories and customer filesystem/workload distributions require their
own explicit measurements before making latency claims.

## Output and verification

Each case retains measured nanoseconds in observation order, the requested and
completed warmup counts, and nearest-rank median/p95 plus minimum/maximum. Warmups
are the only intentionally excluded successful operations. Failed warmups or
samples have a separate fixed phase/duration, stop that case and make the run
fail. Summary statistics cover only the retained successful samples; never quote
them without the failed status. Unmeasured setup, infrastructure or cleanup
failure sets the top-level `harness_failed` flag; absent cases were not measured.
No input, result body, path, reference,
provider diagnostic or secret is exported.

Sampling has a sixty-second admission budget per case, checked between
operations. Production operation/transport deadlines remain intact; an OS
filesystem call itself can still block. Use an external process deadline for
automation. CI uses `python scripts/verify-benchmark.py PATH_TO_FIXTURE` with a
180-second limit and five samples after two warmups. It checks actual component
results, the output contract, statistics and cleanup, without a latency threshold.
Noisy shared-runner durations are not performance regression gates or SLOs.

Interpret results using the [research methodology](RESEARCH_METHODS.md). Keep
separate baselines for OS/build/filesystem and preserve unsuccessful runs. This
harness does not resolve the [open release blockers](RELEASE_BLOCKERS.json).
