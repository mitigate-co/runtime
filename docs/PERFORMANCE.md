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

## Recorded baselines

### Linux / WSL2

[Raw samples and environment](performance-baselines/linux-wsl-x86_64.json) record
the 2026-09-29 optimized run of source `7af11d9`, Rust 1.98.1, on WSL2 x86-64.
All thirteen cases completed 100 samples after ten warmups without failure.
The host exposed twenty logical processors and about 32 GiB to WSL; fixture data
used its ext4 virtual disk and the binary was on a mounted Windows drive. Other
interactive development was running, so this is an uncontrolled local baseline.

| Selected case | Median | p95 |
| --- | --- | --- |
| Schema fingerprint, 32 fields | 36.526 µs | 58.698 µs |
| Scan, 128 declarations | 0.775 ms | 0.895 ms |
| Compiled policy evaluation | 9.305 µs | 9.601 µs |
| Durable audit append, growing history | 14.906 ms | 21.273 ms |
| Direct synthetic stdio call | 0.053 ms | 0.085 ms |
| Managed adapter call | 0.439 ms | 0.621 ms |
| Listener plus managed adapter | 0.508 ms | 0.768 ms |

These component values are not a customer latency promise, a production SLO,
cross-platform comparison or full governed CLI measurement. Keep the raw sample
order and environment when comparing a later run; do not sum medians or subtract
percentiles to invent an end-to-end distribution.

### Windows

[Raw samples and environment](performance-baselines/windows-x86_64.json) record
the 2026-09-30 optimized run of clean source `34aeb864`, Rust 1.98.1, on native
Windows 11 Pro x86-64 (build 26200). The host exposed twenty logical processors
on an Intel Core i9-10850K and 65,400 MiB of memory. Fixture data and executable
used NTFS. Interactive development continued, so this is an uncontrolled local
baseline. It is a separate observation from the WSL run, not an OS comparison.

All thirteen cases completed 100 measured operations after ten warmups each.
The external harness retained the original report, independently checked every
sample count and nearest-rank statistic, and confirmed cleanup and preservation
of an unrelated sentinel. It passed only the minimum OS and owned temporary
directory environment to the fixture. No customer state or network was used.

| Selected case | Median | p95 |
| --- | --- | --- |
| Schema fingerprint, 32 fields | 78.900 µs | 121.200 µs |
| Scan, 128 declarations | 1.928 ms | 2.638 ms |
| Compiled policy evaluation | 24.200 µs | 42.500 µs |
| Durable audit append, growing history | 8.033 ms | 11.796 ms |
| Direct synthetic stdio call | 0.050 ms | 0.082 ms |
| Managed adapter call | 0.248 ms | 0.411 ms |
| Listener plus managed adapter | 0.289 ms | 0.476 ms |

The same component boundaries and interpretation limits apply. This harness does
not measure the durable privacy self-test or the complete governed CLI. These
samples cannot explain historical CI timeouts, establish their cause or clear an
unresolved release blocker. No production deadline or acceptance threshold changes.
