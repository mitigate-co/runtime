# Scan a project

Status: source checkout. Supported signed binaries are not published yet.
These commands need no account or enrollment. They work offline once the pinned
build dependencies are available.

## Build prerequisites

Install Rust through rustup and the native C toolchain:

| System | Required tools |
| --- | --- |
| Windows x64 | Visual Studio C++ Build Tools and the matching MSVC Spectre-mitigated x64/x86 libraries required by Regorus |
| macOS | Xcode command-line tools |
| Linux x64 | Native C compiler and linker |

The repository selects the Rust version and locked dependencies. Run the commands
below from its root. The first build compiles the application and bundled SQLite.

```sh
git clone https://github.com/mitigate-co/runtime.git
cd runtime
cargo run --locked -- version
```

## Check the example project

```sh
cargo run --locked -- mcp scan --root examples/scanner-project
```

This reads the supplied synthetic MCP configuration. It does not launch a server,
invoke a tool, resolve a credential or enable sync. The report lists discovered
declarations and review findings. An empty result means no supported declarations
were found; it does not prove that the machine has no MCP servers.

Replace the example path with your project directory:

```sh
cargo run --locked -- mcp scan --root /path/to/your/project
```

`/path/to/your/project` is a placeholder; quote paths containing spaces. Only
project `.mcp.json` and `.cursor/mcp.json` are supported by this scanner. It does
not search home directories, all applications or running processes. See the
[scanner contract](SCANNER.md) before interpreting coverage.

## Check the privacy boundary

```sh
cargo run --locked -- privacy self-test --json
cargo run --locked -- egress inspect --json
```

The first command creates and removes its own synthetic queue in temporary
storage. Expect `passed: true` and `network_requests: 0`. It does not inspect your
workload or certify an installation. The second command describes supported sync
fields. Without a selected queue, destination and retained queue are `null` and
delivery is `not_checked`.

If a check fails, retain its fixed error category and version. Do not delete
authority databases or disable checks to obtain a passing result. The
[CLI reference](CLI.md) explains exit codes and recovery actions.

## Choose the next action

| Goal | Next step |
| --- | --- |
| Inspect a trusted server's tools | [Explicit enumeration](ENUMERATION.md): review the selected command before using `--allow-exec`. Enumeration runs the server with your OS privileges. |
| Compare tool definitions | [Save and compare snapshots](FINGERPRINTS.md). A scan summary is not an execution identity. |
| Control calls from an MCP client | [Configure governed calls](ENFORCEMENT.md), including local policy, grants, launch review, approvals, controls and audit. Inventory-only mode refuses calls. |
| Share selected metadata with an organization | [Enroll and enable optional sync](SYNC_CONTROLS.md). Enrollment alone does not start capture or delivery. |
| Report a vulnerability | Use the [private reporting path](../SECURITY.md); include a synthetic reproduction. |
| Diagnose a local problem | [Collect a checked support report](DIAGNOSTICS.md) and follow the [recovery runbook](SUPPORT.md). Sharing is manual. |

Local reports can contain customer-controlled names and endpoint origins. Keep
scan results, snapshots and launch files local; they are not the closed Platform
telemetry format. See [privacy architecture](PRIVACY_ARCHITECTURE.md).

The version, example scan, privacy self-test and egress commands are exercised in
native CI. Source installation is a development path; it does not replace signed
distribution or the remaining [production gates](MASTER_SPEC.md#16-launch-gates).
