# Review and bind a local launch

A server's declared name does not identify the program being executed.
`mitigate mcp launch review` binds an explicit configuration to executable bytes,
selected code artifacts, arguments, working directory, environment and credential
references. The resulting reference can identify that exact launch in local
grants, approvals and audit. Review is not authorization or publisher attestation.

## Workflow

Build the CLI and synthetic fixture, then run from the repository root:

```sh
cargo build --locked -p mitigate-cli -p mitigate-mcp-fixture
cargo run --locked -p mitigate-mcp-fixture -- launch-config > target/fixture-launch.json
cargo run --locked -- mcp launch review --launch-config target/fixture-launch.json --out target/launch-review.json --json
cargo run --locked -- mcp launch check --launch-config target/fixture-launch.json --review target/launch-review.json --json
cargo run --locked -- mcp serve --launch-config target/fixture-launch.json --launch-review target/launch-review.json --allow-exec --inventory-only
```

The first two review commands read explicitly selected files and ordinary launch
environment references; they never start a server or read native credential
values. Choose a new review filename every time. `serve` starts the reviewed
program with your OS privileges and speaks MCP on stdin/stdout. Inventory-only
mode still rejects every tool call. No Platform account or network is needed.

Review creation and checking return a schema-1 receipt: profile, salted
`launch_ref`, executable SHA-256 and additional artifact count. They omit paths,
arguments, environment values, credential references and the local salt. Errors
are fixed and omit rejected values and file paths. Exit 0 means the operation
completed; 2 means rejected input, changed launch, timeout or unavailable files;
1 means output failure.

## What is bound

The `mitigate-local-launch-v1` profile commits to:

- OS, architecture and launch configuration version;
- requested and canonical executable paths, and SHA-256 of executable bytes;
- requested and canonical working-directory paths;
- the exact ordered argument array;
- explicitly allowed environment names and the actual ordinary environment
  passed to the child, including available SystemRoot/WINDIR/TEMP/TMP;
- native secret references and their target environment names;
- the launch timeout;
- explicitly selected artifact paths, canonical targets and SHA-256 hashes.

Credential values are excluded. Rotating a value at the same native reference
does not invalidate launch review; changing that reference does. Each connection
still resolves native credentials immediately before its reviewed launch.
Changes to ordinary inherited environment values invalidate review, so prefer
native references for credentials that need rotation.

A random 32-byte salt distinguishes separate reviews of the same configuration.
It is included only in the private review document. The binding uses the existing
versioned JCS/SHA-256 fingerprint implementation with a separate launch domain.
The salt is not a signing key, proof of authorization, or a claim of
anonymization. Neither reviews nor receipts are approved Platform telemetry
contracts. Never upload the private review or its salt as telemetry.

## Select code artifacts explicitly

Launch configuration v1 now optionally accepts `artifact_paths`, an ordered
array of up to 32 absolute paths. Include the script entry point, reviewed
package archive or lockfile when a launcher/interpreter depends on them. Paths
are explicit so review cannot turn untrusted argv into an automatic file crawler.
No home-directory search, package download, dependency traversal or file
discovery occurs. Duplicate canonical paths (including the executable) are
rejected. Selected files must be nonempty regular files, at most 256 MiB each
and 512 MiB combined including the executable.

This is a fingerprint of the executable and selected artifacts, not a claim
that every interpreter module, plugin, shared library, working-directory file,
network-fetched package or dynamically loaded dependency has been measured.
Use installed, pinned local code and select its important artifacts. Executing
an allowed interpreter or shell still gives it the user's privileges. Review
does not make arbitrary scripts or package runners safe, authenticate a package
publisher, restrict tool side effects or sandbox the process.

## Checks and cancellation

`serve --launch-review` and library `connect_reviewed` recompute the complete
binding after native credential resolution and before process creation. The
child uses the exact canonical executable/cwd and captured ordinary environment
that were checked. The review's executable/artifact pins remain on the live
connection. After inventory refresh and immediately before every tool invocation,
Runtime checks their current bytes and canonical targets. Retargeting a code symlink is a
change even when both files have identical bytes. A change invalidates the
connection, terminates its job/group and prevents that tool call; restoring the
file does not revive the connection.

Hashing runs on a blocking worker, uses 64 KiB chunks and has a 30-second caller
deadline. Dropped/cancelled work checks cancellation between file reads and can
never start a process. OS file operations themselves may remain blocked until
the OS completes them. Gateway deadlines can be shorter. Its CLI bounds worker
count and shutdown waiting. No source bytes are logged, persisted or sent to
Platform by this mechanism. Hashing contributes local overhead; no latency SLO
is claimed before release-build benchmarks.

Protect the configuration, selected code and review parent directories from
other writers. Reviews are exclusively created, at most 8 KiB, Unix 0600 or
Windows inherited ACLs; final review-file symlinks/reparse points are rejected.
Administrator changes require a new review and re-evaluation of dependent
grants/approvals. Same-user privileged file/metadata replacement races between
checking and execution remain outside this guarantee. This is ordinary
cross-platform process spawning, not atomic execution from an immutable file
handle or an OS code-integrity enforcement service.

## Verification

`python scripts/verify-launch-review.py PATH_TO_MITIGATE PATH_TO_FIXTURE` tests
actual CLI review/check, environment drift, private outputs, the reviewed MCP
inventory connection, denied calls, live code drift and local audit identity.
Rust tests cover exact configuration changes, bounds, private file handling,
code replacement, symlink retargeting and invalidated-session behavior.
