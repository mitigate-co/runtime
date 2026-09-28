# ADR-0014: Bounded Rego profile and signed local policy bundles

Status: Implemented (MCP-011; release gates tracked separately)
Date: 2026-09-28

## Decision

Embed pinned Regorus 0.12.0 with default features disabled. Enable only `std`
and `arc`. Validate a positive AST allowlist before evaluation: complete constant
decisions, bounded predicates over closed metadata, and `count(capabilities)`.
Require a default denial. Exclude loops, comprehensions, recursion, variables,
arithmetic, external data, imports, extensions and all other builtins. A timer
alone is not an allocation limit; structural bounds prevent allocation-expanding
operations. Lexical bounds precede the dependency parser. Pin the unstable AST
API and re-review it on any version change.

Regorus is the canonical engine, not a new architecture choice. Its maintained
Microsoft upstream ships MIT/Apache-2.0/BSD-3-Clause notices. The selected build
does not enable HTTP, time/UUID, regex, RVM, Azure, coverage, custom allocator or
schema features. Core builtins still include randomness and diagnostics: the
positive AST allowlist, not feature flags alone, rejects those calls. Shipped
interpreter code forbids unsafe Rust;
standard-library, synchronization and build dependencies remain trusted code.
The `std` build includes a Windows Spectre CRT linkage helper. Verus companion
crates support verification; they are not an additional evaluation engine.

Use pinned ed25519-dalek 3.0.0 for strict individual signature verification;
default features disabled, zeroization enabled. Its maintained Dalek upstream
uses BSD-3-Clause. Its curve implementation contains reviewed upstream low-level
code; no custom cryptographic primitive is introduced. No batch verification,
legacy compatibility, PKCS#8/PEM, RNG feature, network, or private-key serialization
is enabled. Use the existing OS randomness and secret broker for local signing.
Private signing seeds must never enter configuration, command arguments or SQLite.

Signed bundle verification binds profile, policy reference, increasing version
and exact source against an independently pinned public key. Local policy uses
the same signed format. An invalid replacement cannot replace a loaded policy.
Disk persistence uses the already reviewed bounded SQLite build and transactions.
Local same-user compromise/whole-store rollback is outside this anti-replay
boundary; no claim of hardware-backed monotonic state is made.

## Dependency cost and verification

The resolved lockfile grows from 196 to 230 packages: 33 external packages plus
`mitigate-policy`. No existing package version changed. Most cost is Regorus and
its verification/parser/synchronization dependencies; Dalek adds curve/signature
code and shares the existing SHA-2 family. Core Regorus randomness remains built
but unreachable through the allowlist. There is no network fetch inside evaluation.
Parsing/evaluation and signature checks run on the local sensitive control path.
The engine increases code size; omitting its broad default feature set avoids the
RVM/HTTP/regex/coverage surface. Release-size measurement belongs to MCP-020; no
binary-size or latency promise is made here.

Local Linux workspace tests and strict lint pass, including policy parsing,
decisions, time-budget exhaustion, signed-field tampering, wrong/weak trust,
signed-but-unsupported source, restart, contention, corruption and private files.
Actual CLI/native-store contracts pass with a temporary isolated keyring, and
22 reference decision/conflict cases agree with OPA 1.21.0. Source scans and
`cargo audit --deny warnings` / license/source/bans gates pass. Existing SHA-2/syn
duplicate warnings remain visible; Regorus also adds a second num-bigint and
synstructure line rather than coercing incompatible versions.

OPA is a checksum-pinned CI/development reference only, never a distributed
request-path dependency. Cross-OS CI/merge remain pending at this implementation
checkpoint. Local Windows compilation found missing matching Spectre libraries;
the prerequisite is documented and was not bypassed. Linux verification uses an
isolated WSL Rust installation. CI Windows images include the required component.
