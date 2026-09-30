# Local MCP policy

The local policy engine embeds Regorus for offline validation, signing, activation
and evaluation. These commands do not execute tools. [Governed-call mode](ENFORCEMENT.md)
composes policy with grants, exact launch review, approvals, controls and audit.
An `allow` policy result is one check, never standalone authorization.
`require_approval` is never permission to execute.

## Quick start

Build the CLI with `cargo build --locked`. On Windows, install the MSVC
Spectre-mitigated x64/x86 libraries matching your C++ toolset. Regorus's build
requires them; do not disable that prerequisite. On Unix, create local state in
a private directory on a filesystem that supports permissions (WSL `/tmp` or a
Linux home directory, rather than an NTFS mount without permission metadata).

```sh
mitigate mcp policy check --source examples/policies/read-and-review.rego
mitigate mcp policy test --source examples/policies/read-and-review.rego --input examples/policies/read-input.json --json
mitigate mcp policy keygen --trust-out trust.json --json
```

`keygen` creates an Ed25519 seed in the native credential store and writes a new
public trust document. Save the returned `secret_ref`; it is needed for signing,
and contains no secret. Protect that reference and public trust document from
modification. The trust document contains format version 1, a random stable
`policy_ref`, and the independently pinned public key. Native OS permission or
unlock prompts are not bypassed. There is no plaintext key fallback or automatic
store creation. See [native storage](SECRETS.md).

Use the returned reference for `--key-ref` below (replace `REFERENCE`):

```sh
mitigate mcp policy sign --source examples/policies/read-and-review.rego --trust trust.json --key-ref REFERENCE --version 1 --out policy-v1.json
mitigate mcp policy init --db policy.db --trust trust.json
mitigate mcp policy activate --db policy.db --trust trust.json --bundle policy-v1.json
mitigate mcp policy status --db policy.db --trust trust.json --json
mitigate mcp policy evaluate --db policy.db --trust trust.json --input examples/policies/read-input.json --json
```

Every command is local. `check`/`test` need no credentials. `test` evaluates
unactivated source for authoring; `evaluate` requires a persisted verified bundle.
Neither executes tools. Status/evaluation reports omit source, input values and
private key material. Policy source itself may contain customer identifiers;
signed bundles and local metadata are **not** approved telemetry schemas.

The example allows an explicit grant for a single read capability, requires
approval for a destructive capability, and denies schema changes, missing
principal attribution, missing grants and explicit denials. It is an example
policy, not automatic configuration or a proof of safe tool behavior.

## Mitigate Rego Profile v1

Profile identifier: `mitigate-mcp-rego-v1`. Rego v1, one module, exactly
`package mitigate.mcp`, exactly one `default decision := "deny"` (the `=` spelling
is also accepted). All other rules must be complete `decision` rules with
constant string outputs `allow`, `deny` or `require_approval`, a nonempty `if`
body, and optional bounded `else` bodies. Default-only denial is valid.

Bodies support conjunctions separated by newlines/semicolons, `not`, boolean
constants, direct `input.offline`/`input.schema_changed` tests, comparisons
(`==`, `!=`, `<`, `<=`, `>`, `>=`) of scalar constants/input fields, and ground
membership (`VALUE in input.capabilities` or a constant array/set). Scalars are
quoted printable ASCII strings, booleans, null, or integers 0–999. Input fields
use direct dot references; they cannot be aliased or indexed dynamically.
The sole callable builtin is `count(input.capabilities)` in a comparison or
membership operand. No user function can replace it.

Imports, helper rules/functions, variables/unification, recursion, `some`,
`every`, comprehensions, arithmetic, raw/escaped strings, external data, `with`,
indirect calls, custom extensions and all other builtins are rejected by a
positive AST allowlist. This includes print/trace, network, time/random and
environment access. Compile-time feature selection alone is not the sandbox.
This deliberately small initial profile can expand only with reviewed limits and
conformance tests. Arbitrary OPA policies are not supported.

Multiple matching rules with different decisions return an evaluation error,
which must deny execution. Use `else` for explicit precedence, as in the example.
An independent grant denial always wins in the enforcing gateway's composition;
policy authors cannot override it. Unknown attribution remains null.

### Closed input

The input must explicitly contain these fields, with no unknown/duplicate keys:

| Field | Type |
| --- | --- |
| `schema_version` | Integer 1 |
| `client`, `principal`, `agent` | 64 lowercase hex fingerprint or explicit null |
| `server`, `tool`, `schema_fingerprint` | 64 lowercase hex fingerprint |
| `capabilities` | Unique classes from the existing 11-value taxonomy |
| `schema_changed`, `offline` | Boolean |
| `grant` | `none`, `denied`, `explicit` |

The trusted local gateway must construct this input. Client-supplied labels or
MCP metadata cannot establish identity, approval, connectivity or grant state.
Raw arguments/results, tool descriptions and arbitrary metadata have no field.
Fingerprints are local identifiers, not anonymization or authentication.

### Resource limits

- Source: 16 KiB ASCII, 512 lines, 1,024 columns; lexical guard at 1,024 tokens,
  delimiter nesting 16 and literal strings 128 bytes, **before** dependency parsing.
- AST: at most 33 rules (including default), 512 expressions, 256 statements,
  32 conditional bodies total, 16 statements/body, 32 scalar items/constant set or array.
- Input: 4 KiB encoded JSON, at most 11 unique capability classes, fixed scalar fields.
- Evaluation: 50 ms cooperative monotonic timer checked every interpreter work
  unit, plus elapsed-time rejection before returning a decision. Strict builtin
  errors. A timed-out, conflicting, undefined or invalid result never allows execution.
- Memory/work growth is constrained structurally: no recursion, binding loops,
  computed collections, expanding arithmetic or unbounded builtin exists in this
  profile. This is not a process memory quota or a real-time OS scheduling promise.
- Local bundle: 32 KiB canonical JSON. Store: 1 MiB database, 256 KiB SQLite cache,
  bounded SQL/rows/VM operations, 250 ms lock wait and 2-second progress deadline.
  Rollback journaling can temporarily use roughly another database's size. Native
  OS filesystem calls are not preempted by SQLite's progress callback.

## Signed activation and failure semantics

The closed envelope has `manifest` and `signature`. The manifest includes
`schema_version:1`, `profile`, `policy_ref`, positive safe-integer `version`
(at most 2^53−1), and exact `source`. The signature is 128 lowercase hex digits.
Sign the byte sequence `mitigate-mcp-policy-bundle-v1` + NUL + RFC 8785 canonical
JSON of the manifest, using standard Ed25519. Verification uses Dalek's strict
individual verifier and rejects weak public keys. Trust is supplied separately;
the bundle cannot select its own signer. Local and externally produced bundles
use the same signed format; there is no unsigned activation switch.

Verification/profile compilation precede replacement. A write transaction
reverifies the current state, compares the independent authority and requires a
strictly higher version. Equal versions are rejected, including identical retries.
The source is stored only locally, with its signature. New file creation never
overwrites. Missing/corrupt/incompatible databases are never silently reset.

The in-memory `ActivePolicy` can evaluate with no database or Platform dependency.
Its refresh API commits a verified replacement before swapping the loaded policy.
Bad signatures, wrong trust, invalid source, lower/equal versions, locks and write
failures leave the loaded policy intact. A failed commit can have uncertain disk
durability: reopen/status before choosing the next version. Restart rechecks the
signature against the independent trust document; invalid cached state fails closed.
The [governed gateway](ENFORCEMENT.md) rechecks locally activated policy at
authorization boundaries. [Offline rules](OFFLINE.md) retain a verified policy
through failed refreshes and require valid local approval authority. There is no
automatic network policy fetching. Key rotation is an explicit new trust
configuration, not a bundle-driven operation.

Protect the store, trust file and their parent directories. Unix state files are
created 0600 and shared permissions are rejected; Windows uses inherited ACLs.
Same-user/admin compromise can replace both trust and cache, or restore a complete
older valid store. These checks do not claim rollback-proof hardware or remote
attestation. Policy signing authenticates the configured authority, not correctness
of every policy it chooses to sign. No key material is persisted in SQLite.

## Verification and recovery

```sh
cargo test --locked -p mitigate-policy
python scripts/verify-policy.py target/debug/mitigate
```

CI additionally runs 22 decision/conflict cases against checksum-pinned OPA
1.21.0 (Linux static executable SHA-256
`5eef70644868bb04d0556bcc795ee42f2ab379e73f51d1bfa30f83e1305bc9b9`).
OPA is a development reference and is never called from Runtime.
`--native` exercises temporary native signing keys, actual commands, restart,
tampering and rollback, then deletes only the fixture's own key. CI runs it inside
the existing native-store fixtures on all three operating systems.

Exit 0 means a valid command/result, including a denial. Exit 2 means input,
verification, evaluation or storage failure; JSON errors are content-free and
stdout is empty. Use `status` after uncertain writes. A profile rejection means
reviewing syntax/limits; an evaluation failure can indicate overlapping rules.
For locked keys, unlock the OS store. For corruption, preserve the file for local
investigation and explicitly restore a known-good backup; do not delete state as
an automatic recovery strategy. See [ADR 0014](decisions/0014-policy-profile-and-signed-bundles.md).
