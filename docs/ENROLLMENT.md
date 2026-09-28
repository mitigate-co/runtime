# Optional Runtime enrollment protocol

`mitigate-enrollment` implements a bounded possession proof, receipt validator
and explicit [native lifecycle](ENROLLMENT_STORAGE.md) for MCP-018. Core protocol
types perform no I/O; the storage module owns local persistence and recovery.
The optional [HTTPS transport](ENROLLMENT_HTTPS.md) sends one explicit verified
bootstrap request. Enrollment does not enable synchronization. Local MCP
operation remains independent of Platform.

## Bootstrap boundary

A user selects one canonical HTTPS Platform origin separately from an enrollment
code. The origin is at most 256 ASCII bytes with no credentials, path, query,
fragment or implicit normalization. The production parser rejects HTTP, default
port spelling, trailing slash and uppercase/Unicode normalization. It accepts
explicit nondefault HTTPS ports. It does not infer a destination from MCP config,
tool content, a code or an HTTP redirect.

The code is exactly `mcp1:<lowercase UUIDv4>:<token>` (85 ASCII bytes). The token is
32 random bytes in canonical unpadded base64url. Whitespace, alternate alphabets,
padding and nonzero unused bits are rejected. Input is consumed through the
zeroizing `mitigate-secrets::Secret` owner, including malformed input.

A fresh Ed25519 seed and two independent 128-bit opaque `ref_` references identify
one enrollment. They are never derived from machine identity, MCP config, tool
definitions or workload content. A recovery attempt restores all of them; it must
not silently rotate a key or one reference after an uncertain response.

## Version-one possession proof

The signed bytes are UTF-8 with LF separators and **a final LF**:

```text
mitigate.runtime.enrollment.v1
<canonical Platform origin>
<grant UUID>
<base64url SHA-256 of decoded token bytes>
<base64url raw 32-byte Ed25519 public key>
<runtime reference>
<enrollment reference>
```

The bootstrap request is an HTTPS POST to `/api/v1/runtime/enroll`, without query,
browser cookie, bearer authorization or redirects. Its JSON body contains exactly
`grant_id`, `token`, `public_key`, `runtime_ref`, `enrollment_ref` and `signature`.
The signature is pure Ed25519 (64 bytes), encoded as canonical unpadded base64url.
JSON field order is not the signed transcript. Both body and receipt are bounded
to 1024 bytes. The transport must enforce its own timeout and streaming body cap.

The token is an authentication credential disclosed only to the selected Platform
over authenticated HTTPS. This is a distinct explicit bootstrap exchange, **not
normal telemetry**. The claim cannot pass the Zero-Content event parser. The
private signing seed is never included. Platform derives organization authority
from the grant; no Runtime-supplied tenant or human identity is accepted.

Successful JSON is a closed `schema_version: 1` envelope containing `enrollment`
with exact `runtime_ref`, `enrollment_ref`, integer `enrolled_at_ms` from zero
through 253402300799999 and `status: "active"`. Unknown/duplicate fields, floats,
exponent numbers, malformed UTF-8, unsupported versions and different references
fail. Server time is informational, not local clock authority. A receipt cannot
authenticate its sender: the caller must establish HTTPS trust before accepting it.

## Ownership and recovery

Keys, codes and signed claims cannot be generically formatted, cloned or serialized.
Secret-bearing allocations are zeroized on drop. Deliberate claim-byte access is
only for the bootstrap transport; embedders must not copy it into logs or storage.
The private key exports only through a `Secret` for native storage. Validated
receipts have no public constructor/Deserialize bypass. Errors contain fixed
categories and recovery instructions, never raw input or provider diagnostics.

Secure orchestration must persist pending material through the OS-native broker
**before** sending and retry an uncertain outcome with the identical identity and
proof. Receipt validation alone does not mark any state durable or enable a sender.
The native lifecycle implements that ordering and exact recovery. The optional
HTTPS component validates one bounded response, while the caller still owns
durable confirmation. The [enrollment CLI](ENROLLMENT_CLI.md) composes these
operations with hidden entry and explicit recovery. Signed telemetry remains a
subsequent slice.
This library alone does not complete MCP-018.

Zeroization does not protect against same-user/root memory access, crash dumps,
swap, an explicitly copied value or a caller's diagnostic hook. Possession proof
does not attest hardware, workload identity or a human. Revocation and grant
expiry remain Platform authority; a previously accepted receipt is not ongoing
authorization. Local protection must continue during a Platform outage.

## Executable synthetic demonstration

From the repository root (Rust toolchain from `rust-toolchain.toml`; Node 20+ for
the independent built-in OpenSSL verifier):

```sh
cargo test -p mitigate-enrollment --locked
cargo run -p mitigate-enrollment --example proof --locked > target/enrollment-fixture.json
node scripts/verify-enrollment.mjs target/enrollment-fixture.json
```

Only the hard-coded **public synthetic** seed (32 bytes of decimal 23), token
(32 bytes of decimal 41), example domain and references are used. The example
does not accept credentials/input or access native storage/network. Its output
must never be repurposed to print real claims. The checked-in vector is reproduced
independently by Node/OpenSSL; Rust must produce the identical signature and six
fields. Both verifiers reject mutation of every signed field and final LF.
CI runs this demonstration on Windows, macOS and Linux.
