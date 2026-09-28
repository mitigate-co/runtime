# Enroll a Runtime

Enrollment is optional. Local scanning and MCP protection require no account.
The `enroll` commands connect a native Runtime identity to the selected Platform
organization. They do not enable telemetry or upload local audit records.

## Start and recover

In Platform, an authorized organization administrator creates a short-lived code
from the organization's Runtimes page. Use the organization's canonical HTTPS
origin and a new state filename in an existing private local directory. Keep that
path for status and recovery. Do not place codes in arguments, environment
variables, shell history or plaintext files.

`enroll start --platform ORIGIN --state FILE` prompts for a hidden code. Paste it,
then press Enter. Backspace removes a character; Ctrl-U clears the entry; Ctrl-C
or Ctrl-D cancels before any enrollment is created. No characters or asterisks are
echoed. Invalid or oversized input is drained through Enter while echo stays off.
The owned input buffer is fixed at 85 bytes and zeroized when released.

Add `--stdin` to read a secure pipe. The pipe producer must obtain the secret
securely; `echo CODE` is not a safe producer. `--json` requires `--stdin`, keeping
machine error output free of prompt text. Pipe input accepts the 85-byte code
with an optional LF or CRLF; other whitespace and extra bytes fail. Interactive
input requires terminal stdin and stderr; it never falls back to echoed input.

The command stores a fresh key, code and opaque references in the OS-native
credential broker before sending one verified HTTPS request. The state file
contains only the Platform origin and a random credential reference. It is never
overwritten. The same operation lock covers transmission and durable receipt
confirmation. Confirming enrollment removes the one-use code from native storage.

After a timeout, failed response or interrupted write, inspect/retry the original
state. A remote acceptance may have occurred even if its response was lost:

```text
mitigate enroll status --platform ORIGIN --state FILE
mitigate enroll retry --platform ORIGIN --state FILE
```

These are command templates; replace `ORIGIN` and `FILE` with the original values.
Pending retries reuse the exact identity and code. Confirmed retries return the
local receipt without a network request. Status always stays local and does not
assert that access is still active remotely. Never erase state or generate a new
identity just because a response was lost.

## Remove a local credential

```text
mitigate enroll forget --platform ORIGIN --state FILE --confirm
```

This deletes only the native entry bound to the supplied anchor and verifies its
absence. Repeating it is safe. The anchor remains for recovery and concurrent-use
protection. This is local credential removal, not remote revocation: revoke the
Runtime in Platform separately. It does not purge a queue or stop another process.
There is no automatic sync sender in this implementation. Future sync composition
must stop delivery and purge the scoped queue before forgetting a credential.

## Reports and failures

`--json` emits schema version 1. Pending/confirmed reports include `status`,
`runtime_ref`, `enrollment_ref` and `sync_enabled: false`. Confirmed reports also
include `enrolled_at_ms`, the informational timestamp from the stored receipt.
Forgotten reports omit the references and timestamp. A receipt is not sync consent.

Errors use fixed categories on stderr, without echoing input, local paths, claim
bytes, transport headers or OS-provider details. `enrollment_exists` means inspect
the original state; `enrollment_busy` means wait for its owner; native-store
failures require unlocking/recovering the store. HTTP rejection and lost responses
preserve pending state for an explicit retry. A locked broker or unavailable
Platform does not prevent local MCP operation.

See [native storage](ENROLLMENT_STORAGE.md) and [HTTPS policy](ENROLLMENT_HTTPS.md)
for parent-directory trust, locking, certificate roots, timeouts and buffer limits.
Enrollment is a separate authorized credential bootstrap, never an event admitted
through the Zero-Content telemetry schema.

## Executable checks

```sh
cargo test -p mitigate-cli --locked
cargo build -p mitigate-enrollment --example native_lifecycle --locked
cargo run -p mitigate-enrollment --example native_lifecycle --locked -- --allow-native-fixture --cli target/debug/mitigate
node scripts/verify-enrollment-cli.mjs target/debug/mitigate
python scripts/verify-enrollment-terminal.py target/debug/mitigate
```

The native lifecycle and Node commands create disposable synthetic native entries and
require an unlocked native store. Append `.exe` to the CLI path on Windows. CI uses
isolated macOS/Linux keyrings. The native fixture proves pending/confirmed restart
and local confirmed retry. The CLI fixture uses a loopback endpoint that cannot
complete TLS, proving no plaintext credential is sent, no implicit retry occurs,
pending identity survives, and precise/idempotent deletion retains the anchor.
No external endpoint, real enrollment code or insecure certificate option is used.
If native cleanup cannot be confirmed, the recovery anchor is retained.

On macOS, omit `--cli target/debug/mitigate` from the native lifecycle example
unless you intend to approve cross-application Keychain access. The unsigned
example and CLI have different application identities. macOS CI runs the receipt
fixture within its creating binary and the actual CLI lifecycle separately, each
with its own entries. It does not relax Keychain ACLs or automate user approval.
Signed release upgrades must verify continuity of application identity.

The terminal fixture uses POSIX PTYs or Windows ConPTY and only synthetic input.
It checks normal/edited input, over-limit pastes, invalid Unicode, cancellation,
no secret echo and exact mode restoration in a parent observer. Even a valid code
stops at an intentionally missing parent directory, before native storage/network.

Keyboard cancellation and ordinary errors restore the original terminal mode.
An OS failure to restore it returns an error before enrollment; close that terminal
before retrying. SIGKILL, process abort, console closure and external termination
cannot guarantee restoration. Standard-library and OS input buffers are outside
the owned-buffer zeroization guarantee. A same-user process can inspect memory or
the terminal. See [prompt decision and dependency review](decisions/0030-hidden-enrollment-input.md).
