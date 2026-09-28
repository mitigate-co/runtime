# Local credentials

Mitigate uses Windows Credential Manager, macOS login Keychain, or Linux Secret
Service. No Platform account is needed. Launch documents contain opaque references,
not credential values. There is no plaintext credential database or automatic
fallback to an environment variable if a native lookup fails.

## Import and connect

Have your secret manager pipe a UTF-8 value into:

```sh
mitigate secrets import --stdin --json
```

This command requires piped input (terminal input is rejected to avoid echoing a
secret). It accepts 1–2560 bytes, rejects NUL, and strips one trailing LF/CRLF.
Do not type a credential into a shell command or save it to an example file.
The result contains only `schema_version: 1`, `action: "imported"`, and a random
`secret_ref`. Retain that reference in the reviewed launch document:

```json
{
  "schema_version": 1,
  "executable_path": "/absolute/path/to/reviewed-server",
  "working_directory": "/absolute/path/to/project",
  "argv": [],
  "secret_references": [
    {
      "environment_key": "PROVIDER_API_KEY",
      "secret_ref": "sec_00000000000000000000000000000000"
    }
  ],
  "timeout_ms": 30000
}
```

The reference above is illustrative: use the actual import result, and an absolute
`.exe` on Windows. `inspect` and `serve` require `--allow-exec` before lookup or
launch. All references must resolve before any upstream starts. Environment names
must be unique (case-insensitively) across `allowed_environment_keys` and
`secret_references`; a maximum of 32 explicit keys and 64 KiB of total environment
apply. Native bindings cannot overwrite SystemRoot, WINDIR, TEMP, or TMP.

```sh
mitigate secrets check --reference sec_00000000000000000000000000000000 --json
mitigate secrets replace --reference sec_00000000000000000000000000000000 --stdin --json
mitigate secrets delete --reference sec_00000000000000000000000000000000 --confirm --json
```

`check` never prints a value. `replace` requires piped input and an existing
reference. `delete` requires explicit `--confirm` and affects precisely one
reference. All commands use exit 0 for success and 2 for fixed, content-free
validation/store errors. Interrupted store writes must not be automatically
retried: verify the local state and deliberately repeat if necessary.

## OS behavior

- Windows: generic credentials under service `co.mitigate.runtime.credentials.v1`,
  Local persistence, explicitly avoiding the adapter's Enterprise-roaming default.
- macOS: the user's default login Keychain. Native access controls may display an
  OS permission prompt for a newly built/signed executable. No iCloud store is
  selected. Allow access only for the reviewed Mitigate binary.
- Linux: an existing unlocked default Secret Service collection and user D-Bus
  session are required. Locked or ambiguous matching items fail; Mitigate does not
  unlock collections. Secret Service transport uses its encrypted session mode.

On headless hosts without a native store, use `allowed_environment_keys` to name
specific variables supplied by your own secret manager. This is an explicit
alternative configuration, never an automatic fallback. No `.env` file is read.

## Boundaries and lifecycle

Native reads run only at authorized launch, inside the launch timeout and shutdown
boundary. Windows/macOS OS calls run off the async reactor; an in-flight OS call
cannot itself be cancelled. Cancellation prevents any subsequent child launch and
drops the returned value. The single-command CLI bounds Tokio shutdown; embedders
must do the same if native UI can remain blocked. Explicit management commands wait
for the native operation to finish; they do not claim a timed-out write was undone.

Owned credential allocations are cleared on drop. Standard-library/OS environment
copies, native-library buffers and the upstream's memory are not all guaranteed to
be wiped. Credentials remain available to the authorized upstream and descendants
for their process lifetime. After rotation/deletion, restart those processes and
revoke the old credential at the provider if required. Deleting a local reference
does not revoke a provider token already copied elsewhere.

This is not a sandbox or protection against malicious code with the same OS-user
privileges. Only launch trusted programs. Tool arguments/results remain local MCP
content; a server could return a credential in that content. Normal CLI inspection
reports omit schemas/descriptions and values; the inventory-only gateway necessarily
relays raw definitions to its local MCP client. No secret value is permitted in
operational diagnostics or Platform telemetry.

## Verification

After `cargo build --workspace --locked`, run:

```sh
target/debug/mitigate-test-mcp secret-contract target/debug/mitigate
```

Append `.exe` on Windows. This explicitly creates one random temporary synthetic
credential, exercises the actual CLI and child environment, then deletes exactly
that reference (including assertion failure cleanup). It verifies rotation,
missing-reference launch prevention, no ambient fallback and canary-free output.
CI runs against Windows Credential Manager, a temporary macOS Keychain, and an
isolated Linux D-Bus/Secret Service instance. It does not use customer credentials.
