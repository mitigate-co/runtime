# ADR 0012: Native secrets and scoped stdio injection

Status: accepted for MCP-009; native Windows/macOS/Linux verification passed in PR #10.

Use a small Runtime secret broker with opaque, random `sec_` references. Values
remain in the current user's native store: Windows Credential Manager with Local
machine persistence, macOS login Keychain, and Linux Secret Service. No plaintext
fallback, global keyring provider, cross-account search, or Platform dependency.
Headless users may keep using explicit environment references supplied by their
own secret manager. A missing native credential never falls back to an ambient
variable with the same name.

Native lookup is separate from untrusted discovery and only occurs after explicit
launch authorization. The reviewed launch document maps references to individual
child environment keys. Resolve all references before spawning; reject conflicts
and failures. Keep values in zeroizing owners until spawning, then drop them.
The standard library and OS necessarily copy the child environment; this is not
a guarantee that every allocation, crash dump, swap page, or descendant is wiped.
The authorized upstream receives the credential for its process lifetime and can
read/use it independently. Grants gate relayed calls, not arbitrary OS behavior.

## Dependency review (2026-09-28)

Standard Rust has no native credential-store API. Direct platform FFI in our code
would duplicate sensitive, unsafe interoperability code. Use pinned, permissively
licensed maintained libraries, with platform dependencies compiled only for that OS:

- `keyring-core` 1.0.0 and `windows-native-keyring-store` 1.1.0 (search feature off).
  MIT OR Apache-2.0, maintained by open-source-cooperative. Windows adds byteorder,
  windows-sys and zeroize. API errors can contain source data: never format them.
  Source review confirms native-buffer zeroization and no secret-value logging.
  Set persistence to Local explicitly; the library default is Enterprise.
- `apple-native-keyring-store` 1.0.2, only `keychain`, using security-framework.
  MIT OR Apache-2.0. Uses native Keychain memory management; no iCloud/protected
  store feature is selected. Native Keychain may request user permission.
  Native contract tests keep credential reads in the same CLI application that
  imported them; macOS can prompt when a different executable tries to read.
  The real child checks both the initial and rotated values after injection.
- `secret-service` 5.2.0, only `rt-tokio-crypto-rust`, on Linux. MIT OR Apache-2.0.
  Uses zbus for local D-Bus and RustCrypto for the Secret Service protocol. This
  adds an IPC/crypto dependency graph but avoids native libdbus/OpenSSL packaging.
  Source review confirms OS randomness for key exchange/IVs. Query only our fixed
  service and exact reference; locked/ambiguous items fail. No implicit unlock.
  D-Bus/OS store access is a local trust boundary, not hosted telemetry.
- `getrandom` 0.4.3, MIT OR Apache-2.0, rust-random: OS randomness for references.
- `zeroize` 1.9.0, Apache-2.0 OR MIT, RustCrypto: optimizer-resistant clearing of
  owned values on every return path. No serialization/clone/debug on secret owners.

Native APIs, zbus and zeroize contain reviewed upstream unsafe/system code. Our
`unsafe_code = forbid` remains in effect. No logging subscriber, telemetry client, HTTP client,
or arbitrary secret provider plugin is introduced. Store reads are on the launch
path, not every tool call. The resolved graph, licenses and RustSec advisories are
checked by cargo-deny/audit and all platform CI before merging.

The lockfile grows from 103 to 186 packages (82 external packages plus the broker
crate), including all OS/build-only entries. Most growth is Linux's zbus/RustCrypto
stack. Windows adds only its native adapter/core, byteorder, zeroize, getrandom and
the log facade to the selected graph. Cargo-audit finds no advisories; license/source
checks pass. Cargo-deny reports version duplication in the old/new SHA-2 dependency
families and syn; these remain visible warnings, not suppressed security findings.

Rejected `dbus-secret-service` 4.1.0 and its keyring adapter: source inspection
found `fastrand::Rng` used for private DH key bytes and IVs. We do not ship it.
The full keyring CLI/wrapper is unnecessary. Linux kernel keyrings have different
persistence semantics; they are not a silent replacement for Secret Service.

Sources: [keyring-core](https://github.com/open-source-cooperative/keyring-core),
[Windows adapter](https://github.com/open-source-cooperative/windows-native-keyring-store),
[Apple adapter](https://github.com/open-source-cooperative/apple-native-keyring-store),
[Secret Service](https://github.com/hwchen/secret-service-rs),
[zeroize](https://github.com/RustCrypto/utils),
[getrandom](https://github.com/rust-random/getrandom).
