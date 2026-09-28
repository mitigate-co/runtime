# ADR 0013: Bounded local SQLite audit

Status: accepted for MCP-010; local implementation verified, cross-OS CI pending.

Use a dedicated local SQLite database with a closed, versioned event schema. Store
references, classifications, decisions and timing; never tool arguments/results,
descriptions, schemas, credentials, free-form errors or arbitrary metadata. Explicit
caller profile references are domain-separated hashes; unknown attribution remains
unknown. These local hashes are neither anonymization nor authorization and are
not automatically eligible for Platform sync.

Application writes append records. Retention is the only deletion operation:
transactionally remove an oldest prefix while retaining its chain anchor. Defaults
are 10,000 records, 30 days and 16 MiB of encoded records. The database has a hard
128 MiB page limit. DELETE journaling, FULL synchronous commits and automatic page
reclamation avoid an unbounded WAL. Retention runs on append and explicit prune;
an idle closed database is not a background scheduler. Clock rollback does not
move the retention clock backwards. Retention cannot securely erase old backups,
filesystem snapshots, SSD history or external copies.

Each record binds its sequence, preceding hash and canonical event to SHA-256.
Verify the complete retained chain on open and before export. Reject corruption
without rewriting or resetting the database. This detects accidental corruption,
unrecomputed edits and missing rows; it is NOT tamper-proof against a local user
who can rewrite the database and recompute the chain, or restore an old copy.
An external signed anchor would be a separate future trust boundary.

Create files exclusively with Unix mode 0600; Windows inherits the selected
directory's ACL. Operators must use a private local directory, not a shared or
network filesystem. Reject linked/reparse database files. No path API can protect
against an administrator or a same-user attacker controlling the parent directory.
Database errors are mapped to fixed diagnostics, never SQLite messages or paths.
Enforcement integration must durably audit before invoking a tool; an unavailable
required audit must fail closed. Inventory-only CLI audit is explicitly selected.

## Dependency review (2026-09-28)

SQLite is prescribed by the MCP low-level specification. The standard library has
no SQLite binding. Select pinned `rusqlite` 0.40.2 (MIT), defaults disabled, with
`bundled`, `limits` and `hooks`. It is maintained by rusqlite contributors. The
native binding `libsqlite3-sys` 0.38.2 is MIT. Its bundled SQLite 3.53.2 is replaced
with unmodified public-domain SQLite 3.53.4 source: the newer patch has relevant
journal-recovery and malformed-database fixes absent from RustSec's binding scan.
See `vendor/libsqlite3-sys/MITIGATE_PATCH.md` for archive/file hashes, ABI review
and removal criteria. CI checks provenance and the compiled version; Runtime
refuses older libraries. Bundling provides consistent behavior across supported OSs and requires a
C compiler at build time. It adds native C/FFI unsafe code upstream; Runtime's own
unsafe-code prohibition remains. New direct runtime helpers are fallible-iterator
and fallible-streaming-iterator; build helpers include cc/pkg-config/vcpkg.

The lockfile increases from 186 to 196 entries: nine external packages and the
audit crate. No unrelated package versions change. Cargo-audit reports no known
advisories; cargo-deny licenses/bans/sources pass. Existing duplicate-version
warnings in the SHA-2 families and syn remain visible.

No extension-loading, tracing, custom SQL, database URLs, network transport or
telemetry feature is selected. Use defensive mode, disable trusted schema,
bound SQL/row sizes and execution, and validate the exact known schema before
application writes. Only fixed parameterized SQL executes. Audit sits on the
local request path, so disk failure and contention must be explicit outcomes.

Sources: [rusqlite](https://github.com/rusqlite/rusqlite),
[SQLite 3.53.4](https://sqlite.org/releaselog/3_53_4.html),
[SQLite defensive guidance](https://sqlite.org/security.html),
[SQLite copyright](https://sqlite.org/copyright.html).
