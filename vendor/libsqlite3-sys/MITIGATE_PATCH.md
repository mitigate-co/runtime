# Mitigate bundled SQLite patch

Base: `libsqlite3-sys` 0.38.2 from crates.io, MIT.
Original crate SHA-256:
`f1d20bef17f513b9b3004532233187769cd072d790971f4e4da0e346eb6401e8`.
Upstream: https://github.com/rusqlite/rusqlite.

The newest published binding on 2026-09-28 bundled SQLite 3.53.2. SQLite 3.53.4
contains journal-recovery and malformed-database fixes relevant to local audit,
including restrictions on unlinking a crafted hot journal's super-journal path.
Do not ship the older C source merely because RustSec has no binding advisory.

Replace only `sqlite3/sqlite3.c`, `sqlite3/sqlite3.h`, `sqlite3/sqlite3ext.h` with
the unmodified public-domain upstream 3.53.4 amalgamation. Source archive:
https://sqlite.org/2026/sqlite-amalgamation-3530400.zip.
Archive SHA-256:
`1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d`.
The C file also matches the independently published release SHA3-256:
`67f423e9ebbbdc473cbc4772c872ee6b89f31fde4ed0279a5c25d5f65c043a16`.

The 3.53.2→3.53.4 header diff contains version constants and documentation only;
no function, layout or ABI declaration changes. Update the five corresponding
version/source/tag/date constants in both bundled Rust binding files. Remaining
binding code, build script, notices and manifest are unchanged. The unused
SQLCipher source directory and Cargo's local registry bookkeeping are omitted;
this vendored copy supports the Runtime's bundled SQLite feature selection, not
SQLCipher. WASI support files are retained as upstream source, not launch support.

`scripts/verify-vendored-sqlite.py` verifies the three C/header file digests in CI.
Audit tests check the compiled library version. Our code uses no arbitrary SQL,
extension-loading API, virtual tables or user-defined SQL functions. Upstream C
build defaults remain intact; the Rust API feature selection stays restricted.
Runtime's own unsafe-code prohibition remains unchanged.

Gitleaks' generic-key heuristic mistakes three `sqlite3_api` member identifiers
and `FTS5_AVERAGES_ROWID` for keys. Its exception matches only those exact C
expressions in these two pinned upstream files; all other content remains scanned.
Original source whitespace is preserved so provenance hashes remain stable.

Remove this patch when a reviewed published binding bundles at least these fixes
and the same cross-OS audit/fixture suite passes. The root Cargo patch must be
preserved in binary builds; standalone crate publishing needs explicit packaging
review before release, as with the process-wrap patch. No binary/source package
release is claimed by this change.

References: https://sqlite.org/releaselog/3_53_4.html and
https://sqlite.org/src/timeline?from=version-3.53.0&to=version-3.53.4&to2=branch-3.53&y=ci.
