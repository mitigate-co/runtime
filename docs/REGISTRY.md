# Public registry facts and offline lookup

`mitigate mcp registry lookup` reads an explicit public catalog and shows all
matching source-attributed claims. It needs no account and makes no network
requests. It does not install a server, launch code, refresh a catalog, change
capability classifications or modify grants/policy. The lookup output is local
diagnostic data, **not a Zero-Content telemetry event**.

This is the public Runtime contract/client portion of MCP-017. Hosted import,
curation, a public API and its UI belong in private Platform and remain separate
acceptance work. There is no live public registry endpoint in this implementation.

## Try the synthetic catalog

From a Runtime checkout:

```sh
cargo run --locked -- mcp registry lookup --catalog examples/registry/catalog.json --subject io.example/synthetic-server
cargo run --locked -- mcp registry lookup --catalog examples/registry/catalog.json --subject io.example/synthetic-server --json
cargo run --locked -- mcp registry lookup --catalog examples/registry/catalog.json --subject io.example/unknown-server --json
```

The checked-in catalog uses reserved example domains and synthetic package names.
It asserts nothing about a real project. Its fixed dates intentionally become
expired: fixtures never refresh themselves or invent current evidence.
`cargo run -p mitigate-registry --example lookup --locked` demonstrates the same
library at a fixed synthetic observation time without the rest of the CLI.

Valid queries exit 0 even when no facts match or the catalog is expired/future
dated. Check `found` and `freshness`; absence is unknown. Rejected input and file/
clock failures exit 2 with a fixed diagnostic and no partial output. Paths,
rejected fields and raw parser errors are never included in failure messages.

## Version 1 import contract

The document is closed: `schema_version`, `generated_at_ms`, `expires_at_ms`,
`sources` and `facts` are required. Unknown keys, duplicate JSON keys, unsupported
versions and missing fields are rejected before lookup. Limits are 1 MiB, 64
sources and 1,024 facts; strict JSON parsing also bounds depth, nodes and strings.
There are no arbitrary descriptions, installation instructions, scripts, opaque
scores or generic metadata. Format checks do not prove that a claim is true.

Every source has a unique `source_ref`, a public HTTPS reference `url`, a declared
`kind` and a `retrieved_at_ms`. Kinds are `publisher`, `package_registry`,
`advisory_database` or `independent_review`. These types describe where the
publisher says evidence came from; they do not authenticate that publisher.

Every fact requires:

| Field | Meaning |
| --- | --- |
| `fact_ref` | Unique bounded catalog-local claim identifier |
| `subject` | Public reverse-DNS namespace/server, e.g. `io.example/synthetic-server` |
| `source_ref` | Existing source in this document |
| `observed_at_ms` | Declared time the claim was observed |
| `confidence` | Publisher-declared `low`, `medium` or `high` |
| `assertion` | One of the closed assertion variants below |

Assertions are `repository` (URL), `package` (npm/PyPI/crates.io, canonical package
name and exact bounded version), `transport` (stdio/streamable HTTP/SSE),
`capability` (the fixed eleven-label taxonomy), `release` (version and publication
time) or `advisory` (CVE/GHSA-format identifier and supporting URL). A transport
claim does not add an adapter. A capability claim is not a local classification
or permission. An advisory reference is not a conclusion that a deployment is
vulnerable. This contract does not evaluate version ranges or advisory applicability.

Catalog-local identifiers are lowercase ASCII slugs, at most 64 bytes. Subjects
are at most 192 bytes, with canonical lower-case namespace components and a
64-byte server name. URL references are canonical ASCII HTTPS, at most 2,048
bytes, without credentials, explicit ports, query strings or fragments. IP hosts
and common local suffixes are rejected. They are **display references only**:
Runtime performs no DNS lookup or HTTP request and makes no claim about where a
domain resolves. Future fetchers must apply their own SSRF and redirect controls.

Times are unsigned UTC milliseconds through year 9999. A source's retrieval must
be at or before catalog generation; an observation must be at or before its
source's retrieval; a release cannot postdate its observation. Expiry must be
strictly after generation and within 30 days. Those relationships detect
inconsistent imports, not forged evidence or rollback. The source determines
how recently facts were revalidated; `current` describes the catalog interval,
not each individual claim's age.

## Lookup and trust

Lookup returns all facts for the exact subject, deterministically ordered by
subject, source, observation and fact identifier, plus only their referenced
sources. Conflicting versions or capabilities from different sources remain
separate. No winning claim, accusation or risk score is invented.

The output includes observation/generation/expiry times, `found`, and `freshness`:
`future` before generation, `current` from generation up to exclusive expiry,
and `expired` at or after expiry. Stale/future claims are still available for
explicit diagnosis. `publisher_authenticated` and `grants_access` are always
false for these unsigned catalogs. Do not turn `confidence: high` into a trust
decision or auto-run an imported package.

The explicit file must be a regular bounded file. A final symlink/Windows
reparse point observed before open is rejected; the parent must be trusted.
This read-only helper does not prevent concurrent same-user path replacement,
authenticate local filesystem ownership or protect against someone controlling
the account. It never searches home directories, repairs files or writes caches.

## Verification and troubleshooting

Library tests cover source disagreement, unknown subjects, deterministic ordering,
every freshness boundary, inconsistent provenance/times, malformed/duplicate JSON,
unknown nested fields and hostile instructions, unsafe URLs, package/advisory
formats, collection/byte bounds, unchanged files and Unix symlinks. Actual CLI
tests cover human/JSON output, no-account operation, stale/unknown results,
explicit selection and fixed failure messages.

For schema/bounds/provenance errors, obtain a corrected catalog from its source.
For a future-dated catalog, verify the source and local OS clock. Do not change
grants to compensate for a missing catalog. Optional lookup failure has no path
into the local MCP gateway's authorization or availability.

No new external dependency/version is added. This crate reuses `serde`,
`serde_json`, `url` and the existing strict JSON parser. See
[ADR 0026](decisions/0026-source-attributed-registry-facts.md).
