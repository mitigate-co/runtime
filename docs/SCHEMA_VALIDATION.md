# Local tool schema validation

`StdioServer::call` compiles the selected tool's input and optional output schemas
before refreshing inventory or invoking anything. Invalid arguments fail locally.
A valid result is returned only after MCP structural checks and, if declared,
output-schema validation. Invalid/missing success output invalidates and terminates
the connection. No call is retried: a server may already have performed effects.

Schemas, arguments and results remain in local memory. There is no file/network
retrieval, content logging, persistence, coercion or insertion of defaults. Fixed
errors omit dependency diagnostics, schema paths, property names and values.
`ToolSchema` has no Debug/Serialize implementation. Library embedders must also
keep their own logging and panic diagnostics free of sensitive content.

This is a validation boundary, not authorization. The CLI still serves inventory
only; grants, signed policy, approvals, emergency controls and full call audit must
be composed before public tool invocation is enabled.

## Execution profile

The profile is `mitigate-tool-schema-2020-12-v1`, implemented using pinned
`jsonschema` 0.58.2. Root schemas require `type: object`, consistent with the
negotiated MCP revisions through 2025-11-25. The default dialect is JSON Schema
2020-12. An explicit `$schema` must equal
`https://json-schema.org/draft/2020-12/schema`. Other dialects are refused for
execution; inspection still reports their definitions.

Supported assertions include types, enum/const, numeric bounds/multiples, string
length/pattern, object properties/required/dependencies, property names, arrays,
prefix/items/contains/uniqueness, boolean schemas, allOf/anyOf/oneOf/not,
if/then/else and unevaluated properties/items. The official embedded meta-schema
checks keyword types. Acyclic local JSON-pointer `$ref` targets must point to
recognized schema locations in the same document; `$defs` is supported. Escaped
pointer keys use `~0` and `~1`; URI percent encoding is refused.

External/relative references, anchors, `$id`, dynamic references, custom
vocabularies, unknown keywords and cyclic references are refused. This is an
explicit bounded execution profile, not a claim of unrestricted JSON Schema
support. Even unused schema definitions are checked. Objects inside `const`,
`default` and `examples` remain data and are never interpreted as references.

`format`, content encoding/media type, title/description/comment, default/examples,
deprecated/readOnly/writeOnly are annotations, not assertions or policy. In
particular, `format: email` does not validate an email address in this profile.
Format-assertion vocabularies are not accepted. `contentSchema` is unsupported.

Patterns use the dependency's linear-time `regex` engine, with its supported
ECMA translation. Backreferences and lookaround are refused. They are never
silently evaluated with a backtracking fallback.

## Limits and lifecycle

| Boundary | Limit |
| --- | --- |
| Serialized schema | 64 KiB per input/output schema |
| Raw value structure | Depth 32; 32,768 nodes; 1,024 entries per container; strings 64 KiB; keys 4 KiB |
| Arguments / validation value | 60,000 bytes / 1 MiB, respectively |
| Schema locations | 256 |
| Expanded reference/applicator path | Depth 32, no cycles |
| Expanded schema weight | 1,024; each unevaluated boundary multiplies its weight by four |
| Patterns | 32 per schema, 256 bytes each |
| Compiled regex / DFA cache | 64 KiB each per pattern |
| Schema weight × value complexity | At most 4,194,304; complexity is nodes plus rounded-up text bytes / 16 |
| Concurrent blocking validation jobs | Four per process |
| Compilation or validation caller wait | Two seconds including waiting for a worker |

Structural bounds are checked before serializing library-created values or
entering the dependency compiler. The weight is a conservative admission estimate,
not a measured CPU instruction count or latency guarantee. The reference graph is
checked independently of dependency resolution.

Compilation and validation run off the async listener thread. Timeout or dropped
call futures cannot dispatch a tool after the caller has gone. A worker that has
already started cannot be forcibly interrupted by Tokio; it keeps its semaphore
permit until completion. This limits detached work to four jobs. The schema and
value limits still apply. This is not OS process isolation or a sandbox.

Pre-dispatch schema/argument rejection leaves a healthy upstream usable. Once
dispatch begins, output mismatch, validation exhaustion, timeout or cancellation
poisons the session and triggers process cleanup. A result marked `isError: true`
may omit structuredContent. If it includes structuredContent, this profile still
requires conformance; servers returning a separate structured error shape must
describe that shape in their output schema. This stricter choice is documented
in ADR 0019.

## Verify and demonstrate

```sh
cargo test --locked -p mitigate-mcp --lib schema
cargo test --locked -p mitigate-mcp-fixture --test upstream
cargo run --locked -p mitigate-mcp-fixture -- schema-contract
```

These commands use synthetic values and this repository's own fixture executable.
The demonstration does not run arbitrary configurations or contact a provider.
CI runs it on Windows, macOS and Linux alongside the existing privacy gates.
