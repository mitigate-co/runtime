# ADR 0018: Bind governance to an explicit local launch review

Status: accepted. Date: 2026-09-28. Scope: enforcing-gateway prerequisites.

## Problem and decision

Server-reported names and scanner summaries are insufficient execution identity.
A different executable/configuration could report the same name and inherit a
name-based grant. Add an explicit private launch review and content-free receipt.
The binding includes executable bytes, canonical/requested paths, argv, cwd,
ordinary environment, native reference destinations, timeout and selected code
artifacts. Native credential values are neither read during review nor hashed.

Use the existing versioned JCS fingerprint code with a separate launch domain
and a random 32-byte local salt. Artifact bytes use SHA-256. The salt stays in a
private local document; the launch reference, executable digest and artifact
count are the local receipt. No signature or anonymity guarantee is implied.
Separate fresh reviews intentionally produce separate launch references.

Reviewed connection construction recomputes the binding before spawn and uses
the captured checked environment and canonical paths. File pins are rechecked
after inventory refresh and before tool invocation; drift invalidates the connection.
An explicit artifact list avoids interpreting arguments as paths or scanning
unrelated files. Existing inventory-only operation remains available without a
review; enforcing composition must require a reviewed connection.

## Dependency and privacy impact

This adds direct edges to already pinned/reviewed `sha2 = 0.10.9` (MIT/Apache-2.0)
and `getrandom = 0.4.3` (MIT/Apache-2.0). There are no external package/version or
feature changes. They provide hashing and OS randomness; neither introduces a
network/telemetry path. Existing platform implementations/unsafe dependency
boundaries are unchanged; own code remains unsafe-forbidden. No new cryptographic
primitive is implemented. Hashing runs outside the async reactor and is bounded.

Review source values live in process memory while computing the binding and are
not serialized. Whole-process memory/swap protection is not claimed. The local
review is not a Platform event, and neither its salt nor config facts may be
forwarded to telemetry. Secret rotation at a fixed native reference remains
supported. Local audit may use the launch reference instead of the server's
self-reported name when a review is explicitly supplied.

## Limits, migration and rollback

Existing launch v1 documents still work; `artifact_paths` is optional. This does
not measure unselected transitive code, authenticate publishers, sandbox tools,
or replace grants/policy/approval/schema validation. Same-user privileged file
replacement races remain outside the trust boundary. Files/code and reviews
need protected directories. Strict 8 KiB review and 512 MiB selected-code limits
bound work; docs specify individual limits and cancellation behavior.

Review documents are newly created, never silently migrated or overwritten.
Changing a binding requires re-review and reconsidering dependent permissions.
Rollback may remove optional inventory review support, but must never turn a
required enforcing review into unchecked execution. See [review contract](../LAUNCH_REVIEW.md).
