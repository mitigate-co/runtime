# ADR 0020: Versioned local call audit

Status: accepted for implementation; cross-platform verification pending.

## Problem

The inventory-era audit envelope cannot correlate separate approval/dispatch/
completion records or attribute the approving operator. Adding optional fields
that serialize as null to every legacy event would alter its canonical exported
bytes. The governing gateway also needs to distinguish an unresolved dispatch
from a known pre-dispatch refusal.

## Decision

Keep version-one event serialization unchanged and introduce a version-two
envelope for governed-call metadata. A required closed `call` object contains
random session/call references, a phase, optional complete-definition/policy-bundle
fingerprints and optional declared operator/choice metadata. Nullable fields are
explicitly required. No names, comments, arguments, results, arbitrary objects or
argument hashes are added.

`append` continues to write version one. `append_call` validates the version-two
phase/decision/result invariants and commits using the same atomic append/retention
path. New decisions `allow_and_log`, `rate_limit`, `disable_tool`, and outcome
`uncertain` are accepted only in version-two events. This is local audit vocabulary;
it does not extend the signed Rego profile or grant authorization.

The database schema, chain domain and retention checkpoints are unchanged. Each
record hashes its own canonical envelope. Readers select validation by event
version, reject `call` even when null in version one, and require a complete
non-null `call` in version two. Unknown fields/versions and duplicate envelope
fields are refused. Old events are never rewritten or given synthetic correlation.

## Semantic boundaries

- `decision`: terminal refusal before dispatch, result `not_invoked`.
- `approval_pending`: resolved caller/tool/policy, `require_approval` and `pending`,
  with an approval reference and no attributed human choice yet.
- `dispatch`: known caller, resolved tool/schema/definition, signed policy bundle,
  allow/allow_and_log and `pending`. If approval is referenced, an approving
  operator must be present. Commit must complete before dispatch is attempted.
- `completion`: the same required authorization facts with success, error,
  cancelled or uncertain outcome. It must never claim `not_invoked` after dispatch.

An event is not a permission token. The caller must provide verified facts and
fresh random correlation IDs; the audit store does not authenticate the operator,
evaluate policy, consume approval, execute tools or prove code provenance. Existing
declared/unknown caller attribution remains unchanged. Operator source is explicitly
`declared_local`; a fingerprint is not proof of human authentication.

Phase validation is per record, not a global workflow state machine. Concurrent
calls can interleave, retention can remove earlier phases, and a crash may leave
a dispatch without completion. Missing completion means outcome unknown; it must
not be relabeled successful, failed or safe to retry. The gateway must own the
lifecycle and use identical facts/references across its phases.

## Migration, rollout and rollback

No table migration or history rewrite occurs. Current readers verify/export mixed
version-one and version-two chains. Older binaries cannot read version-two records
and must fail closed without altering the file. Preserve the original database
when rolling back; use a new explicitly initialized inventory-only database if
operationally necessary, never delete or downgrade retained call history.

The CLI still refuses real tool calls while gateway composition remains pending.
The human audit list shows the phase/call reference; JSON exports the closed full
context. Exports remain local and are not approved Platform telemetry contracts.

## Verification

Tests cover a frozen version-one JSON fixture and chain extension, byte/hash
preservation, interleaved writers, mixed-version retention/restart, corruption,
the phase/decision/result matrix, missing authorization facts, unknown identities,
operator requirements and prohibited/ambiguous fields. Existing full/busy-database
tests exercise the shared transactional append path. The executable audit fixture
checks actual CLI verify/list/human output and can optionally verify that a saved
version-one reader accepts old records and refuses mixed history without damage.

There are no new external dependency versions, cryptographic primitives, cloud
requests, privacy exceptions or OS permission changes.
