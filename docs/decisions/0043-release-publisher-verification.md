# ADR-0043: Fixed publisher identity before release-file consumption

Status: Verification primitive implemented; signed release acceptance pending
Date: 2026-09-29

## Decision

Use the existing operator GitHub CLI's Sigstore verification for release files.
Do not invent a cryptographic format or place a new verifier in the sensitive MCP
request path. Fix the public Runtime repository, direct release workflow,
GitHub-hosted runner, Actions issuer and SLSA v1 identity policy. The caller must
independently select an exact stable version tag and source revision. Both source
and signer certificate claims must match them. Workflow-supplied predicate text
cannot replace certificate identity.

Copy bounded, regular local artifact/bundle inputs into private temporary storage
before verification. Only the authenticated snapshot may be consumed; an earlier
report cannot authorize reopening a mutable source path. The command is read-only
apart from its own temporary files. It prints fixed outcomes and public release
identity/digest fields, never provider errors or caller paths, and grants no
installation or publication authority.

## Consequences

GitHub CLI, its trusted roots, the operating system and reviewed release workflow
become verification prerequisites. GitHub authentication may be used by that CLI;
Runtime secrets and enrollment are unrelated. No Cargo/Python dependency or
Runtime network capability is added. Existing GitHub CLI is separately installed
MIT tooling, not redistributed in Runtime. The release signer must use the exact
direct workflow identity; introducing a reusable signer requires a reviewed
identity-policy change rather than an automatic exception.

The signed release workflow is not implemented by this primitive. Candidate
archives remain unsigned, and unit-test success against a mocked CLI is not
positive cryptographic evidence. Real signed artifact/manifest verification,
Apple signing/notarization, verified installation and all source/security gates
remain mandatory before distribution. No public release is created by this ADR.
