# ADR-0047: Separate builds, signing and installed release acceptance

Status: Implemented; authentic signing and owner dispatch pending
Date: 2026-09-29

## Decision

Use one direct, manual, tag-bound release workflow with separate fresh hosted
jobs for source preflight, native builds, signing and installation acceptance.
Build scripts and downloaded binaries never run in the job holding signing keys
or OIDC attestation authority. Every native build must succeed before any signing
job begins; every signing job must succeed before acceptance begins.

Transport exact same-run immutable artifacts with digest mismatch treated as
failure. Attest the archive, manifest, SBOM and checksums only after native Apple
signing/notarization and successful credential cleanup. Verify every final file
and require sidecar consistency with the authenticated archive. Install with the
real installer on a separate read-only runner before actual CLI smoke checks.

The workflow has no repository-write permission or publication step. Current
source/failure policies and existing protected signing environment configuration
are checked before build and again around signing. Merging tooling is not
authorization to create signing credentials, dispatch a run or publish a release.

## Consequences

More fresh runners and repeated verification are intentional costs of separating
executable code from publisher authority. GitHub, the pinned actions, reviewed
release code and native runner tools remain trusted. Workflow context strings
are local guards, not independent signatures. A malicious trusted signing job or
repository administrator remains outside this boundary.

Normal CI validates workflow syntax and adversarial helper contracts without
keys. It cannot establish authentic Apple/Sigstore success. Public Actions
artifacts and signing metadata are not customer data and are not an approved
release. No local Runtime security/privacy invariant or stored data changes.

See the [pipeline runbook](../RELEASE_PIPELINE.md) for inputs, permissions,
failure handling, tool provenance and remaining acceptance work.
