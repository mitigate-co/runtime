# ADR-0045: Build release files before issuing publisher attestations

Status: Staging implementation; authentic signing and release acceptance pending
Date: 2026-09-29

## Decision

Build each release on its native hosted runner from the exact reviewed clean
source. Check source/tag/CI evidence before and after the build. Reuse the bounded
installer archive contract to validate both private candidate bytes and final
release files. Candidate parsing is structurally separate from the installer's
signed-release entrypoint and does not confer publisher trust.

On macOS, sign and notarize a private binary copy through fixed native tools and
an explicitly prepared Keychain identity/profile before constructing final
digests. Recheck Developer ID, the independently selected team and notarization
with the same native verification used at install time. Do not modify user
Keychains, add permissive entitlements or submit a workspace to Apple.

Publisher attestations must cover the final bytes after all platform-specific
signing. Staging returns no claim of publisher authentication and never publishes
or activates its output. A later direct protected release workflow must compose
these primitives and pass authentic installation/fresh-machine acceptance.

## Consequences

No new dependency or Runtime data-path change. A local input file or mutable CI
candidate cannot replace the current native build. Existing output is preserved;
partial new output after failure cannot be reused for publication. The trusted
runner remains a prerequisite, and context environment strings are not a
signature. No insecure compatibility path is added to the installer.

Real Apple credentials, protected-workflow configuration, authentic attestation
verification and unresolved native security failures remain external acceptance
work. This decision introduces no public release or production deployment.
