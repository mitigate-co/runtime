# ADR-0048: Generate a Homebrew cask only from authenticated Apple releases

Status: Implemented draft generator; actual package acceptance pending
Date: 2026-09-29

## Decision

Distribute prebuilt macOS artifacts through a cask with a fixed stable version,
architecture-specific archive SHA-256 and a binary link. Generate its draft on
macOS only after verifying every asset's publisher identity and both binaries'
Developer ID/team/notarization. Extract bounded minimum-OS/CPU facts from the
authenticated thin Mach-O files; never guess hashes or trust editable manifest
claims as a substitute for signatures. Write no draft if either target fails.

The generator does not publish a release/tap or authorize use. Review and native
ordinary-user install/uninstall acceptance precede a protected tap update.
Homebrew trusts the reviewed cask's pinned archive digest; users do not need to
install Python/GitHub CLI to repeat the maintainer's attestation verification.

## Consequences

The tap, Homebrew and native Apple trust become installation authorities. No
arbitrary download origin, unsigned fallback, inline install script, service,
secret handling, state migration or data-deletion hook is added. Linux/Windows
retain the separately verified directory install path. There is no claimed safe
rollback until a release-specific state compatibility decision is tested.

Tests use synthetic signed-layout archives and mocked signatures; native CI
loads the cask definition with actual Homebrew but never installs fixture bytes.
Actual signed-release and tap acceptance remain required. The narrow Mach-O
reader rejects unsupported layouts; it is not an executable loader or proof of
runtime compatibility. See [Homebrew distribution](../HOMEBREW.md).
