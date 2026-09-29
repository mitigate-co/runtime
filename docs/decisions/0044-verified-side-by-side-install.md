# ADR-0044: Verify both release inputs before installing into a new directory

Status: Install primitive implemented; authentic signed distribution pending
Date: 2026-09-29

## Decision

Compose ADR 0043's authenticated snapshots for the manifest and archive with a
closed signed-release schema and bounded ZIP reader. Bind both signatures and
all packaged bytes to the operator's separately selected revision/tag and the
native target. Never treat an unsigned candidate, editable JSON verification
report, checksum file or mutable original path as installation authority.

Create a new operator-selected directory only after verification. Do not replace
existing installs, mutate PATH, execute package code, migrate authority or manage
an automatic updater. The Apple path additionally requires strict Developer ID
and notarization verification with a separately trusted team identity. Missing
trust material fails closed; production identities must not be invented.

## Consequences

The helper uses the standard Python library, the existing trusted GitHub CLI and
native Apple verifier. No Runtime dependency or egress schema changes. A full
bounded file map avoids archive-controlled extraction paths and allows all byte
checks before writing the selected directory. Exclusive creation prevents
overwriting another installation. The host and chosen parent remain trusted.

Disk/cleanup failures may leave a new incomplete installation; command failure
is authoritative even if receipt bytes appear complete. Retaining that directory
avoids unsafe cleanup through a path that may have changed. Installation receipts
are diagnostic evidence, not protected rollback counters or execution grants.

This side-by-side boundary supports future distribution wrappers but does not
itself complete release engineering. A direct signing workflow, authentic positive
Sigstore/Apple evidence, owned Apple identity, supported-system policy, release
notes and fresh-machine tests remain required before release.
