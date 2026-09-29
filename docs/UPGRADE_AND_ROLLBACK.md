# Runtime upgrade and rollback

There is no accepted public release or approved downgrade target yet. The first
release must explicitly record **no previous supported version**. A successful
older build is not automatically a safe rollback target.

## Install and activate separately

The directory installer verifies and writes a new directory. It does not edit
PATH, replace an existing executable, activate a service, migrate state or start
a gateway. Keep the previous verified binary while evaluating the new one in
fresh synthetic state. Record exact versions, source revisions and digests.

For an explicit upgrade, stop the old gateway/client process before changing
the executable selected by the client. Verify the new release and check the
release's state compatibility decision before allowing it to open existing
policy, approval, control, audit, enrollment or outbox storage. Run the documented
privacy and representative local operation checks before resuming normal use.

Homebrew owns its installed binary link and package lifecycle. Review the tap's
version/digest change before requesting an upgrade. The cask has no self-updater
or automatic migration; package removal does not remove customer Runtime state.

## Refuse an unproven downgrade

Never overwrite or restore authorization, audit, enrollment or outbox databases
just to make an older binary start. Restoring old state can revive spent approvals,
revoked authority, consent or previously delivered events. A file backup alone
does not establish a safe security-state rollback.

A release may name a rollback version only after testing it against the exact
schema/config transition and preserved revocation/consent/expiry semantics. If
that proof is unavailable, stop the affected gateway and optional sender, retain
the current local state for investigation and ship a reviewed forward fix.
Do not bypass clock/storage checks, activate an unsigned artifact or resume sync
as a recovery shortcut.

## Required release decision

Every release's reviewed notes must state:

- source revision, signed tag, archive digests and attestation location;
- supported/verified OS and architecture combinations;
- config/protocol/storage versions and any migration;
- whether opening existing state changes it, and whether that change is reversible;
- an explicitly tested previous version, or that no safe downgrade is supported;
- stop/activation and post-change checks, known limits and unresolved advisories.

The [release pipeline](RELEASE_PIPELINE.md) proves fresh installation composition
only after authentic signing and native acceptance. It does not prove downgrade
compatibility. Runtime rollback and hosted Platform/database rollback are separate
operations and must not share an assumed recovery procedure.
