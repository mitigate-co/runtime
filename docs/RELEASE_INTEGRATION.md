# Runtime release integration

This integration assembles the prepared release and local-support series on
protected main `7066315`. The individual PRs remain the review history for each
boundary; the integration must pass its own complete native and security checks.
No prior failed run is erased or treated as resolved by this integration.

| Review | Included concern |
| --- | --- |
| #52 | Bounded publisher attestation verification |
| #56 | Verified new-directory installation and native Apple verification |
| #59 | Native release staging without executing the candidate |
| #60 | Signed source, existing environment and current blocker policy gates |
| #61 | Temporary isolated Apple signing credentials |
| #62 | Separate build, signing and installation-acceptance runners |
| #63 | Authenticated Homebrew draft and native cask-loader verification |
| #54 | Source quickstart, disclosure and research methodology |
| #55 | Closed local diagnostics export and support workflow |
| #64 | One PR validation matrix, plus protected-main source validation |

The branches are merged into this review branch without rewriting their history.
Protected main requires linear history, so the integration uses a squash merge.
After that merge, superseded PRs may be closed only after verifying the final tree
contains their changes. Their branches, commits, CI results and review diffs remain
available. Do not merge the superseded series again or bypass required checks.

Conflict resolution retains the current inventory/corpus/failure evidence and
combines the documentation for the release and diagnostics slices. The integration
also creates the owned test tap's `Casks` directory; Homebrew's `tap-new` scaffolds
only `Formula`, so the earlier fixture's directory assumption was invalid. Runtime payload,
authorization, clock, retention, consent and storage contracts are unchanged.
The new diagnostics command reads no customer state by default and never uploads.

## Acceptance boundaries

Normal PR checks build four native unsigned candidates and test helpers with
synthetic publisher/Apple fixtures. The native Homebrew test loads an owned local
test cask; it does not install, download or publish a package. These results do
not prove genuine signing, notarization or customer installation.

The manual release workflow remains undispatched. It has no publication step.
Both selected-tag and current-main blocker policies must be clear, and real
provider identity, protected-environment approval, signed tag and native acceptance
are still required. Issues #36, #46, #50 and #57 retain their technical release
blocks. Closing an issue or passing a later run is insufficient evidence of a fix.

The optional private Platform is a separate repository and approval boundary.
Its blocked hosted CI and provider acceptance cannot be satisfied by Runtime CI.
No deployment, public release, tag, package tap, signing environment or credentials
are created by this integration.

Rollback before dispatch is to leave the manual release workflow unused. For
installed-state compatibility, follow [upgrade and rollback](UPGRADE_AND_ROLLBACK.md);
never restore revoked authority or old consent by restoring stale local databases.
