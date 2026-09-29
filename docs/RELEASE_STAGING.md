# Native release staging

`scripts/release/stage_release.py` prepares the native release archive, manifest,
SBOM and checksum list that a later publisher-attestation step must authenticate.
It never compiles code, executes a candidate, creates a GitHub release, uploads an
attestation, installs an executable or changes an existing installation. No release workflow
is enabled by this implementation.

This is build tooling for the direct `.github/workflows/release.yml` identity
reserved by [publisher verification](RELEASE_AUTHENTICATION.md). It refuses a
local invocation, feature branch, PR, fork, reusable workflow, self-hosted runner
or rerun. The invocation must identify the exact stable tag, full commit and
matching workflow revision in its `sign` job on a GitHub-hosted runner. Environment strings are a
context check, **not cryptographic authority**: a person controlling the host can
forge them. Consumers still require real attestations and native Apple trust.

The intended workflow invocation is:

```sh
python scripts/release/stage_release.py \
  --commit "$GITHUB_SHA" --tag "$GITHUB_REF_NAME" \
  --candidate dist/candidate --output dist/release
```

This is an interface example, not a currently usable release command. The output
parent must already exist and be trusted. On macOS the workflow must also supply
`--apple-identity` (40-character certificate fingerprint), `--apple-team`
(independently selected 10-character team ID), `--apple-keychain` (absolute path
to the prepared runner Keychain) and `--apple-notary-profile` (reference to stored
notary credentials). The tool does not accept passwords, API keys or private keys
as arguments and does not search a developer's Keychain for a convenient identity.

## Build and verification order

The workflow must first build and smoke-test all four native candidates in
separate unprivileged jobs. Those jobs receive no Apple keys, signing environment,
OIDC permission or attestation-write permission. Only after **all** succeed may
the `sign` jobs download each exact named immutable candidate from the **same
workflow run**, with artifact digest mismatch treated as an error. No arbitrary
repository, run, name, latest-artifact lookup or user-supplied download is allowed.
GitHub's immutable artifact transport and the reviewed workflow are trusted at
this handoff; candidate metadata/checksums alone are not source authentication.

The staging helper then:

1. Checks the exact workflow context, native target and new output destination.
2. Require a clean checkout at the selected commit and passing current
   [source gates](RELEASE_SOURCE_GATES.md).
3. Snapshots and checks the closed candidate manifest and all eight archive members
   with the same bounded reader used by the installer. Candidate validation is a
   separate entrypoint; the installer continues to reject unsigned candidates.
4. On Apple, signs a private copy with Developer ID, hardened runtime and secure
   timestamp, then submit a ZIP containing only that binary to Apple's notary
   service. Require `Accepted`, a valid submission identifier, and successful
   native Developer ID/team/notarization verification. No permissive entitlements
   are added. Only fixed Apple tools run, without shell interpolation or workload
   secrets in their environment. Tool output is discarded except for a bounded
   notary JSON response, which is never printed or included in the archive.
5. Rechecks the checkout and current GitHub source evidence after notarization.
6. Creates a new output directory exclusively. Replaces only the private build-info
   and install instructions, incorporate the signed Apple bytes where applicable,
   regenerate digests and validate the final archive with the actual installer
   contract before returning success.

Linux and Windows binaries receive publisher authentication through the later
Sigstore attestation step; this helper does not add Windows Authenticode signing.
On Apple, raw command-line executables cannot carry a stapled notarization ticket.
The native verifier requires Apple's notarization evidence and may need network
access; offline installation is not promised. See Apple's
[notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
and [signing requirements](https://developer.apple.com/documentation/security/resolving-common-notarization-issues).

## Failure and authority

Exit 0 returns `staged: true` and `publisher_signed: false`. The manifest uses the
installer's `signed_release` layout, but its name/kind conveys no trust: neither
it nor the archive can pass the installer without the separate publisher bundles.
Existing files/directories are never replaced. A write, validation or cleanup
failure returns no successful result and can leave new incomplete output for
inspection. Do not attest, publish or reuse such output. The helper does not
delete operator-selected directories or retry signing/notarization automatically.

The notary client has a 15-minute service wait and a 16-minute process limit.
Failure, timeout, pending/invalid status, malformed/duplicate/oversized JSON or
failed native trust verification prevents finalization. Apple may still process
a timed-out submission; that does not turn this invocation into success.

The trusted isolated runners, reviewed checkout, GitHub CLI, immutable artifact
handoff, system Apple tools and existing Keychain/ACL setup are prerequisites. No customer
configuration, Runtime credentials or telemetry are read. The public executable
is sent to Apple only when explicitly running the signing path.

## Acceptance still required

Unit tests mock the Apple and GitHub boundaries and exercise all four archive
layouts, changed sources, failed notary checks, corrupt candidates,
destination races and safe errors. They do not prove a real Developer ID signature
or a public attestation. Native candidate CI remains independent.

The direct signing workflow still needs protected-environment approval, narrowly
scoped credentials and OIDC permissions, current unresolved-failure checks,
attestation of exact final files, authenticated installation/smoke checks and
reviewed publication. A real owned Apple identity, real positive Apple/Sigstore
verification, release notes, rollback policy, supported-platform decisions and
fresh-machine acceptance remain release gates. Issues #46, #50 and #57 remain
unresolved; closing an issue or a later passing CI run does not establish a fix.
Issue #36's prior privacy-probe failure also still needs technical resolution
evidence. Nothing in this helper clears those gates or authorizes publication.

The [read-only signing prerequisite check](RELEASE_SIGNING_GATES.md) observes
source, workflow context, environment protections and the source-controlled
unresolved failure list before a future privileged job may start.
