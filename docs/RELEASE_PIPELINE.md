# Isolated release preparation

`.github/workflows/release.yml` prepares signed artifacts and tests installation.
It has **no publication step** and no `contents: write` permission. The workflow
is implemented but has not been dispatched with real signing credentials. No
signed release, native notarization success or production readiness is claimed.

## Jobs and authority

| Job | Runs | Authority and boundary |
| --- | --- | --- |
| `preflight` | Exact signed tag, clean source, first-attempt main CI, current blocker policies and existing environment protections | Repository/actions/deployment reads only. No environment binding, keys or OIDC. |
| `build` | Four native locked builds and actual candidate smoke tests | Repository read only. No signing environment, OIDC or attestation writes. |
| `sign` | Candidate verification, Apple signing/notarization where applicable, final assembly, publisher attestation, signature verification | A fresh hosted runner after **all** builds succeed and `release-signing` approval. Only this job has OIDC and attestation writes. No compilation or candidate execution. |
| `accept` | Publisher/sidecar verification, actual installer, Apple verification, installed-binary smoke tests | Another fresh hosted runner after **all** sign jobs succeed. Read-only token, no signing environment or OIDC. |
| `complete` | Reports that all four native acceptance jobs succeeded | No repository permissions or publishing commands. |

Targets match candidate CI: Ubuntu 22.04 x86-64, Windows 2022 x86-64, macOS 14
arm64 and macOS 15 Intel. These are runner coverage, not a claim of support for
every customer OS version or a substitute for ordinary-user installation tests.

Artifact downloads select one exact name from the **same workflow run**. They
never select latest, an arbitrary run/repository, a pattern or a caller-supplied
artifact. The immutable artifact handoff rejects digest mismatches. A failed
build cannot be replaced with an artifact from an earlier run. Shared caches
and persistent runners are not used for the release pipeline.

## Owner setup before any dispatch

1. Resolve each source-controlled [release blocker](RELEASE_BLOCKERS.json) with
   technical evidence through review. Both the tag's policy and current `main`
   policy must be clear. Passing a later test does not clear a prior failure.
2. Configure the existing `release-signing` environment as required by
   [signing prerequisites](RELEASE_SIGNING_GATES.md). Disable administrator bypass
   through GitHub settings; the public API checker cannot prove that setting.
3. Configure the five Apple credential inputs as environment secrets and
   `APPLE_SIGNING_IDENTITY`/`APPLE_TEAM_ID` as reviewed environment variables, as
   described in [Apple signing setup](APPLE_SIGNING_RUNNER.md).
4. Independently configure the same public `APPLE_TEAM_ID` as a repository
   variable. The acceptance jobs have no signing-environment access. A mismatch
   fails native identity verification; do not derive this trust value from a
   downloaded archive or attestation payload.
5. Review the clean protected source, required checks, stable version, signed
   annotated tag, release notes and rollback decision. Select that **tag as the
   workflow ref**, and pass the matching `tag` and full `source_commit` inputs.

No tag, environment, credentials or dispatch is created by this implementation.
Merging the workflow does not run it. It accepts only manual dispatch; normal
push/PR checks validate syntax and exercise helpers with synthetic tests.
Actual dispatch and protected environment approval remain owner operations.
Do not dispatch this workflow as a workaround for unresolved gates.

## Final bytes and acceptance

Apple private inputs are supplied only to the macOS staging step. It removes them
from subprocess environments and destroys its temporary Keychain before the
attestation step. Attestations cover four final files per target: archive,
manifest, external SPDX SBOM and `SHA256SUMS`. The fixed publisher identity binds
the direct `release.yml`, selected tag and source/workflow commit. It does not
accept signatures from a build, PR, fork, different workflow or self-hosted run.

`release_bundle.py` checks all four signatures, uses the installer's closed
archive contract, requires the external SBOM to equal the embedded bytes and
requires all three checksum entries to match. It rechecks current source,
environment and blocker policy before retaining the bounded bundle. Existing
bundle output is never overwritten. Neither this step nor signing runs the binary.

`accept_release.py` repeats verification on a separate runner, installs through
the real installer into a new temporary directory, then executes version, valid
and invalid config checks, empty project scan, privacy self-test and empty egress
inspection. Its subprocess environment excludes provider tokens and signing
inputs and uses fresh synthetic user state. Missing signatures, sidecar drift,
native Apple rejection, failed installation, smoke failure or cleanup failure
prevent success. No customer config, credentials or local state is read.

The five-file signed artifact is retained in Actions for seven days. On a public
repository, authorized GitHub users may download Actions artifacts; they are test
outputs and are not an approved GitHub Release. Do not advertise, copy to a package
channel or install them for customers before all release acceptance gates pass.
Attestation generation uses GitHub's public-repository Sigstore infrastructure;
source identity and artifact digests are public signing metadata, not customer data.

## Tools and verification limits

New build-only tools are MIT-licensed and pinned: `actions/download-artifact` v8,
`actions/attest-build-provenance` v4.2.2 and actionlint v1.7.12. The actions are
commit-pinned; the linter download is checksum-pinned and runs in the existing
required `secrets` job. Existing checkout, Python setup and upload actions retain
their reviewed pins. Native platform tools and the installed GitHub CLI are part
of the hosted-runner trust boundary. Unsupported verifier flags fail closed.

Synthetic tests prove ordering, rejection paths, byte consistency and fresh
installation composition; they mock publisher/native signatures and never run
fixture bytes. Actual signed/notarized artifacts, clean-user acceptance,
Homebrew/install ergonomics, support/rollback decisions and protected publication
remain release work. This workflow introduces no Runtime data-path migration.
Rollback is to leave manual dispatch disabled; do not re-use artifacts from a
failed run or rerun failed security checks until green.
