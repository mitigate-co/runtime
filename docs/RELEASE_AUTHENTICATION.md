# Authenticate a release file

`scripts/release/authenticate.py` checks a supplied release file against a Sigstore
attestation bundle using the installed GitHub CLI. It does not extract, execute,
install, update, publish or sign anything. This is a verification primitive for
the release pipeline; there is no supported signed Runtime release yet.

From a separately trusted checkout, with Python 3.11+ and a trusted current GitHub
CLI supporting the listed identity flags:

```sh
python scripts/release/authenticate.py /path/to/release-file \
  --bundle /path/to/attestation.jsonl \
  --commit FULL_40_CHARACTER_COMMIT_SHA --tag v0.1.0
```

The paths and uppercase revision are placeholders. Obtain the intended tag and
revision through a trusted release decision, not from an unverified downloaded
manifest. Do not execute a verifier supplied inside the archive being checked.
Exit 0 reports publisher verification and the exact artifact SHA-256 and size.
Exit 2 reports a fixed failure category. Provider output, paths and local
environment values are never copied into the report.

## Fixed policy

The GitHub CLI verifies the artifact digest, signature, certificate chain and
transparency evidence. Every invocation requires:

- repository and signer repository `mitigate-co/runtime` on `github.com`;
- signer workflow `.github/workflows/release.yml`;
- source and signer commit equal to the separately selected full revision;
- source ref and exact certificate identity for the selected stable version tag;
- GitHub Actions OIDC issuer and SLSA provenance v1;
- SHA-256 and a GitHub-hosted runner.

There is no custom trusted root, alternate workflow, branch, digest, `latest`
lookup, skip-verification switch or fallback to checksums. The release workflow
identity is reserved here; its implementation and an authentic positive signed
artifact remain acceptance work. Candidate packaging has no signing authority,
and its passing checks do not create a trusted release.

GitHub CLI and its Sigstore trust material are part of the trusted verification
base. A local bundle avoids fetching the attestation itself; trusted-root refresh
can still require network access. Offline verification is not promised. Missing
tools, unsupported flags, network/trust errors and a 45-second timeout fail
closed. GitHub authentication, OS paths and proxy settings may be inherited;
unrelated workload values, debug flags and custom Sigstore-root environment are
excluded. No Runtime enrollment or customer credential is used.

## Bytes and consumption

Artifacts are limited to 128 MiB and bundles to 4 MiB. Each input must be a nonempty
regular file. Symlinks/reparse points, replacement between path inspection and
descriptor opening, growth beyond the limit and changes observed during copying
are refused. Both files are copied into a private temporary directory before the
verifier sees them. Subsequent changes to the original paths cannot replace the
verified snapshot. Unix directory/file modes are 0700/0600; Windows uses the
current user's temporary-directory ACL. A trusted local host and no malicious
same-user process remain prerequisites.

Consumers must use `authenticated_snapshot` and consume its private path
inside the context. The context removes the copy on success or failure. Reopening
the original path based on a prior JSON report would reintroduce a race and is
forbidden. Authentication alone does not authorize extracting an archive, running
a binary, changing PATH, downgrading, or replacing an existing installation.

The [verified local installer](VERIFIED_INSTALL.md) composes two authenticated
snapshots with a closed signed-release layout, file digests, native Apple checks
and exclusive new-directory creation. It does not accept unsigned candidates or
activate/run the installed binary. Authentic positive release acceptance remains
required.

## Acceptance evidence

Tests exercise fixed policy flags, closed failure reports, environment isolation,
input limits and file replacement, private snapshot consumption and cleanup,
nonzero verifier results, missing tools and timeouts. Their positive cases mock
the trusted CLI boundary; they do not establish real signature validity. The
actual installed GitHub CLI rejects a malformed synthetic bundle with the real
unsigned Linux candidate and returns only `verification_failed` through this
wrapper. A real positive signed-tag/artifact verification remains required.

The [source gate](RELEASE_SOURCE_GATES.md), Apple signing/notarization, signed
manifest and archive, current unresolved security issues, safe installation,
rollback and fresh-machine checks remain separate requirements. Do not clear the
[release standard](engineering/RELEASE_STANDARD.md) from this report alone.

[Native release staging](RELEASE_STAGING.md) prepares final native files and
implements the Apple signing/notarization tool boundary. It returns no publisher
authentication claim and cannot substitute for this verifier's real attestation.

Policy follows the official [GitHub CLI verification interface](https://cli.github.com/manual/gh_attestation_verify),
including its warning that editable provenance predicates are not certificate
identity. See [ADR 0043](decisions/0043-release-publisher-verification.md).
