# Release source checks

Before any release signing, run the read-only GitHub evidence check against an
explicit reviewed commit and stable version tag:

```sh
python scripts/release/preflight.py --commit FULL_40_CHARACTER_COMMIT_SHA --tag v0.1.0
```

Replace the uppercase placeholder with the reviewed source revision. This command
requires Python 3.11+ and an already configured GitHub CLI with repository read
access. It makes no mutation, creates no tag and acquires no signing credential.
The report contains only the fixed repository, selected source/tag and five gate
results. Provider errors, token diagnostics and action logs are not printed.

Exit 0 means these source gates are satisfied; exit 2 means at least one is
blocked or its evidence is unavailable. `source_eligible` never means production
ready. The command refuses malformed source identifiers before contacting GitHub.

## Required evidence

1. `mitigate-co/runtime` is public, unarchived and uses `main`.
2. The selected tag is annotated, verified by GitHub and points directly to the
   selected commit. Lightweight, unsigned, unverifiable, moved and nested tags
   fail. GitHub's signature verification is part of the trusted provider boundary.
3. The source commit is `main` or an ancestor, established by the comparison's
   base and merge-base. A passing feature branch is not a release source.
4. The exact commit's latest `Verify` push on `main` has every expected native,
   dependency and secret job completed successfully.
5. The same commit's `Package candidates` push on `main` has all four native
   package jobs completed successfully.

Workflow identity, repository, event, branch, commit, run ID and attempt are
checked together. Job-name sets are explicit: missing, duplicate, extra, skipped,
incomplete and wrong-attempt jobs fail. Workflow changes require a reviewed update
to this policy. Incomplete/paginated evidence fails rather than silently choosing
a convenient old run. A retry cannot erase a failed security run: only first
attempts qualify, and an earlier failed or unfinished matching main run prevents
eligibility even if a newer matching run succeeds. Investigate the failure and
make a reviewed correction; do not use empty changes to disguise it.

## Remaining release controls

This is a source gate, not a publisher or download verifier. Protected branch/tag
rules and authorized maintainers still control release intent. Its JSON is a
point-in-time observation, not a reusable credential: the future signing workflow
must run it immediately against its own pinned source. Never substitute cached
output or a feature-branch run. The verifier is trusted build tooling and must be
invoked from reviewed source on a trusted runner.

It does not prove macOS signing/notarization, artifact signatures/provenance,
installer verification, backup/rollback safety, absence of known security bugs or
fresh-machine acceptance. Those remain separate required gates in the
[release standard](engineering/RELEASE_STANDARD.md). In particular, successful CI
does not resolve Runtime issue #46's still-unexplained Windows governance fault.
Runtime issue #50 also retains an unexplained pre-transport readiness failure.
Neither is cleared by a later successful run. There is no release publication or
production deployment in this change.

The [release-file authenticator](RELEASE_AUTHENTICATION.md) applies the fixed
publisher policy to a bounded local file and attestation bundle. It is independent
of these source checks; both are required, and neither is a production-ready flag.

The provider interfaces are GitHub's REST
[workflow runs](https://docs.github.com/en/rest/actions/workflow-runs),
[workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs),
[Git tags](https://docs.github.com/en/rest/git/tags) and
[commit comparison](https://docs.github.com/en/rest/commits/commits#compare-two-commits).
