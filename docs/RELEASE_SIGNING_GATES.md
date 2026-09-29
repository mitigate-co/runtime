# Signing prerequisites

`scripts/release/signing_gate.py` is a read-only check for the direct
release workflow's unprivileged `preflight` job. It does not sign, approve,
publish, create an environment or change repository settings.

```sh
python scripts/release/signing_gate.py --commit FULL_40_CHARACTER_COMMIT_SHA --tag v0.1.0
```

Replace the revision with the separately reviewed source. Outside the exact
manual tag workflow, the context gate fails; this command can still show the
other missing prerequisites using repository-read access. Its JSON contains only
fixed gate names, booleans, public issue numbers and the selected repository/tag/
commit. Provider errors, logs, reviewer identities and extra provider fields are
not copied into the report. Exit 0 means all observed prerequisites passed;
exit 2 means blocked or unavailable. A saved report is never signing authority.

## Required evidence

- The caller is the `preflight` job of the direct reviewed
  `.github/workflows/release.yml`, manually dispatched at the exact stable tag
  on a GitHub-hosted runner, with matching source/workflow commit and attempt 1.
- The local checkout is clean and matches the selected commit.
- All current [source/tag/first-attempt CI checks](RELEASE_SOURCE_GATES.md) pass.
- Both the selected checkout's [release blocker policy](RELEASE_BLOCKERS.json)
  and the current protected `main` policy are valid and contain no unresolved
  failures. An older tag cannot hide a failure recorded after its source commit.
- GitHub reports an existing `release-signing` environment with one required
  reviewer rule, one to six distinct user/team reviewers, custom deployment
  policies and exactly one allowed **tag** pattern: `v*`. No branch patterns or
  additional patterns are accepted. The workflow context separately restricts
  tags to stable semantic versions. Missing/malformed/paginated evidence fails.

The environment must exist before a signing job references it. Otherwise GitHub
can implicitly create a new environment without the intended protections. The
preflight job must not reference that environment itself; only downstream signing
jobs do. The actual approval is enforced by GitHub before those jobs receive
secrets. This helper observes configuration, not an approval decision.

The maintainer configures allowed reviewers and should disable administrator
bypass in the environment settings. The documented public environment API used
here does not expose that bypass setting, so this checker does not claim to
verify it. `prevent_self_review` is accepted in either documented boolean state
to support a single-maintainer project; require independent approval when the
project has multiple maintainers. No reviewer identity is invented or installed
by this change. Repository administrators and GitHub remain trusted authorities.

## Unresolved failure policy

The source-controlled JSON has exactly `schema_version: 1` and an ascending unique
`unresolved_issues` array of bounded positive integers. Unknown fields, duplicate
keys, wrong types, missing files, links or more than 4 KiB are refused.
The current-main copy is read from the fixed repository contents endpoint with
`ref=main`; wrong type/path/encoding, malformed Base64 or conflicting size fails.
Missing remote policy is not treated as an empty failure list. No policy file or
repository override is accepted from command arguments.

It currently retains:

- [#36](https://github.com/mitigate-co/runtime/issues/36): prior privacy-probe
  failure lacks technical resolution evidence even though the issue was closed.
- [#46](https://github.com/mitigate-co/runtime/issues/46): unexplained Windows
  governance result.
- [#50](https://github.com/mitigate-co/runtime/issues/50): unexplained Windows
  pre-transport readiness failure.
- [#57](https://github.com/mitigate-co/runtime/issues/57): unexplained Windows
  gateway-capture failure; retained diagnostics do not establish its cause.

Remove a number only in a reviewed corrective PR that links the demonstrated
cause, fix or justified fixture correction, regression coverage and required CI
evidence. Later successful runs, issue closure, retries and empty changes do not
resolve a security failure. New launch-blocking failures belong in this list in
the corresponding implementation/diagnostic change. It is not a vulnerability
database and must never contain private reports or customer data.

## Workflow boundary and remaining acceptance

The [release pipeline](RELEASE_PIPELINE.md) composes the staging helper and keeps
compilation and candidate execution on separate unprivileged runners, uses exact
same-run immutable artifact handoffs, isolates Apple credentials, attests final
bytes and verifies/executes installed releases on fresh acceptance runners.
Do not grant OIDC, signing or publication permissions to build/test jobs.

Current-source checks must run again before signing/publishing because policy,
tag state, CI evidence and environment configuration can change. This preflight
does not prove an authentic signature, credential availability, approval,
notarization, a safe rollback, fresh-machine acceptance or production readiness.
The workflow is defined but has not been dispatched. No signing environment,
tag, public release or deployment has been created by this change.

Provider contracts: GitHub's [environment API](https://docs.github.com/en/rest/deployments/environments),
[deployment branch/tag policies](https://docs.github.com/en/rest/deployments/branch-policies)
and [deployment review](https://docs.github.com/en/actions/how-tos/managing-workflow-runs-and-deployments/managing-deployments/reviewing-deployments).
