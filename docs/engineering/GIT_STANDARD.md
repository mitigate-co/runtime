# Mitigate Git Standard

## Goal

Git history is an engineering artifact. It should make debugging, review, release and acquisition diligence easier—not merely store snapshots.

## 1. Protected branches

`main` is protected.

Require for merge:

- CI checks,
- review where the repository has multiple maintainers,
- no unresolved review threads,
- up-to-date branch or merge queue according to repo policy,
- signed commits/tags where configured.

Never force-push `main`.

## 2. Branch names

Use short, descriptive branches:

```text
feat/mcp-schema-fingerprint
fix/gateway-env-leak
security/egress-unknown-fields
refactor/policy-decision-types
docs/runtime-threat-model
chore/release-signing
```

Do not use opaque names like `changes`, `test2`, `new-version`.

## 3. Commit philosophy

A commit should be:

- one coherent concern,
- reviewable in isolation,
- buildable/testable at meaningful checkpoints,
- free of unrelated formatting churn,
- written so `git bisect` remains useful.

Do not make one commit per trivial line. Do not dump a multi-day feature into one 12,000-line commit.

## 4. Commit messages

Use Conventional Commit-style subjects:

```text
feat(mcp): fingerprint normalized tool schemas
fix(gateway): prevent secret env inheritance across servers
security(egress): reject unknown telemetry keys
test(policy): cover destructive-action offline denial
docs(runtime): document command server trust boundary
refactor(audit): separate local detail from sync events
```

Subject:

- imperative,
- specific,
- <= roughly 72 characters when practical,
- no period.

Body when needed explains **why**, tradeoffs and compatibility—not a file list Git already knows.

Example:

```text
security(egress): reject unknown telemetry keys

Unknown keys made schema evolution convenient but also created a path for
unreviewed free-form content to leave the runtime. Treat telemetry schemas as
closed contracts and require an explicit version bump for new fields.

Refs MIT-142.
```

## 5. Staging

Review every staged diff before commit:

```bash
git diff --check
git diff --staged
```

Prefer intentional staging (`git add -p`) for mixed worktrees.

Never commit:

- `.env`/credentials,
- private keys,
- customer data,
- local databases,
- build output unless intentionally versioned,
- editor state,
- temporary debug dumps,
- copied dependency source without license/provenance.

## 6. Rebasing and merging

Before opening/refreshing a PR, incorporate current `main` cleanly.

For private feature branches, interactive rebase is acceptable to make history coherent **before sharing/merge**.

Never rewrite history another person is relying on without explicit coordination.

Use repository policy consistently:

- squash merge for small/medium PRs if we want one clean logical commit, or
- merge/rebase preserving commits when individual commits are intentionally meaningful.

Do not alternate randomly.

Recommended default: **squash merge normal PRs**, preserve commit series only for deliberately structured changes where history itself adds value.

## 7. Pull request size

Prefer PRs that can be seriously reviewed in one sitting.

If a feature is large, sequence it:

1. types/contracts,
2. implementation behind no/disabled behavior,
3. integration,
4. UI/ops,
5. cleanup.

Every intermediate step should preserve production correctness.

## 8. PR template content

Every PR answers:

- What problem does this solve?
- Why this design?
- What trust boundaries change?
- What data can enter/leave?
- Failure/offline behavior?
- Tests run?
- Compatibility/migration impact?
- Docs updated?
- Preview/screenshots for UI?
- Rollback plan for risky changes?

## 9. Security-sensitive changes

Require heightened review/checklist for:

- telemetry schema,
- egress guard,
- auth/authorization,
- secret handling,
- subprocess execution,
- policy engine,
- update/signing,
- tenant isolation,
- encryption.

A "small" diff in these areas is still security-sensitive.

## 10. Tags and releases

Release tags:

```text
v0.1.0
v0.1.1
v0.2.0
```

Use SemVer once external consumers depend on CLI/protocol behavior.

Release from a clean, committed, CI-green tree.

Never build release artifacts from local uncommitted changes.

Signed release includes:

- tag,
- checksums,
- SBOM,
- provenance/attestation,
- changelog/release notes,
- binaries/packages/container references.

## 11. Reverts

Prefer `git revert` for already-shared/merged changes. Preserve history.

Hotfix branches start from the release/main point specified by release policy and merge back so the fix is not lost.

## 12. Git hygiene for agents

Before editing:

```bash
git status
git branch --show-current
git log -n 10 --oneline
```

Before committing:

```bash
git diff --check
git diff
git status
```

After committing:

```bash
git show --stat --oneline HEAD
git status
```

Never discard user changes to "clean things up." Preserve/understand pre-existing modifications.

## 13. Runtime publication vs private Platform

`mitigate-co/runtime` may be private during pre-release development and later made public because it is a dedicated open-source-target repository. Treat **every Runtime commit as if it will be public tomorrow**.

Before changing Runtime visibility:

- scan the entire Git history for secrets,
- verify dependency/source licenses and provenance,
- confirm no Platform/proprietary files ever entered history,
- review issues/PRs/actions/artifacts for unintended exposure,
- confirm contributor agreements/provenance,
- tag the reviewed release and publish signed artifacts.

Do not copy Platform history into Runtime. If proprietary material ever entered Runtime history, do not assume deleting the file is enough; rebuild/sanitize the public history deliberately before publication.

The repositories are separate products with an explicit API/protocol boundary, not a mirrored monorepo.
