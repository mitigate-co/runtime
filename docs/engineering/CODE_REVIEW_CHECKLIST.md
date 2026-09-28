# Code Review Checklist

Use judgment; this is not a checkbox substitute for understanding the change.

## Correctness

- Does the implementation match the stated behavior/acceptance criteria?
- Are edge/error/offline paths explicit?
- Are state transitions valid and testable?
- Is concurrency/cancellation behavior safe?

## Security/privacy

- Does untrusted input cross a new boundary?
- Can raw content/secrets enter logs, Platform telemetry or errors?
- Are sizes/timeouts/rates bounded?
- Can config/arguments reach a shell?
- Does authz happen before sensitive action?
- What happens if identity is unknown?
- What happens if Platform/policy/approval is unavailable?
- Did telemetry schema change? If yes, is egress validation/test coverage updated?

## Architecture

- Is this code in the correct repo/module?
- Does it introduce a duplicate concept/type?
- Is the abstraction justified by a real boundary?
- Did a parked roadmap module leak into current scope?

## Readability

- Can a reader infer intent from names and types?
- Are security invariants documented where they matter?
- Is there repetitive/generated-looking boilerplate that should be factored or deleted?
- Are comments explaining why rather than narrating syntax?

## Tests

- Is the happy path covered?
- Failure/offline path?
- Security/adversarial path where relevant?
- Regression test for a bug fix?
- Tests deterministic and meaningful?

## Operations

- Useful errors/metrics without secrets?
- Migration/compatibility implications?
- Rollback path?
- Docs/release notes updated?

## Git

- Diff focused?
- No unrelated formatting churn?
- Commit/PR explains why?
- No secrets/generated junk/customer data?
