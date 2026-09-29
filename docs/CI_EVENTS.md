# CI event coverage

`Verify` and `Package candidates` run for every pull request, every push to
protected `main`, and explicit manual dispatch. A feature-branch push without
a pull request does not start these workflows. Open a PR to request validation.

This avoids two identical native matrices for every feature update. It changes
when validation is requested, not the tests, targets, job permissions, timeouts,
assertions, dependency/license checks or secret scans. All required checks must
still pass before protected merge. No existing run is canceled or retried by
this change, and no prior failure is cleared.

PR jobs validate the proposed merge with their selected base. A protected-main
push validates the actual merged source revision. Release eligibility requires
that exact revision's successful first-attempt **push/main** workflows; a passing
PR or manual run cannot substitute for release source evidence. Source/tag,
unresolved-failure, signing and native acceptance gates remain separate.

Manual dispatch is available for explicit diagnostic work. It is not a way to
replace failed security evidence with a more convenient success. Record and
resolve the original failure before declaring the affected release accepted.
