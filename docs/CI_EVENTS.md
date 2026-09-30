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

## Windows failure reproduction

The Windows verification job retains exactly three compiled debug executables
for two days: `mitigate.exe`, `mitigate-test-mcp.exe` and
`examples/native_lifecycle.exe`. This also runs after a test failure if all three
files were built, so a failed job can be investigated without rebuilding it on
another machine. A cancelled run or incomplete build does not produce this bundle.
The artifact name includes the run ID and attempt; no database, credential,
temporary workspace, process log or other build output is included.

These are unsigned developer test inputs, not a release or customer installer.
Before local execution, verify the trusted Runtime repository, reviewed source,
workflow identity, selected run/attempt and immutable artifact ID using GitHub.
Retain the original failure log separately. Download that exact archive, compare
its SHA-256 with GitHub's artifact digest, and inspect its members before extracting
into a new owned directory. Do not execute a binary from an unreviewed pull request
or substitute the newest artifact for the failing source. GitHub and the reviewed
CI toolchain are trusted for this diagnostic path; the digest is not a publisher
signature. Released installations still require the separate authentication gates.

Use isolated synthetic state and bounded process cleanup. The fixture CLI requires
the explicit executable path, for example `mitigate-test-mcp.exe governance-contract
PATH_TO_MITIGATE_EXE`; invoke that executable through its full owned path. The
native lifecycle fixture additionally requires its explicit native-store opt-in
and owns only its synthetic entries. Do not point tests at customer state, change
the system clock, retry until green, or treat a successful reproduction attempt
as proof that the original failure is resolved.
