# Support and recovery

Mitigate's local scanner and governance work without a Platform account. Start
with `mitigate version`, the failing command's `--help`, and its fixed error code.
Keep workload files, database copies, launch configurations and logs local.

## Collect evidence

Run `mitigate diagnostics --output support-report.json --json` with a new filename.
Add `--check-storage` for an isolated synthetic storage/privacy check; add
`--config FILE` only when checking an explicitly chosen Runtime configuration.
The [report contract](DIAGNOSTICS.md) lists exactly what can be exported.
Nothing is sent automatically. Review the file before sharing it.

For a non-sensitive bug, use the Runtime repository's
[issue form](https://github.com/mitigate-co/runtime/issues/new?template=runtime-feedback.yml).
Include the version, fixed error code, expected/observed outcome and a minimal
synthetic reproduction. Report environment categories rather than usernames or
paths. A sanitized support report is optional. Do not paste shell history, full
configuration, credentials, private endpoints or raw tool arguments/results.

For suspected disclosure, authorization bypass or another exploitable issue,
use [private vulnerability reporting](https://github.com/mitigate-co/runtime/security/advisories/new)
as described in [SECURITY.md](../SECURITY.md). Never attach sensitive data to a
public issue. The report command does not open an issue or grant support access.

## Choose the recovery action

| Symptom or code | Action |
| --- | --- |
| `config_*` | Check the selected regular JSON file against [configuration v1](CONFIGURATION.md). Use supported fields/limits; errors do not echo the source. |
| `diagnostics_output_unavailable` | Choose a new filename in a writable directory you control. Existing files are preserved; inspect a partial newly created file locally if writing failed. |
| `diagnostics_privacy_refused` | Do not bypass the export gate or substitute raw logs. Report the installed version and this fixed code. |
| Synthetic `workspace` / `cleanup` | Choose an existing writable temporary parent. Inspect only the test-owned temporary directory if cleanup failed; never recursively clear an authority/queue directory. |
| Synthetic `setup` / `storage_input` / `storage_partition` / `storage_stale_lease` | Keep the failed report, inspect the installed version, and report the synthetic failure. A fresh synthetic test does not repair real state. |
| `storage_busy` / `storage_unavailable` / `storage_path` / `storage_interrupted` | Check free disk space, directory permissions and competing processes. Preserve real stores; interruption does not prove an operation was never committed. |
| `storage_clock` / `approval_clock_invalid` / `control_clock_rejected` | Restore trustworthy system time. Preserve persisted clock guards, approvals and counters; never clamp time or reset state to force admission. |
| `storage_budget` / delivery not ready | Inspect local load, clock and queue status. A missed lease/deadline must not authorize a late send. Do not extend production deadlines to make a fixture pass. |
| `storage_integrity` / `audit_integrity_failed` | Preserve the affected store and keep the operation stopped. Do not delete or recreate it as a recovery shortcut. |
| `policy_bundle_unverified` / `policy_version_rejected` | Verify the independently pinned authority and signed version; retain the last-known-good bundle. Do not accept unsigned or rolled-back policy. |
| `mcp_launch_changed` / `gateway_review_changed` | Review executable, launch facts and current tool definitions. Create new review/authority only after the change is understood. |
| Native credential unavailable | Unlock/check the operating-system store and the exact reference. Never fall back to plaintext configuration or ambient credentials. |
| Upstream timeout or uncertain completion | Inspect local audit and the upstream outcome before deciding what to do. An uncertain destructive action must not be automatically replayed. |

The [CLI reference](CLI.md#recovery), [enrollment](ENROLLMENT_CLI.md),
[local enforcement](ENFORCEMENT.md), [outbox](OUTBOX.md) and [optional sync](SYNC_CONTROLS.md)
references define command-specific recovery. The synthetic support check never
asserts that actual authority, enrollment or queue state is healthy.

## Design-partner feedback

Support collection is explicit, local and manual. There is no background crash
uploader, free-text feedback telemetry, hidden usage tracker or automatic issue
submission. The issue form captures a component, version and reproducible result;
any human-provided text is outside the diagnostic allowlist and needs review.
GitHub account data and submitted content follow GitHub's service policy.

Maintainers should classify each submitted report by component and outcome,
reproduce using synthetic fixtures, link a regression test to the issue, and
record the fixing commit and verification result. Do not copy customer content
into tests, commit history or public discussion. Seek a safe synthetic reproduction
when the supplied report cannot be shared. Keep security reports in the private
disclosure workflow through coordinated release.

Feedback counts represent submitted reports, not users, installations, adoption
or failure rates. Don't infer a denominator from voluntary reports. Public claims
follow [research methods](RESEARCH_METHODS.md). Dedicated security contact,
supported signed releases and fresh-machine acceptance remain launch gates.
