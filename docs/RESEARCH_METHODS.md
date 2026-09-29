# MCP research methodology

Status: publication protocol. No population study or adoption dataset is claimed
by the Runtime fixture suite. Each future report needs its own reviewed evidence,
sampling description, privacy assessment and limitations.

## Define the question before collecting observations

State the exact outcome being measured: configuration discovery, declared tool
capabilities, definition changes, a reproduced authorization failure, or a local
performance measurement. Keep these outcomes distinct. A declared write capability
is not evidence of exploitation; a description is an untrusted claim; a successful
scan does not establish that every client or server was discovered.

Record the tested Runtime revision, protocol/schema versions, platform/build
inputs, test configuration and observation window. Publish executable synthetic
fixtures and commands where possible. Do not publish customer configurations,
prompts, tool arguments/results, credentials, local identity mappings or raw audit
stores as a reproducibility shortcut.

## Separate evidence sources

| Source | What it can establish | Limits |
| --- | --- | --- |
| Deterministic synthetic corpus | Behavior of the selected implementation on the disclosed cases | No prevalence, adoption, exploit-frequency or completeness claim |
| Reviewed public server/configuration material | Attributed statements and reproducible observations about those exact versions | Source freshness, licensing and selection bias must be recorded; package declarations do not authenticate code |
| Explicit local reproduction | Observed behavior under a stated authorized setup | No inference about other installations or workloads |
| Optional closed organization telemetry | Only the reviewed aggregate questions supported by admitted fields and consent | No raw payload analysis, global adoption estimate, causal inference or arbitrary dimensions |

Hosted curation, cohort construction and publication controls belong to the
private Platform. This Runtime protocol neither defines their implementation nor
authorizes a dataset export. Each aggregate publication requires its separate
reviewed privacy policy and eligibility checks. Missing, withheld and stale
results must remain distinguishable from zero.

## Reproduce and classify

For a suspected problem, construct the smallest synthetic example on a clean
local setup. Record the expected and observed behavior, exact affected version,
prerequisites and whether a tool invocation occurred. After possible dispatch,
an error or missing response must remain uncertain; do not describe it as a rolled
back action. Confirm privacy failures with controlled canaries rather than live
secrets or customer documents.

Classify an observation as one of: source claim, static declaration, controlled
reproduction, or aggregated observation. Record disagreements and unsupported
features. Preserve original failures, including intermittent ones. A later pass
does not explain or erase a failure; record its resolution and regression test
when the cause is established.

## Report measurements honestly

Specify the eligible population, selection/exclusion rules, denominator, unit of
analysis and collection window. Distinguish installations, machines, runtimes and
organizations. Do not sum non-independent observations or describe a convenience
sample as the broader market. If the collection design cannot support an estimate,
report the observed sample only.

For timing, separate parsing/classification/policy/gateway overhead from upstream
server latency and build/setup time. Describe warm-up, sample count, hardware,
OS, load, summary statistics and uncertainty. Preserve failed/timeout cases and
explain exclusions. Do not present noisy CI durations as product latency promises.
The [local harness](PERFORMANCE.md) supplies reproducible synthetic component
measurements with raw ordered samples and explicit failures. Its scope excludes
the full governed CLI path and must remain visible in any comparison.

For longitudinal comparisons, keep definitions and cohort rules consistent and
disclose changes. For capability classification, provide the taxonomy version and
the evidence/confidence source; a flag is a review signal, not a safety verdict.

## Coordinate disclosure and publication

Privately report exploitable findings through the [security process](../SECURITY.md)
before public discussion. Use an authorized local reproduction; this methodology
does not grant permission to test somebody else's deployment. Share only the
minimum synthetic evidence needed to reproduce the issue. Track affected versions,
mitigation, a regression, signed patch availability and coordinated disclosure.

Before publishing a report, a reviewer must confirm that its claims follow the
evidence, denominators and limitations; its source licensing/attribution is clear;
and its examples, screenshots, logs and downloadable artifacts contain no customer
content, secrets, identifying configuration or unreviewed telemetry. Report
corrections with a dated change record rather than silently replacing conclusions.
Release-readiness claims additionally require the [production gates](MASTER_SPEC.md#16-launch-gates).
