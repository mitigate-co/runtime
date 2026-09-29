# Local support report

Run `mitigate diagnostics` to inspect the installed version and supported schema.
No account, network connection, enrollment or native credential access is needed.
Nothing is uploaded. Choose a new filename to save the same checked JSON returned
by `--json`:

```sh
mitigate diagnostics --json
mitigate diagnostics --output support-report.json --json
mitigate diagnostics --config examples/runtime.json --check-storage --json
```

The last example runs from the repository root. The configuration path is explicit;
there is no home-directory discovery or environment-variable fallback. Omit it
to leave configuration unread. `--check-storage` creates and removes an isolated
synthetic queue in the OS temporary directory. `--work-dir EXISTING_DIRECTORY`
selects a different parent and requires `--check-storage`. It does not open a real
outbox or test a selected customer's database. See [privacy probe](PRIVACY_COMMANDS.md).

## Export contract

Schema 1 contains exactly these root fields:

| Field | Allowed values |
| --- | --- |
| `schema_version` | Integer `1` |
| `kind` | `mitigate_diagnostics` |
| `runtime_version` | Version compiled into this binary |
| `operating_system` | `windows`, `macos`, `linux`, `other` |
| `architecture` | `x86_64`, `aarch64`, `other` |
| `configuration_schema` | Integer `1` |
| `configuration` | Closed object below |
| `storage_check` | Closed object below |

`configuration.status` is `not_read`, `valid` or `unavailable`. `not_read` has
no additional fields. `valid` adds integer `max_file_bytes` (1,024–1,048,576) and
`max_servers` (1–256). `unavailable` adds only `error`, one of the documented
`config_*` codes in the [configuration reference](CONFIGURATION.md).

`storage_check.status` is `not_run`, `complete` or `unavailable`. `not_run` has
no additional fields. `complete` adds boolean `passed`, `positive_control`,
`queue_isolation`, `persisted_canaries_absent`; integers `attempted` (1–4,096),
`rejected` (0–attempted), and `network_requests` (always zero). `passed` must
agree with the control results and rejection counts. `unavailable` adds only
`error`: `workspace`, `setup`, `cleanup`, `storage_input`, `storage_path`,
`storage_busy`, `storage_unavailable`, `storage_interrupted`, `storage_integrity`,
`storage_partition`, `storage_clock`, `storage_stale_lease` or `storage_budget`.

The independent export gate checks every key, type, enum, bound and consistency
rule before serializing at most 4 KiB including the final newline. Unknown fields
or arbitrary text fail the entire report; they are never best-effort redacted.
Collector changes must pass this separate gate. Both stdout JSON and saved files
use the same checked bytes. The human summary contains only fixed labels and
checked version/platform/error values.

Schema 1 excludes logs, policy contents/identifiers, audit records, enrollment
state, actual queue records, paths, hostnames, timestamps, user/org identities,
environment values, payloads, credentials and backend exception text. It does
not automatically read those sources to redact them. This deliberately narrower
support scope needs a reviewed schema change before any additional collection.
Diagnostic metadata still reveals the installed version and coarse platform;
review the report before choosing to share it.

## Files and exit codes

`--output` creates a new file and refuses existing files, final-component links,
portable device filenames and alternate streams. Unix permissions are `0600`;
Windows uses the chosen parent's inherited ACL. Use a directory you control.
The parent is trusted: this is not defense against a privileged same-user process
replacing directories concurrently. A failed write/sync may leave a partial new
file; existing files are never overwritten. Inspect that new file locally and
choose a different filename on the next attempt.

Exit `0` means the report was collected. A requested check may still be
`unavailable` or `complete` with `passed: false`; inspect its status. This makes
failure evidence available for support and does not certify overall health.
Exit `2` means invalid CLI arguments, `diagnostics_privacy_refused`, or
`diagnostics_output_unavailable`; no JSON report is printed. Failure errors use
the standard fixed stderr contract. Other output I/O failures follow the
[CLI exit contract](CLI.md). No telemetry setting or authority changes.

## Verification

Actual-binary tests cover explicit/ambient configuration, hostile values,
synthetic storage isolation, missing parents, permissions, symlink/overwrite
refusal and equality of exported/stdout bytes. Separate gate tests inject
unknown nested fields, secrets, paths, oversized strings, wrong types,
out-of-range numbers and inconsistent outcomes. They require total refusal.
These checks do not prove the machine, every filesystem or every MCP server safe.

See the [support runbook](SUPPORT.md) for recovery and reporting.
