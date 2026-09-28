# ADR 0009: Confirm all Windows job members have exited

Status: accepted. Corrective follow-up to MCP-003 during MCP-005 CI.

## Evidence and decision

One Windows CI run returned from enumeration cleanup while a descendant's listener was still reachable. Inspection found that process-wrap 10.0.1 treated any completion-port packet as job completion and cached parent exit before checking descendants. This is a concrete lifecycle defect, not permission to weaken the cleanup guarantee or retry a flaky gate until it passes.

Keep the existing command/job architecture and pin a reviewed local source patch. Read the OS job's active-process count; return completion only at zero. Query errors and the existing two-second deadline fail cleanup. Tokio waiting remains asynchronous and cancellation-safe without detached background waits. Preserve upstream license/provenance and record the diff in `vendor/process-wrap/MITIGATE_PATCH.md`. This adds no external packages or privilege and retains Runtime's unsafe-code prohibition; required Windows FFI stays inside the existing dependency boundary.

Microsoft documents [job basic accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information) and [job queries](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject). A [job completion notification](https://devblogs.microsoft.com/oldnewthing/20130405-00/?p=4743) must distinguish the whole job becoming empty from other events. We use the count directly so missed/consumed notifications and wait cancellation cannot become false success.

Tests check an application-level response from the descendant immediately after cleanup and add a live-descendant test after parent exit, including try_wait and cancelled/retried wait. A TCP handshake can temporarily succeed during kernel socket teardown after process exit, so connection establishment alone was an imprecise liveness assertion. Removing the active-process guard makes the new regression fail; restoring it passes. The patch is removed only after an upstream correction passes these tests. This fixes lifecycle confirmation; it does not add sandboxing, handle malicious process-group escape on Unix, or make forced termination of Runtime graceful.
