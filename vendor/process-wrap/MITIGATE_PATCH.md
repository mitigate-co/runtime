# Mitigate process-wrap patch

Source: process-wrap 10.0.1 from crates.io, Apache-2.0 OR MIT. Original archive checksum: `1f21b97672d2dc848e7b25701ab4535618b92f4861c13cc3f7f7bed52ad3c8da`. Upstream repository: https://github.com/watchexec/process-wrap. Upstream source and license notices are retained; the manifest starts from Cargo.toml.orig. This is a source dependency, not generated build output. Runtime's own unsafe-code prohibition remains unchanged.

The Windows job wait in 10.0.1 considers any successful completion-port packet sufficient, including process creation. Tokio also caches the leader's exit before job completion. A Windows CI failure demonstrated a descendant still reachable after explicit shutdown returned. Re-running that test is not a fix.

Local changes:

- `src/windows.rs`: replace completion-packet waiting with `QueryInformationJobObject(JobObjectBasicAccountingInformation)` and check `ActiveProcesses == 0`; propagate query failure.
- `src/tokio/job_object.rs`: poll that query at 5 ms intervals, cache completion only after zero members, keep wait cancellation safe, and do not spawn detached blocking waits.
- `src/std/job_object.rs`: apply equivalent membership confirmation to wait/try_wait.
- `Cargo.toml`: enable Tokio's existing time feature. No new package/version or license added.

The additional completion port remains owned and closed using upstream RAII; it is not used as completion evidence. Job creation, suspended assignment, kill-on-close, termination and Unix behavior are unchanged. Runtime bounds awaited cleanup at two seconds; query/timeout failures remain cleanup errors. Future cancellation still requests termination but cannot synchronously await it.

Regression: `job_wait_tracks_descendants_after_parent_exit_and_wait_cancellation` uses a live synthetic descendant after its parent exits. Both try_wait and a cancelled/retried wait must remain incomplete until the job is terminated. Shutdown/timeout probes now require a response written by the descendant; a TCP handshake alone can briefly succeed while Windows tears down an already exited process's socket. Tests assert no application response immediately after cleanup, without retrying until green. The source patch is applied by the workspace `[patch.crates-io]`; standalone crates.io publishing needs explicit packaging review before release. No source package release is claimed.

Remove this patch when a reviewed upstream release provides equivalent confirmed, cancellation-safe completion behavior and the same regression suite passes. See ADR 0009 for the production boundary and Microsoft references.
