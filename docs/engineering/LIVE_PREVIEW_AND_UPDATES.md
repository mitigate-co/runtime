# Agent Progress Updates and Live Preview

## Progress updates

Coding agents must keep the user oriented during long tasks.

Minimum cadence:

- initial milestone statement,
- after each meaningful implementation slice,
- after material tests/builds,
- immediately on blocker/security finding,
- final completion summary.

Good update:

> MCP schema fingerprinting is implemented and covered by normalization fixtures. I found one issue with descriptions affecting hashes; I normalized descriptions separately so cosmetic description changes do not silently reapprove an input-schema change. Next I am wiring the diff into scan output.

Bad update:

> Still working.

Do not spam individual shell commands.

## Live preview

For `mitigate-co/platform` UI work:

1. start the documented dev server,
2. keep it running in a persistent terminal/session if tooling supports it,
3. expose the local preview URL/port to the user,
4. visit/inspect the changed UI after meaningful changes,
5. preserve mock/dev data clearly separated from production data,
6. never claim a preview exists if the server is not running.

The standard development URL/port may be chosen by the repository; document it in the repo README. If port 3003 is already the current convention, preserve it unless there is a concrete reason to change it.

## Preview validation checklist

- page loads without console/runtime errors,
- loading state,
- empty state,
- realistic populated state,
- error/retry state,
- keyboard navigation,
- narrow viewport,
- desktop viewport,
- no sensitive data printed in dev console/network logs.

## Runtime live validation

For CLI/runtime work, the equivalent of live preview is a continuously runnable demonstration:

```bash
cargo run -- mcp scan
cargo run -- mcp serve ...
```

Keep representative fixture/demo servers available so the user can see working behavior, not only test output.
