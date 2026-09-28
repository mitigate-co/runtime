# Changelog

## Unreleased — explicit tool enumeration

- `mcp inspect` starts a reviewed stdio MCP server only with `--allow-exec`, negotiates a supported version and enumerates tools without calling them.
- Bound protocol messages, pagination, tool counts and deadlines; reject ambiguous responses and inventory changes.
- Isolate environment inheritance, suppress upstream error/stderr content and terminate process groups/jobs on completion, timeout and cancellation.

## Unreleased — scanner sources

- Read-only discovery of Claude Code and Cursor repository configurations with human and JSON output.
- Report configuration risks without launching servers, expanding variables, opening referenced files, or transmitting data.
- Reject ambiguous, malformed, oversized and linked configuration sources; exclude credentials, raw arguments and URL paths from reports.

## Unreleased

- Add standalone `mitigate version` and strict `mitigate config check` commands.
- Configuration validation has no account, credential, network, or subprocess dependency.
- Establish Windows/Linux/macOS checks and dependency/license/secret gates.
