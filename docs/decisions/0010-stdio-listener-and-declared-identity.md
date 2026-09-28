# ADR 0010 — Stdio listener with explicit declared identity

Status: accepted. Date: 2026-09-28.

## Context

MCP-007 requires a local endpoint, caller profile and protocol relay. Initial target clients already support stdio. Exposing a loopback HTTP service would introduce browser-origin, authentication and session-routing boundaries before upstream lifecycle and policy packages are implemented. MCP implementation names are self-asserted and cannot establish a principal.

## Decision

Implement a transport-neutral asynchronous byte-stream listener for inherited stdio pipes first, with no network listener. Keep the client protocol in `mitigate-gateway`, separate from the managed process transport. A narrow `ToolService` owns the authorization/execution boundary and is the protocol integration test seam. It has no permissive default. The application must provide and shut down a concrete service; MCP-008 supplies upstream integration. This slice does not add a misleading usable `serve` command before that integration exists.

Keep identity immutable for a session. Unknown remains unknown; an explicit local profile can declare bounded references with `gateway_profile` provenance and `declared` confidence. Ignore client implementation names and metadata for attribution. A profile is not a token, signature or proof of OS process identity.

Bound frames, complexity, session bytes, ID memory, lifetime and deadlines. Start with one active tool request per connection; continue servicing pings and cancellation and reject concurrent tool requests clearly. Retain all request IDs for the bounded session to reject reuse. On cancellation, terminate the session and require reconnect so dropped upstream responses cannot be correlated to new work. Service cancellation/cleanup is mandatory, not a detached task.

## Consequences

No inbound Internet rule or Platform account is required. Network authentication, richer attribution and concurrency can be added when required by actual clients, without treating raw MCP content as policy or telemetry. The documented bounded session requires client reconnect on cancellation or exhaustion. Calls remain unavailable without a concrete authorized service. Tests exercise the same parser/listener used by integration, with virtual time for deterministic deadlines. Existing dependencies suffice; Tokio's test-util feature is enabled only for tests and adds no package.
