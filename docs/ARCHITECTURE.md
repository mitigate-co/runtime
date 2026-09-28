# Mitigate Architecture

## Repository boundary

```text
PUBLIC
https://github.com/mitigate-co/runtime

        customer environment
              │
              ▼
       mitigate runtime
       ├─ MCP scanner
       ├─ MCP gateway
       ├─ policy
       ├─ secret broker
       ├─ local audit
       ├─ privacy self-test
       └─ egress firewall
              │
              │ optional Zero-Content sync
              ▼

PRIVATE
https://github.com/mitigate-co/platform

       Mitigate Platform
       ├─ account/org
       ├─ enrollment/fleet
       ├─ inventory/audit metadata
       ├─ registry
       ├─ reputation/index
       └─ hosted UI
```

The Runtime is the trust boundary. Platform is optional for the MCP wedge.

## Design principles

### Local-first

`mitigate mcp scan` and `mitigate mcp serve` must provide useful local operation with no Platform account.

### Outbound only

Platform enrollment/sync uses outbound HTTPS. Runtime does not require an inbound Internet firewall rule.

### Capability-oriented internal APIs

Subsystems depend on narrow traits/interfaces:

- `DiscoverySource`
- `McpTransport`
- `SecretProvider`
- `PolicyEvaluator`
- `AuditSink`
- `EgressSink`

Do not add an interface merely because it is fashionable. Add one when it owns a boundary, test seam or second implementation.

### Stable normalized MCP model

Upstream client/server details normalize into stable Mitigate types. Avoid leaking a specific client config format through the rest of the codebase.

### Content plane vs control facts

Raw arguments/results remain in the local content plane. Platform receives control facts only.

### Last-known-good policy

If Platform or policy refresh fails, Runtime continues using the last verified policy bundle. Corrupt/unverified replacement bundles are never activated.

## Runtime process layout

Prefer one main Rust process for the wedge unless isolation evidence justifies multiple processes.

```text
mitigate
├─ CLI command dispatch
├─ discovery
├─ gateway listener
├─ upstream process/network transports
├─ policy engine (Regorus)
├─ secret broker
├─ SQLite/local audit
├─ egress guard
└─ update/registry clients
```

Do not create sidecars for convenience.

## Implemented local control store

MCP-014 adds a customer-side SQLite control store in `mitigate-policy`: emergency
stop, exact target disables, persistent deterministic quotas and bounded local
administrator history. A transaction commits all matched quota deductions before
returning admission. The operator CLI and gateways can share that store without
process-local quota resets. Passing controls does not satisfy grants, policy,
approval or audit; the executable remains inventory-only until that composition
passes its gates. See [control boundaries](CONTROLS.md) and ADR 0017.

## Platform architecture

Keep the first Platform implementation simple:

- Cloudflare for edge/API/queue where useful,
- Neon PostgreSQL,
- React/Vite web,
- TypeScript/Hono APIs,
- Drizzle migrations,
- Better Auth,
- R2 for public/static artifacts if needed.

Avoid microservice decomposition. One monorepo may deploy multiple workers/processes but shares contracts and one domain model.

## API/protocol rules

- version all external APIs,
- exact JSON schemas,
- no arbitrary metadata maps in telemetry,
- cursor pagination,
- RFC 7807-style errors or equivalent structured errors,
- request IDs,
- idempotency for state-changing ingest/control operations,
- UTC timestamps,
- opaque externally visible IDs.

## Future modules

Future modules plug into the Runtime/Platform boundaries; they do not redefine them. See parked module docs.
