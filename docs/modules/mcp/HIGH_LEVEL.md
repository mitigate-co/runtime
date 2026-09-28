# Mitigate MCP — High-Level Product Specification

**Status:** ACTIVE WEDGE — BUILD NOW  
**Repository:** customer-side implementation in `mitigate-co/runtime`; hosted/fleet pieces in `mitigate-co/platform`.

## Product statement

Mitigate MCP is the local-first security and governance layer for Model Context Protocol servers and tools.

It has three pieces:

1. **Scanner** — discovers MCP servers/tools on machines and in repositories and produces a useful security inventory without requiring an account.
2. **Gateway** — gives agents one governed MCP endpoint with per-principal/agent grants, local credential injection, approvals, rate limits, change detection, kill switches and local audit.
3. **Registry / fleet view** — optionally syncs Zero-Content metadata to Mitigate Platform and enriches it with a source-attributed public registry and aggregate reputation signals.

## Why this wedge

MCP adoption is moving faster than traditional corporate inventory and permission models. Organizations need to answer:

- Which MCP servers are installed?
- Which tools do they expose?
- Which can read, write, delete, execute, access credentials or communicate externally?
- Which agents/users are permitted to invoke them?
- Did a tool definition change after approval?
- Where are credentials stored?
- What happened without centralizing the tool payload itself?

## Public promise

> Discover and govern MCP locally. Your credentials and tool payloads stay with you.

Avoid absolute claims such as "Mitigate never touches sensitive data." Runtime may inspect/process data locally. The precise claim is that Mitigate Platform does not need raw tool content for normal inventory/governance/audit operation.

## P0 capabilities

### Scanner

- common MCP config discovery,
- repository config scanning,
- server/package/version identification where available,
- reachable server tool enumeration,
- normalized schema fingerprinting,
- read/write/delete/exec/credential/etc. capability classification,
- dangerous config checks,
- human and JSON output,
- registry lookup/enrichment.

### Gateway

- local MCP endpoint,
- upstream stdio/network server adapters required by target clients,
- explicit client/agent/principal identity,
- per-server/tool/capability grants,
- embedded Regorus policy evaluation,
- approval for risky/destructive calls,
- local secret injection,
- rate limits,
- server/tool kill switches,
- schema change detection/review,
- local audit,
- fail-local behavior when Platform is offline.

### Platform/fleet

- optional account/org,
- runtime enrollment,
- fleet health/version,
- server/tool inventory,
- schema-change view,
- safe policy/audit facts,
- public registry,
- aggregate index/reputation with disclosure and opt-out.

## Privacy

Cloud may receive:

- opaque/pseudonymous principal/agent refs,
- server/tool identifiers,
- version/schema fingerprint,
- capability category,
- decision/result,
- policy/version,
- bounded timestamps/counters.

Cloud does not need:

- raw arguments,
- raw tool results,
- credentials,
- file contents,
- database rows,
- arbitrary command/output bodies.

## Adoption

### Individual

```bash
brew install mitigate-co/tap/mitigate
mitigate mcp scan
```

No account required.

### Team/company

1. install Runtime on relevant endpoints/hosts,
2. scan and/or route MCP through the gateway,
3. optionally enroll Runtime with Platform,
4. see organization inventory and changes,
5. enable grants/approvals/enforcement deliberately.

Fleet packaging expands when real organization deployment requires it; do not delay the wedge for a full MDM matrix.

## Success metrics

- active organizations,
- 30/90-day organization retention,
- MCP calls governed/month,
- servers/tools discovered,
- schema changes detected,
- risky/destructive calls requiring approval/denial,
- organization deployment ratio,
- registry coverage and observed deployment breadth,
- design-partner logos.

## Production definition

Production-quality means a fresh user can install Mitigate, discover MCP, govern representative servers through the gateway, keep credentials local, approve/deny destructive actions, detect schema changes, run the privacy self-test and—if enrolled—see useful fleet metadata in Platform without uploading raw tool payloads.
