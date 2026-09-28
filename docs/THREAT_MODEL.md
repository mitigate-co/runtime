# Mitigate Threat Model — MCP Wedge

## Assets to protect

- MCP credentials and OAuth material,
- local tool arguments/results,
- customer files/data reachable by MCP,
- policy/grant integrity,
- update/signing chain,
- organization/fleet metadata in Platform,
- registry/reputation integrity.

## Adversaries

- malicious or compromised MCP server,
- tool-description/schema poisoning,
- compromised local user process,
- malicious config/repository content,
- compromised dependency/update path,
- unauthorized employee/agent,
- attacker with stolen Platform session,
- cross-tenant attacker,
- malicious public registry submission/source.

## Trust boundaries

1. client/agent → Mitigate Gateway
2. Gateway → policy engine
3. Gateway → secret broker
4. Gateway → upstream MCP server/process
5. Runtime → optional Platform egress
6. Platform user → organization data
7. registry collectors → curated public facts
8. release system → customer updates

## Priority threats

### Command injection

Mitigation: executable + argv arrays, no shell interpolation, path checks, tests with hostile config values.

### Credential leakage

Mitigation: OS secret store, narrow child env, no secret logs/sync, redaction/egress guards.

### Tool poisoning/schema drift

Mitigation: normalized fingerprints, change alerts, reclassification, configurable reapproval.

### Permission confusion

Mitigation: explicit principal/agent/tool grants, unknown identity state, deny/approval for risky actions where configured.

### Gateway bypass

Mitigation: Mitigate can only govern traffic routed through it; scanner highlights discovered direct configs. Do not claim total enforcement without a customer control point.

### Cloud compromise

Mitigation: content minimization, Platform cannot decrypt secrets it never receives, tenant isolation, MFA/admin controls, rate limiting and audit.

### Malicious update

Mitigation: protected release workflow, signed artifacts/manifests, provenance, reproducible builds where practical, rollback and revocation.

### Registry poisoning

Mitigation: source attribution, confidence/provenance, separation of observed facts vs analyst classification, no unsourced definitive accusations.

## Implemented boundaries through MCP-005

This section records current controls; the priority mitigations above also include later production packages. Discovery only reads two bounded project config sources and never executes commands or reads credential references. Explicit stdio inspection requires a separate reviewed launch file and execution intent. It clears ambient environment inheritance, bounds protocol parsing and terminates the OS job/process group on normal completion, failure and cancellation. It runs with the caller's privileges and is not a sandbox.

Local snapshots separate identity, schema, description and server-fact changes. They are unsigned change detectors, not authenticated approval input or anonymized telemetry. Discovery summary fingerprints omit secret and argument values and cannot bind exact gateway execution. Classification ignores instructions in descriptions and retains unknown/open-schema risk. Explicit administrator overrides bind current fingerprints and fail on drift while preserving inferred risk evidence. A same-user process that can replace policy/config/executable files is outside this local file boundary. No Platform egress path or enforcement gateway is claimed by these packages.

Regression evidence: discovery privacy fixtures, subprocess protocol/lifecycle canaries, snapshot drift tests and classification poisoning/stale-override tests. OS-native secret storage, grants, approvals, audit, egress firewall and signed releases remain later gates.

Windows cleanup additionally checks actual job membership, rather than treating any completion-port message as success. A reviewed source patch and deterministic cancellation regression cover the upstream wait defect found in CI; see ADR 0009. This does not widen permissions or change the local execution boundary.

## Known limitations

- A local admin/root user can usually tamper with local security software.
- Unmanaged devices with no Runtime are not visible.
- MCP clients bypassing the gateway are discovered only where scanner visibility exists.
- Tool capability classification can be incomplete or wrong; explicit admin decisions override assisted inference.
- Open-source auditability does not by itself guarantee the shipped binary matches source; provenance/reproducibility addresses that gap.
