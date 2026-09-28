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

## Known limitations

- A local admin/root user can usually tamper with local security software.
- Unmanaged devices with no Runtime are not visible.
- MCP clients bypassing the gateway are discovered only where scanner visibility exists.
- Tool capability classification can be incomplete or wrong; explicit admin decisions override assisted inference.
- Open-source auditability does not by itself guarantee the shipped binary matches source; provenance/reproducibility addresses that gap.
