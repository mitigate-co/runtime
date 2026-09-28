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

MCP-011's policy boundary verifies independently pinned Ed25519 signatures and
the restricted Rego AST before activation. Source and raw tool payloads do not
enter decision reports; raw payloads have no policy-input field. Parser bounds
precede Regorus, and allowed expressions cannot generate unbounded collections
or perform I/O. Timeouts/conflicts are errors, never implicit allow. Atomic
replacement and persistent increasing versions prevent normal rollback/replay;
the loaded last-known-good policy survives invalid refresh/storage failures.
Separate trust/cache files remain vulnerable to a privileged same-user attacker
or full old-store restoration. Signing authenticates an authority, not policy
correctness. This is not hardware rollback protection or a process memory quota.
See [policy profile and limits](POLICY.md). The explicit
[governed gateway](ENFORCEMENT.md) composes this boundary with grants and approvals.

The MCP-009 secret broker stores values only in the current user's native credential
store. Opaque references cannot select other services, arbitrary paths or vault
providers. Child bindings are explicitly reviewed, bounded and resolved before
launch; unknown/locked/missing/ambiguous records fail without ambient fallback.
Values and provider errors never enter normal diagnostics. Windows records use
Local persistence. Native OS operations are trusted IPC, not Platform egress.
See [credential handling](SECRETS.md) and ADR 0012 for native prompts and failure
semantics. This does not hide credentials from the selected upstream, its
descendants, another privileged same-user process, or every memory dump/swap page.
Deleting a reference does not revoke copied provider credentials. Full telemetry
privacy enforcement and release gates remain open; per-call governance cannot
revoke a credential already copied into a selected server's environment.

The executable gateway requires an explicit inventory-only or governed mode. Inventory-only denies every call. Governed mode requires reviewed launch/definitions, verified local authority and mandatory audit; see [composition and commit boundaries](ENFORCEMENT.md). Both validate profiles before launch and confirm upstream cleanup on EOF, timeout or graceful shutdown. Its standard-I/O worker lifetime ends at CLI process exit; see ADR 0011. Abrupt OS termination can skip Rust destructors, especially on Unix, so graceful cleanup tests do not establish crash-proof descendant containment. No sandbox is implied.

The managed stdio adapter retains an initial fingerprint baseline and re-enumerates before each authorized transport call. Drift prevents invocation; malformed responses and errors invalidate and terminate the connection. Cancellation poisons the connection before releasing its borrow, preventing a later call from consuming a stale response. Tests verify descendant cleanup and absence of invocation on drift. These are transport controls, not proof of server behavior or a substitute for policy, schema validation, grants and approval. See [upstream boundaries](UPSTREAM.md).

The MCP-007 listener additionally rejects ambiguous envelopes, reused IDs and out-of-order initialization, bounds local streams, and prevents clientInfo or request metadata from changing caller identity. Profile identity is explicitly declared, never authenticated by implication. Cancellation and disconnect drop in-flight service work; the upstream owner must confirm cleanup. No permissive service or network listener is included. See [gateway boundaries](GATEWAY.md) and ADR 0010. This protocol library alone is not an enforcing gateway.

- A local admin/root user can usually tamper with local security software.
- Tool schemas must pass a closed, bounded local execution profile before calls.
  Unknown dialects/keywords, external references, cycles and excessive expansion
  fail closed. Both input and output schemas compile before invocation; invalid
  results are withheld, without retrying possibly completed effects. Validation
  workers retain bounded admission slots after timeout/cancellation. This is not
  a thread-killing timeout or OS sandbox. See [schema validation](SCHEMA_VALIDATION.md)
  and ADR 0019. Raw result content is still workload data, not safe telemetry.
- Governed-call audit separates pre-dispatch authorization from observed outcome.
  Required caller/tool/policy/approval facts are checked before a dispatch record
  can be appended. The store does not itself authorize execution or authenticate
  operators. Missing completion is unknown outcome, never permission to replay.
  Mixed-version chains preserve legacy encoding; old readers refuse new records
  without rewriting them. See [call audit](AUDIT.md) and ADR 0020.
- Local control state and quota balances survive normal restarts and use atomic
  shared-database admission. Emergency/exact disables precede quotas; a failed
  commit releases no allowance. Missing/corrupt/busy/full storage and backward
  time fail closed. Exact unknown identity stays unknown; other governance must
  authorize it independently. Trusted OS time, parent-directory permissions and
  same-user ownership remain assumptions. Whole-file restoration can roll back
  local state; history is bounded and not remote attestation. Already-dispatched
  effects cannot be undone. See [controls](CONTROLS.md) and ADR 0017. Governed
  admission never refunds quota when a subsequent approval/audit check fails.
- Optional exact launch review binds executable bytes, selected code artifacts,
  argv, cwd, ordinary environment and native reference destinations. Reviewed
  connections recheck selected code after inventory refresh and before invoking
  a tool. Drift invalidates the session; self-reported names cannot substitute
  for the reviewed launch reference. Reviews neither authenticate publishers
  nor measure unselected transitive code. Protect local files/directories;
  privileged replacement races remain out of scope. See [launch review](LAUNCH_REVIEW.md)
  and ADR 0018. Review is one requirement, never complete call authorization.
- Local one-call approvals bind exact caller/session/call, tool definitions and
  policy facts, expire, and commit consumed state before returning a permit.
  Races, replay, changed context and storage failure cannot produce a second permit.
  Operator attribution is declared, not authenticated; same-user database access
  is trusted. No raw arguments or predictable argument hashes are stored. Retention
  is bounded and whole-database rollback by a privileged attacker is outside this
  guarantee. See [approval boundaries](APPROVALS.md) and ADR 0016. The live gateway
  owns bounded waiting, rechecks and correlated call audit. A metadata worker has
  no transport handle and cannot dispatch after request cancellation.
- Local grants use explicit exact scopes and deny precedence. A missing constraint
  is rejected rather than interpreted as a wildcard; unknown clients cannot be
  allowed. Grants and policy remain separate checks, and partial allowances cannot
  be combined for a broader action. The pure matcher trusts gateway-supplied facts
  and time; it does not authenticate profiles or prevent privileged clock rollback.
  These local rule files are not automatically trusted cloud input. See
  [grant boundaries](GRANTS.md) and ADR 0015. Governed mode reloads rules at each
  authorization check and requires independent policy and admission checks.
- Local audit uses bounded SQLite metadata and a hash chain. Raw content is excluded;
  retention intentionally removes an oldest prefix and preserves its checkpoint.
  Corruption or unexpected schema prevents export and required gateway startup.
  A same-user/admin attacker who controls the database can recompute the chain or
  restore an old valid copy; local verification is not signed remote attestation.
  Protect the parent directory and backups. See [audit limits](AUDIT.md).
- Unmanaged devices with no Runtime are not visible.
- MCP clients bypassing the gateway are discovered only where scanner visibility exists.
- Tool capability classification can be incomplete or wrong; explicit admin decisions override assisted inference.
- Open-source auditability does not by itself guarantee the shipped binary matches source; provenance/reproducibility addresses that gap.
