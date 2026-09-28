# Mitigate Security Engineering Standard

## Secure-by-default review questions

For every feature ask:

1. What untrusted input enters?
2. What can it cause the process to do?
3. What secret/content can it see?
4. What leaves the customer boundary?
5. What happens if Platform is unavailable?
6. What happens if upstream MCP is malicious?
7. How is identity established?
8. What is logged?
9. What is persisted?
10. How is the feature disabled/revoked?

## Secret handling

- no secrets in CLI args when avoidable,
- no secrets in process list/logs,
- local secure storage,
- shortest feasible lifetime,
- separate secret references from metadata,
- child process gets only required secret/environment.

## Input handling

- parse, don't concatenate,
- explicit size limits,
- timeouts,
- concurrency limits,
- path canonicalization where needed,
- no unsafe shell expansion,
- treat server descriptions/tool schemas as untrusted data.

## Local interfaces

Prefer Unix domain sockets / Windows named pipes. If loopback HTTP is needed:

- bind loopback only,
- authenticate requests,
- capability/CSRF considerations,
- random/short-lived tokens,
- explicit origin/client assumptions.

## Supply chain

CI includes:

- dependency vulnerability scan,
- license scan,
- secret scan,
- SBOM generation,
- artifact signing,
- provenance/attestation.

Pin/lock dependencies. Review major transitive changes.

## Updates

- signed manifest,
- signed artifact,
- checksum,
- rollback path,
- staged rollout when fleet update exists,
- do not execute unsigned "latest" downloads.

## Threat model maintenance

Update `docs/THREAT_MODEL.md` when trust boundaries/capabilities change.
