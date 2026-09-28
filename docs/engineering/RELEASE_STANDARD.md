# Mitigate Release Standard

## Runtime release gates

A public Runtime release requires:

- clean protected commit/tag,
- full CI green,
- privacy fixture suite green,
- malicious MCP/config suite green,
- dependency/license/secret scans green,
- SBOM generated,
- binary/package signatures,
- checksums,
- provenance/attestation,
- macOS notarization where distributed,
- release notes,
- supported-platform smoke tests.

## Versioning

Use SemVer once external compatibility matters.

Protocol/schema versions can evolve independently but must have explicit compatibility mapping.

## Rollback

Document which previous version is safe to revert to and any schema/config migration implications.

## Platform deploy

- preview/test,
- staging,
- production promotion,
- forward-compatible DB migrations first,
- backup/checkpoint before risky production migrations,
- post-deploy health verification,
- rollback procedure.
