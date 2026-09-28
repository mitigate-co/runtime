# Security Policy

Mitigate treats security and privacy failures as product failures.

## Reporting a vulnerability

Do not open public issues for exploitable vulnerabilities or sensitive reports.

The production repository should publish a dedicated security contact and `security.txt` before launch. Until then, repository owners must configure a private GitHub security advisory workflow.

## Scope priorities

High priority includes:

- raw content escaping the Zero-Content boundary,
- credential disclosure,
- authorization bypass,
- command injection,
- MCP server/tool identity confusion,
- policy bypass,
- signature/update-chain compromise,
- cross-tenant access in Platform,
- unauthenticated local control endpoints,
- unsafe destructive-action failover.

## Disclosure process

1. privately acknowledge report,
2. reproduce and classify,
3. contain if necessary,
4. fix with regression test,
5. release signed patched artifacts,
6. publish advisory with appropriate coordination,
7. update threat model and engineering guidance if systemic.

Never retaliate against good-faith security research performed within published rules.
