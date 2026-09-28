# Contributing to Mitigate Runtime

Mitigate Runtime is the auditable customer-side trust layer of Mitigate.

## License

Customer-side runtime code is intended for Apache-2.0 distribution. Every contribution must be compatible with that licensing posture.

Outside contributions require the project's contributor agreement before merge. A DCO/sign-off may also be required by repository configuration.

## Before opening a change

1. Read `AGENTS.md`.
2. Read `docs/MASTER_SPEC.md` and the active module spec.
3. Open or reference an issue for anything larger than a focused bug/documentation fix.
4. Keep changes narrowly scoped.

## Pull requests

A good PR contains:

- problem statement,
- why the change is needed,
- design summary,
- security/privacy impact,
- tests performed,
- compatibility/migration impact,
- screenshots or preview URL for UI changes,
- documentation changes.

Every review should be able to answer: "What invariant is this change preserving or introducing?"

## Dependency policy

Prefer Rust standard library and small, well-maintained permissive dependencies. New dependencies require a reason, license check and security/maintenance review.

Forbidden without explicit owner/legal review:

- AGPL,
- SSPL,
- source-available licenses that create distribution restrictions,
- dependencies that silently collect telemetry,
- dependencies requiring customer content to transit a third party.
