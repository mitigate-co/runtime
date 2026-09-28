# Repository Standard

## Public Runtime — `mitigate-co/runtime`

Recommended root:

```text
runtime/
├── .github/
│   ├── workflows/
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── crates/
├── schemas/
├── docs/
├── examples/
├── tests/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── AGENTS.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── NOTICE
└── CHANGELOG.md
```

Public README should be excellent: problem, trust/privacy model, install, 60-second scan, gateway quickstart, docs links, security reporting, license.

## Private Platform — `mitigate-co/platform`

Recommended root:

```text
platform/
├── apps/
│   ├── web/
│   ├── control-api/
│   ├── ingest-api/
│   └── jobs/
├── packages/
│   ├── db/
│   ├── contracts/
│   ├── registry/
│   └── ui/
├── infra/
├── docs/
├── AGENTS.md
├── README.md
└── package.json
```

Do not share a repository merely to avoid defining an API boundary. The public/private split is intentional.
