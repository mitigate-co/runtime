# Public Runtime Repository

**Repository:** https://github.com/mitigate-co/runtime  
**Visibility:** may remain private during development; intended public at release  
**License:** Apache-2.0 target

## Purpose

This repository is the auditable customer-side trust boundary.

For the current wedge it owns:

- `mitigate` CLI,
- MCP scanner,
- MCP gateway,
- Regorus policy runtime,
- local secret-broker interfaces,
- local audit,
- Zero-Content egress firewall,
- privacy self-test/egress inspector,
- registry client,
- signing/update client,
- public protocol/schema types.

## What must never enter this repository

- Mitigate Platform secrets,
- proprietary registry crawler/curation logic,
- customer data,
- internal company credentials,
- proprietary cross-organization analytics,
- private operational dashboards,
- private benchmark aggregation logic.

## Quality bar

Because this repo is the public proof behind Mitigate's privacy promise, it should be our best code.

A security engineer should be able to audit:

- where tool payloads flow,
- where secrets are stored/injected,
- exactly which fields may leave the Runtime,
- how policies are evaluated,
- how updates are verified,
- what happens during cloud failure.

## Suggested public docs

- README
- CONTRIBUTING
- SECURITY
- architecture
- privacy boundary
- telemetry schemas
- MCP scanner/gateway quickstart
- threat model
- reproducible build/release verification

## Pre-release visibility rule

The dedicated Runtime repo may stay private until launch and then be made public **only because it is treated as public-safe from its first commit**. Do not use it as a temporary home for Platform code, company secrets, customer data, private research datasets or proprietary history. Run a full history secret/license/provenance review before changing visibility.

If the repo ever contains material that cannot be public, do not rely on deleting the current file state; Git history must be cleaned/rebuilt deliberately before publication.
