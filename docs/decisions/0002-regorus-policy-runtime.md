# ADR-0002: Regorus for Embedded Rego Policy

Status: Accepted  
Date: 2026-09-27

## Context

The Runtime is Rust. The older plan used OPA/Rego compiled to WASM, adding another runtime/host boundary.

## Decision

Embed Regorus and define a documented Mitigate Rego Profile. Validate representative policies against OPA reference behavior in CI where practical.

## Consequences

- simpler Rust packaging,
- fewer moving parts in the trust boundary,
- cannot casually promise support for every OPA builtin,
- policy compatibility becomes a tested product contract.
