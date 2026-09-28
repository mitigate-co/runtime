# Error Handling Standard

## Principle

Errors are part of the product API. They should be actionable, typed where useful, and safe to expose/log.

## Layers

### Library/domain errors

Use structured variants that preserve semantics:

```text
ConfigInvalid
ServerLaunchFailed
McpHandshakeFailed
ToolNotFound
PolicyDenied
ApprovalExpired
SecretUnavailable
EgressRejected
PlatformUnavailable
```

### Application/CLI errors

Add human context and recovery suggestion without exposing payloads/secrets.

### Platform API errors

Return stable error code, request ID and safe message. Keep internal stack/detail server-side in sanitized logs.

## Secret/content safety

Never include raw:

- auth headers,
- env secret values,
- tool arguments/results,
- raw subprocess stderr if it may contain credentials,
- customer file bodies.

If upstream text is useful for debugging, classify/store locally under explicit diagnostic mode rather than central logging.

## Retries

Retry only errors known to be transient and only when operation semantics are safe/idempotent.

Never retry an egress/privacy rejection with the same rejected payload.
