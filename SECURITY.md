# Security policy

## Trust boundary

`zixcel-aws` is not a credential vault. Public requests carry only opaque `secret://aws/...` references and exactly bind subject, device, workload, grant, audience and purpose. The `CredentialUsePort` implementation owns reference resolution, authorization and the replay ledger.

Observe and Propose never call the port. Execute calls it once only after validating explicit mode, a trusted clock, signing timestamp and expiry of 1-300 seconds. Credential audience and HTTP host have distinct meanings and must match independently in the Crowsi binding and request digest. The implementation must atomically consume request IDs and reject reuse even after failure.

Only `secret://aws/{tenant}/zixcel-aws/{purpose}/{audience}/{credential-id}` credential references are accepted. No implicit aliases or host-derived scopes are allowed. Derive the Crowsi resource from the canonical ID using the `crowsi:credential-resource:v1\0` domain digest and match it with the outer `use-credential` action.

## Credential handling

- Never put access key IDs, secret access keys or session tokens in JSON, CLI arguments or environment variables.
- `AwsCredentialMaterial` implements neither Debug, Serialize nor Clone and zeroizes on drop.
- Errors must not include provider messages or credential values.
- Sign only the caller-computed lowercase SHA-256, never a raw body.
- Reject caller-supplied Authorization, Cookie, API keys and SigV4 query credentials.

Only the final Authorization, x-amz-date and, when required, x-amz-security-token may be returned as single-use operation output bound to request digest, audience, service and expiry. This exceptional output is limited to 60 KiB, allowlisted header names, Debug redaction and one stdout JSON object. Never persist it in logs, databases, caches, telemetry or retry queues.

## Response verification

Consumers must verify all the following, use the result immediately, then discard its values:

1. Response protocol and request ID
2. The `request_digest` of the complete typed request JSON
3. Independent bindings of credential `audience`, HTTP `host` and requested service
4. `expires_at_epoch_seconds` against the trusted clock
5. Allowlisted header names and absence of duplicates
6. `result_digest` binding request, scope, expiry and headers

`result_digest` is the SHA-256 of the UTF-8 JSON object with field order `request_digest,audience,service,expires_at_epoch_seconds,headers`, represented as `sha256:<lowerhex>`.

## Unsupported behavior

This crate performs no external HTTP transmission, redirects, credential discovery, AWS profile/environment reads, long-running daemon operation or S3-specific path canonicalization. AWS workloads requiring ambiguous paths remain unsupported until a separately versioned closed contract and dedicated test vectors are added.

## Local IPC

The CLI connects only to an owner-local Unix socket whose path contains no secrets. Socket and peer UID, parent directory, modes, frame size and timeout are validated fail-closed. The Coordinator uses only authorized short-lived Crowsi leases through `CredentialOperationExecutor` and must not persist responses. This repository alone contains no daemon, credential store or external communication route.

## Common OSS reporting policy

# Security policy

## Reporting a vulnerability

Use this repository's Security tab and **Report a vulnerability** to submit a private
report to maintainers. Do not open a public issue or pull request containing exploit
details, credentials, customer data, or personal information. If private reporting
is unavailable, use GitHub's private security-support channel and request a private
reporting route before disclosing details.

Include affected versions, a minimal synthetic reproduction, expected and observed
behavior, and impact. Remove real secrets and identifying data. Maintainers assess
the report and coordinate a correction and disclosure. No response-time guarantee,
bounty, or support contract is implied.

## Supported versions

The current main branch is maintained during development. Released-version support
is stated in release notes; older releases are not implicitly supported. Do not infer
runtime safety from a source scan or a passing CI policy check. Dependencies,
deployments, history, and application-specific authorization require their own checks.
