# zixcel-aws-custody-adapter interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

## Acceptance

Verify exact operation/target binding, refusal outside the authorized scope,
secret-free projections and cleanup after provider failure. Configuration and
real provider execution must be verified separately from fixture tests. No AWS
account, external operation or credential is provisioned by installing this crate.
