# Using zixcel-aws

Prepare bounded AWS operations and signing requests without making secrets part of the public contract.

## Before you start

The calling application supplies principal, purpose, authorization and transport. Secret custody is outside the serialized request.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate an AWS operation and its signing context.
- Compose SigV4 work with a credential-custody implementation.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
