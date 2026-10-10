# Using zixcel-aws-custody-adapter

Connect an authorized AWS operation to credential use inside Crowsi custody.

## Before you start

The caller supplies exact scope and transport. Neither adapter availability nor a valid plan grants AWS account access.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate the AWS operation and principal purpose.
- Compose declared signing and runtime interfaces.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
