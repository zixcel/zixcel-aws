# zixcel-aws-custody-adapter

Connect an authorized AWS operation to credential use inside Crowsi custody.

## What you can do

- Validate the AWS operation and principal purpose.
- Compose declared signing and runtime interfaces.

## Current scope

The caller supplies exact scope and transport. Neither adapter availability nor a valid plan grants AWS account access.

Package distribution is not activated by this documentation. Use the owning product workspace and declared dependency versions. Registry availability is a separate release gate.

## Getting started

Install Rust 1.97 or newer. Run from the owning product workspace:

```sh
cargo test --locked -p zixcel-aws-custody-adapter
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Detailed documentation](docs) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

## Product responsibility

This component is maintained in [zixcel/zixcel-aws](https://github.com/zixcel/zixcel-aws). Use the [product README](../../README.md) for composition, use cases and trust boundaries.
