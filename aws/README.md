# neotales-vaults-aws

Reads and updates provisioned AWS Secrets Manager secrets.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-aws neotales-vaults-core aws-config tokio --features tokio/macros,tokio/rt-multi-thread
```

## What you can do 🔐

**List and remove secrets.** Listing returns names across all pages. Removal
schedules deletion of all versions; `purge` requests deletion without recovery.
AWS performs final deletion asynchronously. Individual versions cannot be
directly removed. `removal_with_recovery_days` configures a 7–30 day window;
it cannot be combined with purge.

**Use the provider.**

```rust
use neotales_vaults_aws::{AwsDriver, Config};
use neotales_vaults_core::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let driver = AwsDriver::new(Config { vault: "work".into(), sdk, allow_http_loopback: false })?;
    let secret = Client::new(driver).get("work", "token")?;
    println!("Loaded {} bytes", secret.value.expose().len());
    Ok(())
}
```

 AWS Secrets Manager driver for `neotales-vaults`. The caller supplies an AWS
SDK shared configuration, including its credentials provider and region.
The driver disables SDK retries. Reads support explicit version IDs. Writes
update existing secrets; creation is deliberately a separate provisioning step.
`EnsureSecret` is an exception: it creates a missing secret using AWS
`CreateSecret` and reads the existing secret if another caller created it first.
The caller controls credential refresh through the SDK. Custom HTTP endpoints
require explicit opt-in and a literal loopback address.

An opt-in integration test exercises a provisioned secret and local encryption
against the pinned Floci AWS image:

```sh
cargo test -p neotales-vaults-aws --test floci -- --ignored
```

Docker and the locally cached image named in the test are required. Real AWS
interoperability is not yet verified.


## Licence

[MIT](LICENSE.md)
