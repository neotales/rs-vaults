# neotales-vaults-gcp

Reads and updates provisioned Google Cloud Secret Manager secrets.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-gcp neotales-vaults-core
```

## What you can do 🔐

**List and remove secrets.** Listing returns secret IDs across pages. Removing
without a version deletes the entire secret and all versions; this is not
recoverable. With a version, default removal disables it and purge requests
destruction. A configured destruction delay can defer permanent destruction.
Use `removal_with_etag` to require a matching entity tag.

**Use the provider.**

```rust
use neotales_vaults_core::{Client, SecretValue};
use neotales_vaults_gcp::{Config, GcpDriver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let driver = GcpDriver::new(Config {
        vault: "work".into(), project: std::env::var("GOOGLE_CLOUD_PROJECT")?,
        endpoint: "https://secretmanager.googleapis.com".into(),
        token: SecretValue::new(std::env::var("GOOGLE_ACCESS_TOKEN")?.into_bytes()),
        allow_http_loopback: false,
    })?;
    let secret = Client::new(driver).get("work", "token")?;
    println!("Loaded {} bytes", secret.value.expose().len());
    Ok(())
}
```

Google Cloud Secret Manager driver for provisioned secrets. It uses gRPC and a
caller-provided OAuth bearer token; callers must refresh that token themselves.
Reads accept concrete version numbers. Writes create a new version of an
existing secret, and are not automatically retried.

HTTPS is required except for explicitly enabled literal-loopback HTTP for local
emulators.

An opt-in test uses the pinned Floci GCP image to exercise versioned reads,
updates, and local JSON encryption using a stored key:

```sh
cargo test -p neotales-vaults-gcp --test floci -- --ignored
```

Docker and the locally cached image named in the test are required. Real GCP
interoperability is unverified.

## Licence

[MIT](LICENSE.md)
