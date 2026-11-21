# neotales-vaults-infisical

Reads and writes Infisical shared secrets through its v4 HTTP API.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-infisical neotales-vaults-core
```

## What you can do 🔐

**List and remove shared secrets.** Listing requests names without values or
imports, for the configured folder. Default removal uses Infisical's delete
API; a pending approval is not reported as a completed deletion. The API does
not expose purge or version selection through this driver.

**Read and write a shared secret.** Configure a project, environment, folder,
and an existing bearer access token. Pass the driver to a core client. Values
must be UTF-8. Version selection is not supported.

```rust
use neotales_vaults_core::{Client, SecretValue};
use neotales_vaults_infisical::{Config, InfisicalDriver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let driver = InfisicalDriver::new(Config {
        vault: "work".into(), address: std::env::var("INFISICAL_URL")?,
        project_id: std::env::var("INFISICAL_PROJECT_ID")?,
        environment: "dev".into(), secret_path: "/".into(),
        token: SecretValue::new(std::env::var("INFISICAL_TOKEN")?.into_bytes()),
        allow_http_loopback: false,
    })?;
    let secret = Client::new(driver).get("work", "TOKEN")?;
    println!("Loaded {} bytes", secret.value.expose().len());
    Ok(())
}
```

Writes first check whether the secret exists and then create or update it.
Concurrent changes by other clients can affect the outcome. Failed writes
are not retried. HTTPS is required except for explicitly enabled literal
loopback HTTP. An opt-in integration test exercises creation, reading, and
updating against a disposable Infisical v0.167.11 instance:

```sh
cargo test -p neotales-vaults-infisical --test live -- --ignored
```

It requires Docker and the pinned Infisical, PostgreSQL, and Redis images in
the test source to be available locally.

## Licence

[MIT](LICENSE.md)
