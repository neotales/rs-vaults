# neotales-vaults-azure

Reads and writes Azure Key Vault secrets.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-azure neotales-vaults-core
```

## What you can do 🔐

**List and remove secrets.** Listing follows Key Vault's pages and returns
names. Default removal soft-deletes the entire secret, including its versions.
`purge: true` purges a previously deleted secret; call deletion first. Purge
protection can prevent that operation. Individual versions cannot be removed.

**Use the provider.**

```rust
use neotales_vaults_azure::{AzureDriver, Config};
use neotales_vaults_core::{Client, SecretValue};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let driver = AzureDriver::new(Config {
        vault: "work".into(), address: std::env::var("AZURE_VAULT_URL")?,
        token: SecretValue::new(std::env::var("AZURE_ACCESS_TOKEN")?.into_bytes()),
        allow_http_loopback: false,
    })?;
    let secret = Client::new(driver).get("work", "token")?;
    println!("Loaded {} bytes", secret.value.expose().len());
    Ok(())
}
```

Azure Key Vault secret provider for `neotales-vaults`. Configure a vault URL
and an already obtained bearer token. Secret values must be UTF-8. Reads
support explicit Azure secret versions. The caller must refresh the token
before it expires. Certificates and keys are not supported by this driver.

HTTPS is required except for explicitly enabled literal loopback HTTP, for
local emulators. Redirects are disabled. Writes are not retried.

An opt-in test uses a disposable, loopback-bound Floci Azure container:

```sh
cargo test -p neotales-vaults-azure --test floci -- --ignored
```

Docker and the locally cached image pinned in the test are required. This test
does not establish compatibility with a real Azure account.

## Licence

[MIT](LICENSE.md)
