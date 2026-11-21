# neotales-vaults-local-json

Stores versioned resources in an encrypted local JSON vault.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-local-json neotales-vaults-local-crypto neotales-vaults-core neotales-vaults-azure
```

## What you can do 🔐

**List names.** `Client::list_secrets`, `list_certificates`, and `list_keys`
return stored names, including entries marked deleted.

**Remove resources.** Default removal marks the latest or selected version
deleted. Purge removes the selected version, or all history if no version is
specified. Purging the current version does not make an older version current.
Purge cannot erase backups or filesystem remnants.

**Use the provider.**

```rust
use neotales_vaults_azure::{AzureDriver, Config as AzureConfig};
use neotales_vaults_core::{Client, SecretValue};
use neotales_vaults_local_crypto::{Config as CryptoConfig, LocalCrypto};
use neotales_vaults_local_json::{Config, LocalJsonDriver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let remote = Client::new(AzureDriver::new(AzureConfig {
        vault: "cloud".into(), address: std::env::var("AZURE_VAULT_URL")?,
        token: SecretValue::new(std::env::var("AZURE_ACCESS_TOKEN")?.into_bytes()),
        allow_http_loopback: false,
    })?);
    let crypto = LocalCrypto::new(remote, CryptoConfig {
        vault: "cloud".into(), key_name: "encryption-key".into(),
        key_version: std::env::var("KEY_VERSION")?,
    })?;
    let local = LocalJsonDriver::new(Config {
        vault: "local".into(), path: std::env::var("VAULT_PATH")?.into(),
    }, crypto)?;
    let secret = Client::new(local).get("local", "token")?;
    println!("Loaded {} bytes", secret.value.expose().len());
    Ok(())
}
```

A versioned local JSON vault encrypted with a version-pinned secret from a
`neotales-vaults` client. It can use AWS, Azure, or GCP secret-manager drivers
as the key source. The caller must provision and retain the encryption key;
see `neotales-vaults-local-crypto` for its encoding.

The implementation supports versioned secret, certificate and key reads and
writes. Certificate and key bytes are stored as supplied, without validation.
Secret versions support expiry, tags, enabled and deleted status, including
metadata replacement. Secret-only documents from the initial format remain
readable.
The whole JSON document is authenticated and encrypted. Cooperating writers
use a sidecar lock and an atomic replacement, but external modifications and
rollback are not detected. Keep the key version and vault name stable to read
the file. Writes are not retried and an error can leave their outcome unknown.

This crate is intended for publication but has not been published.

## Licence

[MIT](LICENSE.md)
