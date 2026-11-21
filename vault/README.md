# neotales-vaults-vault

Reads and writes Vault and OpenBao KV v2 secrets over HTTP.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-vault neotales-vaults-core
```

## What you can do 🔐

**Remove a secret.** Default removal soft-deletes the latest version; specify a
version to soft-delete it instead. With `purge`, a specified version is
destroyed, or without a version all versions and metadata are deleted.

**List secret names.** Listing traverses the KV v2 metadata API and returns
slash-separated paths. Each segment must be nonempty and cannot be `.` or `..`.

**Read a versioned secret.** Configure the server origin, KV v2 mount, vault
name, and token, then use a core client. `get_with` accepts Vault's positive
integer version. `set_secret` stores UTF-8 text in the `value` field; it
merges existing data and uses create-only CAS for a missing path.

```rust
use neotales_vaults_core::{Client, SecretValue};
use neotales_vaults_vault::{Config, VaultDriver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let driver = VaultDriver::new(Config {
        vault: "work".into(), address: std::env::var("VAULT_ADDR")?,
        mount: "secret".into(), namespace: None, allow_http_loopback: false,
        token: SecretValue::new(std::env::var("VAULT_TOKEN")?.into_bytes()),
    })?;
    let secret = Client::new(driver).get("work", "token")?;
    println!("Loaded {} bytes", secret.value.expose().len());
    Ok(())
}
```

The driver requires HTTPS except for explicitly enabled literal-loopback HTTP.
It disables redirects and does not retry writes. An opt-in test exercises
OpenBao 2.3.1 in a disposable container:

```sh
cargo test -p neotales-vaults-vault --test openbao -- --ignored
```

The test requires Docker and the image pinned in the test source. A separate
ignored test in the same file exercises HashiCorp Vault 1.21.4.

## Licence

[MIT](LICENSE.md)
