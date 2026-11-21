# neotales-vaults

Read vault secrets, certificates and keys through a shared Rust API.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-core
```

## What you can do 🔐

**Choose a provider.** [`core/`](core/) defines the interfaces,
[`vaults/`](vaults/) registers configured drivers and resolves references, and
[`os/`](os/) reads and writes secrets in the operating system credential store.
[`keepass/`](keepass/) reads and optionally writes passwords, certificates, and
keys in KDBX files.
[`age-json/`](age-json/) stores versioned, age-encrypted secrets, certificates,
and keys in JSON.
[`age-sqlite/`](age-sqlite/) stores the same resource types in SQLite.
[`vault/`](vault/) connects to Vault and OpenBao KV v2 over HTTP.
[`infisical/`](infisical/) reads and writes Infisical shared secrets.
[`crypto/`](crypto/) generates local signing keys and self-signed certificates.
[`vaultwarden/`](vaultwarden/) reads and optionally updates login passwords
through the Bitwarden CLI.
[`aws/`](aws/), [`azure/`](azure/), and [`gcp/`](gcp/) access their cloud
secret managers. [`local-crypto/`](local-crypto/) encrypts individual values
or whole JSON documents using a versioned vault-stored key;
[`local-json/`](local-json/) uses that key source for a versioned local vault.
Cloud emulator tests are opt-in; see each provider's README.
Workspace and integration test instructions are in [`TESTING.md`](TESTING.md).
Listing, removal, and purge behavior by provider is in
[`PROVIDERS.md`](PROVIDERS.md).

**Parse a reference.**

```rust
use neotales_vaults_core::{ResourceKind, VaultUri};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reference: VaultUri = "nv://work/secrets/api-key/v2?region=west".parse()?;
    assert_eq!(reference.kind, ResourceKind::Secret);
    assert_eq!(reference.version.as_deref(), Some("v2"));
    Ok(())
}
```

**Implement a driver.** Implement `Driver` with your provider's configuration and
pass it to `Client::new`. `get` reads the current value; `get_with` accepts
a version and retry override. Driver capabilities are operation-specific.
The OS driver supports secret reads and writes, but not versions.

Retry policies are selected per call, then per client, then globally. Only
errors classified `Transient` are retried through `neotales-resilience`. Calls
and sleeps are synchronous. Writes are not automatically retried. Tracing and
the `metrics` facade record operation kinds and outcomes, never names or values.
Metrics are no-ops unless the application installs a recorder.

## Licence

[MIT](LICENSE.md)
