# neotales-vaults-core

Defines provider-neutral interfaces for reading vault secrets, certificates and keys.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-core
```

## What you can do

**Ensure a secret exists.** Import `EnsureSecret` and call
`client.ensure_secret(vault, name, &options)`. It returns the existing value,
or generates and creates a new one only after a `NotFound` error. Transient failures use the
configured retry policy, checking for the value again before each attempt.
The generic read-then-write fallback is not atomic: a concurrent writer can
be overwritten, and a provider may report an inactive secret as not found.
Drivers with conditional creation provide stronger protection. Some providers
cannot create a missing secret through their current driver, including the
Bitwarden CLI driver, which addresses items by server-assigned UUID.

```rust
use neotales_vaults_core::{Client, EnsureSecret, GenerationOptions};

fn ensure_token(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let token = client.ensure_secret("work", "token", &GenerationOptions::default())?;
    println!("Loaded {} bytes", token.value.expose().len());
    Ok(())
}
```

**List names and remove resources.** `Client::list_secrets`,
`list_certificates`, and `list_keys` return names only. The corresponding
remove methods accept `RemoveOptions` with `purge`, `version`, and
provider-specific `query` fields. Providers reject unsupported operations or
options. Default removal is not necessarily recoverable, and is never retried.

**Parse a reference.** 🔐

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
pass it to `SecretsClient::new`. `get` reads the current value; `get_with` accepts
a version and retry override. Driver capabilities are operation-specific.
Concrete drivers are maintained as separate crates in this workspace; see
the [workspace README](https://github.com/neotales/rs-vaults).

Retry policies are selected per call, then per client, then globally. Only
errors classified `Transient` are retried through `neotales-resilience`. Calls
and sleeps are synchronous. Writes are not automatically retried. Tracing and
the `metrics` facade record operation kinds and outcomes, never names or values.
Metrics are no-ops unless the application installs a recorder.

## Licence

[MIT](LICENSE.md)
