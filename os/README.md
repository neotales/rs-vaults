# neotales-vaults-os

Reads and writes secrets in the operating system credential store.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-os neotales-vaults-core
```

## What you can do 🔐

**Read an OS credential.** Construct `OsDriver` with a service name and use it
with a core `Client`. Accounts use a domain-separated SHA-256 hash of the vault
and secret names. `Client::set_secret` creates or replaces the value.
Only secrets are supported; versions are rejected. Failed writes may have an
unknown outcome and are not automatically retried.

`remove_secret` deletes an existing credential. It rejects `purge`, `version`,
and provider-specific options. Listing is unavailable: account identifiers are
hashed and cannot be converted back to names.

```rust
use neotales_vaults_core::Client;
use neotales_vaults_os::{Config, OsDriver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let client = Client::new(OsDriver::new(Config { service: "example".into() })?);
	let secret = client.get("work", "token")?;
	println!("Loaded {} bytes", secret.value.expose().len());
	Ok(())
}
```

On Linux, an opt-in test starts a private D-Bus session with a temporary home
and Secret Service, without using the desktop keyring:

```sh
cargo test -p neotales-vaults-os --test linux_secret_service isolated_secret_service_round_trip -- --ignored --exact
```

It requires `dbus-run-session`, `dbus-send`, and `gnome-keyring-daemon`.

## Licence

[MIT](LICENSE.md)
