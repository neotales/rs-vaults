# neotales-vaults-age-sqlite

Stores versioned secrets, certificates, and keys in an age-encrypted SQLite vault.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-age-sqlite neotales-vaults-core
```

## What you can do 🔐

**List and remove resources.** Listing returns names, including entries marked
deleted; database names are visible and listing does not authenticate them.
Default removal marks the selected or latest version deleted. Purge removes one
version or, when no version is specified, all versions. Purging the latest does
not reactivate older versions. SQLite journals, backups and storage remnants
are outside the driver's control.

**Store a resource.** Configure a vault name, SQLite path, native age recipients,
and matching identities. Core clients can write and read secrets, certificates,
and exportable keys. Each write creates a UUIDv7 version. SQLite transactions
keep the current-version pointer and value together.

```rust
use neotales_vaults_age_sqlite::{AgeSqliteDriver, Config};
use neotales_vaults_core::{Client, SecretValue};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let driver = AgeSqliteDriver::new(Config {
		vault: "work".into(),
		path: std::env::var("VAULT_PATH")?.into(),
		recipients: vec![std::env::var("AGE_RECIPIENT")?],
		identities: vec![SecretValue::new(std::env::var("AGE_IDENTITY")?.into_bytes())],
	})?;
	let secret = Client::new(driver).get("work", "token")?;
	println!("Loaded {} bytes", secret.value.expose().len());
	Ok(())
}
```

The database stores encrypted values, but names and versions remain visible.
The driver cannot detect deletion or rollback. SQLite may create temporary
journal files while transactions run. Certificate and key bytes are not parsed
or validated. Do not point the driver at an unrelated SQLite database.

`set_secret_with` sets RFC 3339 expiry, non-secret tags, enabled, and deleted
status when creating a version. The metadata is encrypted with the value.
Reads reject expired or inactive versions. `update_secret_metadata` replaces
metadata on an existing version, including inactive versions, and re-encrypts
it to the currently configured recipients.

## Licence

[MIT](LICENSE.md)
