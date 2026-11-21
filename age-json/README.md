# neotales-vaults-age-json

Stores versioned secrets, certificates, and keys in a JSON file with age-encrypted values.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-age-json neotales-vaults-core
```

## What you can do 🔐

**List names.** `Client::list_secrets`, `list_certificates`, and `list_keys`
return stored names, including entries marked deleted. The listing does not
authenticate names in the visible JSON file.

**Remove resources.** Default removal authenticates and marks the latest or
selected version deleted. Purge authenticates and removes the selected version,
or every version when unspecified. Purging the latest does not reactivate older
versions. Backups and filesystem remnants are outside the driver's control.

**Store a resource.** Configure a file path, vault name, native age recipients,
and matching private identities. `Client::set_secret`, `set_certificate`, and
`set_key` create UUIDv7 versions. Read methods accept an earlier version.
The driver uses an adjacent `.lock` file to serialize cooperating writers.
Key reads return exportable private bytes as a redacted `SecretValue`. Treat
those bytes as sensitive and restrict access to the configured identities.

```rust
use neotales_vaults_age_json::{AgeJsonDriver, Config};
use neotales_vaults_core::{Client, SecretValue};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let driver = AgeJsonDriver::new(Config {
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

Names and metadata remain visible. Ciphertext is bound to the vault, name, and
version and resource kind, but the file cannot detect rollback or deletion.
`set_secret_with` can set RFC 3339 expiry, non-secret tags, enabled, and deleted
status on a new version. Reads reject expired or inactive versions. Version
metadata is authenticated for new records, but remains visible.
`update_secret_metadata` replaces metadata on an existing version, including
inactive versions, and re-encrypts it to the currently configured recipients.
Non-native age keys are not supported yet.
Certificate and key bytes are stored as supplied and are not parsed or validated.

## Licence

[MIT](LICENSE.md)
