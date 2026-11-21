# neotales-vaults-keepass

Reads and writes KeePass secrets, certificates, and keys through the `neotales-keepass` KDBX library.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-keepass neotales-vaults-core
```

## What you can do 🔐

**List names.** List root entry titles as secret names, or titles in the
driver's marked certificate and key groups. Duplicate titles fail as ambiguous;
nested KeePass groups are not traversed.

**Remove an entry.** With writes enabled, removal moves it to the KeePass
recycle bin when enabled; otherwise it deletes it and records a tombstone.
`purge` deletes an active or uniquely matching recycled entry and records a
tombstone. Backups and filesystem remnants are not erased. Entry versions
cannot be selected.

**Read a password.** Configure a path, a vault name, and a database password,
then pass `KeepassDriver` to the core client. The secret name selects a unique
entry title in the database root. Duplicate titles fail closed. Nested groups
and entry history are not supported.

**Discover credentials.** Use `KeepassDriver::discover(vault, path)` to look up
the database password in the native OS credential store. The service is
`neotales-vaults-keepass`, and the account is the canonical absolute UTF-8
path to the KDBX file. A stored password takes precedence over
`KEEPASS_SECRET`; if no entry exists or the store is unavailable, the
environment password is used when present. `KEEPASS_KEYFILE`, when set, is
the path to an additional KeePass key file. A key file can be used alone or
with a password. Credentials are captured at discovery time; changing them
requires constructing a new driver. No credentials are stored automatically.
The explicit `KeepassDriver::new(Config { ... })` path continues to use only
its supplied password, without consulting the keyring or environment.

```rust
use neotales_vaults_core::Client;
use neotales_vaults_keepass::KeepassDriver;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let driver = KeepassDriver::discover("work", std::env::var_os("KEEPASS_DATABASE").ok_or("set KEEPASS_DATABASE")?)?;
	let secret = Client::new(driver).get("work", "mail")?;
	println!("Loaded {} bytes", secret.value.expose().len());
	Ok(())
}
```

Certificates and keys use separate marked groups named
`neotales-vaults-certificates-v1` and `neotales-vaults-keys-v1`. Resource
payloads are encoded in protected password fields. An existing unmarked group
with either reserved name is never overwritten. Certificate and key bytes are
stored as supplied and are not validated.

**Enable writes explicitly.** Call `with_write_options` on the driver with
`KdbxWriteOptions`. Each write rewrites the entire database as KDBX 4.1 using
those settings, which can change the cipher and KDF. Test interoperability and
keep a backup before enabling it. A sidecar lock coordinates cooperating
drivers only. Other applications can race with the final replacement.

## Licence

[MIT](LICENSE.md)
