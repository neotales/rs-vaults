# neotales-vaults

Registers vault drivers and resolves `nv://` references.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults neotales-vaults-core neotales-vaults-os
```

## What you can do 🔐

**Register a driver.** Create a `Registry`, then call `register` with a
configured core `Client`. `get_uri("nv://work/secrets/token")` resolves the
registered vault and reads its secret. Add `?ensure=1&size=30` to generate a
missing secret. `upper`, `lower`, `digits`, `symbols`, `size`, and `chars`
accept aliases `U`, `L`, `D`, `S`, `s`, and `c`; booleans accept `true`,
`false`, `1`, and `0`. All classes default to enabled and size defaults to 16.
`chars` replaces the character classes.

```rust
use neotales_vaults::{Registry, Resource};
use neotales_vaults_core::Client;
use neotales_vaults_os::{Config, OsDriver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let driver = OsDriver::new(Config { service: "example".into() })?;
	let mut vaults = Registry::new();
	vaults.register("work", Client::new(driver))?;
	let Resource::Secret(secret) = vaults.get_uri("nv://work/secrets/token")? else {
		return Err("expected a secret".into());
	};
	println!("Loaded {} bytes", secret.value.expose().len());
	Ok(())
}
```

## Licence

[MIT](LICENSE.md)
