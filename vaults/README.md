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
registered vault and reads its secret. URI query parameters are rejected.

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
