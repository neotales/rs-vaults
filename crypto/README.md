# neotales-vaults-crypto

Generates local signing keys and self-signed X.509 certificates for vault clients.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-crypto
```

## What you can do 🔐

**Generate a key.** `generate_key` returns an Ed25519 or ECDSA P-256 key in
the core `Key` type. Private bytes are PKCS#8 DER, stored in a redacted secret.

```rust
use neotales_vaults_crypto::{Algorithm, generate_key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = generate_key("signing-key", Algorithm::Ed25519)?;
    println!("Generated key {}", key.id);
    Ok(())
}
```

**Generate a self-signed TLS server identity.** Supply a common name, subject
alternative names, explicit Unix validity timestamps, and algorithm in
`CertificateRequest`. Store its certificate and key using a vault client.
Self-signed certificates are not automatically trusted.

**Convert PEM and DER.** Certificate conversion checks X.509 structure but not
trust or validity. Private-key conversion checks DER framing, not key semantics.

## Licence

[MIT](LICENSE.md)
