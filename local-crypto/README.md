# neotales-vaults-local-crypto

Encrypts local values with a versioned vault-backed key.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-local-crypto
```

## What you can do 🔐

**Use the provider.**

```rust
use neotales_vaults_local_crypto::generate_key;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = generate_key()?;
    println!("Generated {} encoded bytes for storage in a secret manager", key.expose().len());
    Ok(())
}
```

Encrypt individual local values with AES-256-GCM using an explicitly versioned
secret obtained from a `neotales-vaults-core` client, including a compatible
cloud secret-manager driver. The secret must contain a base64-encoded 32-byte
key. Provision and rotate that key separately; this crate never creates or
overwrites it. Preserve older key versions to decrypt older values.
Use `generate_key` to generate a suitably encoded random key, then store it
with the chosen cloud driver's `set_secret` operation and retain the returned
version. AWS and GCP require the secret to be provisioned first.

The ciphertext is a JSON envelope bound to the configured vault, secret name,
key version and caller-provided context. The context must be reproduced exactly
at decryption. The context and key reference are authenticated but are not
contained in the envelope; callers must supply them again.

`encrypt_json_file` validates and encrypts an entire JSON document, creating a
new encrypted file without replacing an existing file. `decrypt_json_file`
returns the validated plaintext in memory without writing a plaintext file.
This is not a versioned JSON vault driver: it does not provide individual
secret, certificate or key entries, and cannot detect rollback of an older file.

The crate is intended for publication; it has not been published.

## Licence

[MIT](LICENSE.md)
