# neotales-vaults-vaultwarden

Reads and updates Vaultwarden and self-hosted Bitwarden login passwords through an unlocked Bitwarden CLI session.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-vaults)

<!-- badges: crates.io, docs.rs, CI. Add after the first release. -->

## Install

After the first release:

```sh
cargo add neotales-vaults-vaultwarden neotales-vaults-core
```

## What you can do 🔐

**List and remove login passwords.** Listing returns login item UUIDs, not
display names or password values, from the CLI's local cache. With a write
lock configured, removal syncs first and sends an item to the trash; `purge`
requests permanent deletion of an active or trashed login. Versions are not
supported. External clients can race the sync and deletion.

**Read a login password.** Configure the `bw` executable, an unlocked session,
the expected HTTPS server, and the expected account UUID. A secret name must be
an item UUID. The driver checks the active CLI profile before every read.

```rust
use neotales_vaults_core::{Client, SecretValue};
use neotales_vaults_vaultwarden::{Config, VaultwardenDriver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let driver = VaultwardenDriver::new(Config {
        vault: "work".into(), command: "bw".into(),
        server: std::env::var("BW_SERVER")?,
        account_id: std::env::var("BW_ACCOUNT_ID")?,
        session: SecretValue::new(std::env::var("BW_SESSION")?.into_bytes()),
    })?;
    let secret = Client::new(driver).get("work", &std::env::var("BW_ITEM_ID")?)?;
    println!("Loaded {} bytes", secret.value.expose().len());
    Ok(())
}
```

The caller manages login, unlock, and sync. The CLI reads its local cache, which
may be stale. The session is passed in the child's environment. Versions and
non-login items are not supported.

**Opt in to updates.** `with_write_lock` enables updates of existing login
items. It syncs first, then sends the full modified item to the CLI over stdin.
Cooperating writers must use the same lock path. Other clients can still race;
the driver's lock cannot prevent lost external changes. Failed writes have an
unknown outcome and are not automatically retried.

## Container integration tests

The opt-in tests start disposable, digest-pinned Vaultwarden and Bitwarden Lite
servers through `testcontainers`. Bitwarden Lite also starts disposable
PostgreSQL and Mailpit containers. Tests create only synthetic accounts, use
temporary CLI state and a local HTTPS proxy, and bind published ports to
loopback. The Bitwarden Lite installation ID and key are dummy fixture values,
not real installation credentials. Never point these tests at a real server.

Install the pinned CLI in a disposable directory and run:

```sh
npm install --prefix /tmp/opencode/vaults-bw-test --no-save --no-package-lock @bitwarden/cli@2025.6.1
NEOTALES_TEST_BW=/tmp/opencode/vaults-bw-test/node_modules/.bin/bw \
  cargo test -p neotales-vaults-vaultwarden --test container -- --ignored --test-threads=1
```

The tests require Docker, Node.js, `openssl`, and Python 3. They verify reads
and updates of existing login items and preservation of unrelated fields; they
do not verify other Bitwarden item types or concurrent external writers.

## Licence

[MIT](LICENSE.md)
