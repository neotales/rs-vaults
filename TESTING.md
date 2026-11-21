# Testing

Run the portable workspace checks with:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

The integration tests below are ignored by default. They use disposable data
and do not need cloud credentials. Container tests require Docker and use
images pinned by digest in their test source. The cloud emulator and Infisical
tests require cached images; the Bitwarden/Vaultwarden testcontainers tests may
pull missing images. Container ports are published to loopback only.

```sh
cargo test -p neotales-vaults-vault --test openbao -- --ignored
cargo test -p neotales-vaults-infisical --test live -- --ignored
cargo test -p neotales-vaults-aws --test floci -- --ignored
cargo test -p neotales-vaults-azure --test floci -- --ignored
cargo test -p neotales-vaults-gcp --test floci -- --ignored
```

The Bitwarden and Vaultwarden container tests additionally require a pinned
Bitwarden CLI. Setup and invocation are documented in
[`vaultwarden/README.md`](vaultwarden/README.md#container-integration-tests).

On Linux, the following tests use a private D-Bus session, temporary home and
temporary Secret Service. They require `dbus-run-session`, `dbus-send`, and
`gnome-keyring-daemon`; they do not use the desktop keyring.

```sh
cargo test -p neotales-vaults-os --test linux_secret_service isolated_secret_service_round_trip -- --ignored --exact
cargo test -p neotales-vaults-keepass --test discovery isolated_credential_discovery -- --ignored --exact
```

Floci provides emulator coverage, not proof of interoperability with live
cloud accounts. The Bitwarden and Vaultwarden tests use disposable self-hosted
servers, not the Bitwarden cloud service. macOS Keychain and Windows Credential Manager
have not been exercised by the isolated Linux tests.
