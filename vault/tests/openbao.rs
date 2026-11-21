//! Opt-in isolated OpenBao integration test.

use neotales_vaults_core::{Client, GetOptions, RemoveOptions, SecretValue};
use neotales_vaults_vault::{Config, VaultDriver};
use std::{
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const OPENBAO_IMAGE: &str =
    "openbao/openbao:2.3.1@sha256:41dc3e47da01575e1ffea70aa635180b57ff999264398313334c259a697bf7a2";
const VAULT_IMAGE: &str = "hashicorp/vault:1.21.4@sha256:4e33b126a59c0c333b76fb4e894722462659a6bec7c48c9ee8cea56fccfd2569";
const TOKEN: &str = "neotales-vaults-openbao-test-token";

struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["stop", "--time", "2", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
#[ignore = "requires Docker and the pinned OpenBao image; starts a disposable loopback-only container"]
fn openbao_kv2_round_trip_and_versions() {
    exercise(
        OPENBAO_IMAGE,
        "BAO_DEV_ROOT_TOKEN_ID=neotales-vaults-openbao-test-token",
    );
}

#[test]
#[ignore = "requires Docker and the pinned Vault image; starts a disposable loopback-only container"]
fn vault_kv2_round_trip_and_versions() {
    exercise(
        VAULT_IMAGE,
        "VAULT_DEV_ROOT_TOKEN_ID=neotales-vaults-openbao-test-token",
    );
}

fn exercise(image: &str, token_env: &str) {
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-d",
            "--pull=never",
            "--publish",
            "127.0.0.1::8200",
            "-e",
            token_env,
            image,
            "server",
            "-dev",
            "-dev-listen-address=0.0.0.0:8200",
        ])
        .output()
        .expect("run Docker");
    assert!(
        output.status.success(),
        "could not start disposable KV server container"
    );
    let id = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    assert!(!id.is_empty());
    let container = Container(id);
    let output = Command::new("docker")
        .args(["port", &container.0, "8200/tcp"])
        .output()
        .expect("inspect port");
    assert!(output.status.success());
    let endpoint = String::from_utf8(output.stdout).unwrap();
    let port = endpoint
        .trim()
        .strip_prefix("127.0.0.1:")
        .expect("loopback port");
    let address = format!("http://127.0.0.1:{port}");
    let health = format!("{address}/v1/sys/health");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if ureq::get(&health).call().is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "KV server failed to become ready"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let client = Client::new(
        VaultDriver::new(Config {
            vault: "bao".into(),
            address,
            mount: "secret".into(),
            token: SecretValue::new(TOKEN.as_bytes().to_vec()),
            namespace: None,
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    client
        .set_secret("bao", "example", &SecretValue::new(b"first".to_vec()))
        .unwrap();
    client
        .set_secret("bao", "nested/path", &SecretValue::new(b"nested".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("bao", "nested/path").unwrap().value.expose(),
        b"nested"
    );
    assert!(
        client
            .list_secrets("bao")
            .unwrap()
            .contains(&"nested/path".to_owned())
    );
    let first = client.get("bao", "example").unwrap();
    assert_eq!(first.value.expose(), b"first");
    let version = first.metadata.version.unwrap();
    client
        .set_secret("bao", "example", &SecretValue::new(b"second".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("bao", "example").unwrap().value.expose(),
        b"second"
    );
    assert_eq!(
        client
            .get_with(
                "bao",
                "example",
                &GetOptions {
                    version: Some(version.clone()),
                    retry: None
                }
            )
            .unwrap()
            .value
            .expose(),
        b"first"
    );
    assert!(
        client
            .list_secrets("bao")
            .unwrap()
            .contains(&"example".to_owned())
    );
    client
        .remove_secret(
            "bao",
            "example",
            &RemoveOptions {
                version: Some(version.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        client
            .get_with(
                "bao",
                "example",
                &GetOptions {
                    version: Some(version.clone()),
                    retry: None
                }
            )
            .is_err()
    );
    client
        .remove_secret(
            "bao",
            "example",
            &RemoveOptions {
                version: Some(version),
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    client
        .remove_secret(
            "bao",
            "example",
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        !client
            .list_secrets("bao")
            .unwrap()
            .contains(&"example".to_owned())
    );
    client
        .remove_secret(
            "bao",
            "nested/path",
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
}
