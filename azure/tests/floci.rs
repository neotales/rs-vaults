//! Opt-in disposable Floci Azure integration test.
use neotales_vaults_azure::{AzureDriver, Config};
use neotales_vaults_core::{Certificate, Client, GetOptions, Key, SecretValue};
use neotales_vaults_local_crypto::{Config as CryptoConfig, LocalCrypto};
use std::{
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const IMAGE: &str =
    "floci/floci-az:0.17.0@sha256:40f1bbf1ef13569c6eacb47e565bf4cd28785ca833208dcc074910e13aec64ea";

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
#[ignore = "requires Docker and the locally cached pinned Floci Azure image"]
fn secret_versions_round_trip() {
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-d",
            "--pull=never",
            "--publish",
            "127.0.0.1::4577",
            IMAGE,
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "failed to start Floci Azure");
    let c = Container(String::from_utf8(output.stdout).unwrap().trim().to_owned());
    let output = Command::new("docker")
        .args(["port", &c.0, "4577/tcp"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let binding = String::from_utf8(output.stdout).unwrap();
    let port = binding.trim().strip_prefix("127.0.0.1:").unwrap();
    let address = format!("http://127.0.0.1:{port}/devstoreaccount1-keyvault");
    let deadline = Instant::now() + Duration::from_secs(60);
    let health = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .new_agent();
    while health
        .get(format!("{address}/secrets/probe?api-version=7.4"))
        .call()
        .is_err()
    {
        assert!(Instant::now() < deadline, "Floci Azure not ready");
        thread::sleep(Duration::from_millis(100));
    }
    let client = Client::new(
        AzureDriver::new(Config {
            vault: "azure".into(),
            address,
            token: SecretValue::new(b"disposable-token".to_vec()),
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    let first = client
        .set_secret("azure", "example", &SecretValue::new(b"first".to_vec()))
        .unwrap()
        .version
        .unwrap();
    assert_eq!(
        client.get("azure", "example").unwrap().value.expose(),
        b"first"
    );
    client
        .set_secret("azure", "example", &SecretValue::new(b"second".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("azure", "example").unwrap().value.expose(),
        b"second"
    );
    assert_eq!(
        client
            .get_with(
                "azure",
                "example",
                &GetOptions {
                    version: Some(first),
                    retry: None
                }
            )
            .unwrap()
            .value
            .expose(),
        b"first"
    );
    let key_version = client
        .set_secret(
            "azure",
            "encryption-key",
            &neotales_vaults_local_crypto::generate_key().unwrap(),
        )
        .unwrap()
        .version
        .unwrap();
    let crypto = LocalCrypto::new(
        client.clone(),
        CryptoConfig {
            vault: "azure".into(),
            key_name: "encryption-key".into(),
            key_version: key_version.clone(),
        },
    )
    .unwrap();
    let encrypted = crypto
        .encrypt(&SecretValue::new(b"local plaintext".to_vec()), b"record")
        .unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains("local plaintext"));
    assert_eq!(
        crypto.decrypt(&encrypted, b"record").unwrap().expose(),
        b"local plaintext"
    );
    assert!(crypto.decrypt(&encrypted, b"different record").is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encrypted.json");
    let json = SecretValue::new(br#"{"password":"private-json-value"}"#.to_vec());
    crypto
        .encrypt_json_file(&json, b"json-file", &path)
        .unwrap();
    assert!(
        !std::fs::read_to_string(&path)
            .unwrap()
            .contains("private-json-value")
    );
    assert_eq!(
        crypto
            .decrypt_json_file(&path, b"json-file")
            .unwrap()
            .expose(),
        json.expose()
    );
    let crypto = LocalCrypto::new(
        client.clone(),
        CryptoConfig {
            vault: "azure".into(),
            key_name: "encryption-key".into(),
            key_version,
        },
    )
    .unwrap();
    let local = Client::new(
        neotales_vaults_local_json::LocalJsonDriver::new(
            neotales_vaults_local_json::Config {
                vault: "local".into(),
                path: dir.path().join("vault.json"),
            },
            crypto,
        )
        .unwrap(),
    );
    let version = local
        .set_secret("local", "example", &SecretValue::new(b"first".to_vec()))
        .unwrap()
        .version
        .unwrap();
    local
        .set_secret("local", "example", &SecretValue::new(b"second".to_vec()))
        .unwrap();
    let certificate = Certificate {
        data: b"test-certificate".to_vec(),
        content_type: Some("application/pkix-cert".into()),
    };
    let key = Key {
        id: "test-key".into(),
        public_key: None,
        private_key: Some(SecretValue::new(b"private-test-key".to_vec())),
    };
    local
        .set_certificate("local", "example", &certificate)
        .unwrap();
    local.set_key("local", "example", &key).unwrap();
    let rotated = client
        .set_secret(
            "azure",
            "encryption-key",
            &neotales_vaults_local_crypto::generate_key().unwrap(),
        )
        .unwrap()
        .version
        .unwrap();
    assert_eq!(
        local
            .get_with(
                "local",
                "example",
                &GetOptions {
                    version: Some(version),
                    retry: None
                }
            )
            .unwrap()
            .value
            .expose(),
        b"first"
    );
    assert_eq!(
        local
            .get_certificate("local", "example", &GetOptions::default())
            .unwrap()
            .value,
        certificate
    );
    assert_eq!(
        local
            .get_key("local", "example", &GetOptions::default())
            .unwrap()
            .value,
        key
    );
    assert!(
        !std::fs::read_to_string(dir.path().join("vault.json"))
            .unwrap()
            .contains("private-test-key")
    );
    let wrong_crypto = LocalCrypto::new(
        client.clone(),
        CryptoConfig {
            vault: "azure".into(),
            key_name: "encryption-key".into(),
            key_version: rotated,
        },
    )
    .unwrap();
    let wrong = Client::new(
        neotales_vaults_local_json::LocalJsonDriver::new(
            neotales_vaults_local_json::Config {
                vault: "local".into(),
                path: dir.path().join("vault.json"),
            },
            wrong_crypto,
        )
        .unwrap(),
    );
    assert!(wrong.get("local", "example").is_err());
    assert!(
        client
            .list_secrets("azure")
            .unwrap()
            .contains(&"encryption-key".to_owned())
    );
    client
        .remove_secret("azure", "encryption-key", &Default::default())
        .unwrap();
    assert!(client.get("azure", "encryption-key").is_err());
    client
        .remove_secret(
            "azure",
            "encryption-key",
            &neotales_vaults_core::RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
}
