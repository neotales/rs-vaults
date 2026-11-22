//! Opt-in disposable Floci AWS integration test.
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_secretsmanager::{
    config::{BehaviorVersion, Region},
    primitives::Blob,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use neotales_vaults_aws::{AwsDriver, Config};
use neotales_vaults_core::{Client, EnsureSecret, GetOptions, SecretValue};
use neotales_vaults_local_crypto::{Config as CryptoConfig, LocalCrypto};
use std::{
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const IMAGE: &str =
    "floci/floci:2.5.0@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19";
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
#[ignore = "requires Docker and the locally cached pinned Floci AWS image"]
fn provisioned_secret_versions_round_trip() {
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-d",
            "--pull=never",
            "--publish",
            "127.0.0.1::4566",
            IMAGE,
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "failed to start Floci AWS");
    let container = Container(String::from_utf8(output.stdout).unwrap().trim().to_owned());
    let output = Command::new("docker")
        .args(["port", &container.0, "4566/tcp"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let binding = String::from_utf8(output.stdout).unwrap();
    let port = binding.trim().strip_prefix("127.0.0.1:").unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let health = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .new_agent();
    while health
        .get(format!("http://127.0.0.1:{port}/"))
        .call()
        .is_err()
    {
        assert!(Instant::now() < deadline, "Floci AWS not ready");
        thread::sleep(Duration::from_millis(100));
    }
    let sdk = aws_types::SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(format!("http://127.0.0.1:{port}"))
        .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
            "test", "test", None, None, "fixture",
        )))
        .build();
    let service = aws_sdk_secretsmanager::Client::new(&sdk);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let first = rt.block_on(async {
        service
            .create_secret()
            .name("example")
            .secret_binary(Blob::new(b"first".to_vec()))
            .send()
            .await
            .unwrap()
            .version_id()
            .unwrap()
            .to_owned()
    });
    let client = Client::new(
        AwsDriver::new(Config {
            vault: "aws".into(),
            sdk,
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    let result = client
        .ensure_value("aws", "ensured", &SecretValue::new(b"created".to_vec()))
        .unwrap();
    assert_eq!(result.value.expose(), b"created");
    let result = client
        .ensure_value("aws", "ensured", &SecretValue::new(b"ignored".to_vec()))
        .unwrap();
    assert_eq!(result.value.expose(), b"created");
    assert_eq!(
        client.get("aws", "example").unwrap().value.expose(),
        b"first"
    );
    client
        .set_secret("aws", "example", &SecretValue::new(b"second".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("aws", "example").unwrap().value.expose(),
        b"second"
    );
    assert_eq!(
        client
            .get_with(
                "aws",
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
    let version = client
        .set_secret(
            "aws",
            "example",
            &SecretValue::new(STANDARD.encode([42u8; 32]).into_bytes()),
        )
        .unwrap()
        .version
        .unwrap();
    let crypto = LocalCrypto::new(
        client.clone(),
        CryptoConfig {
            vault: "aws".into(),
            key_name: "example".into(),
            key_version: version.clone(),
        },
    )
    .unwrap();
    let ciphertext = crypto
        .encrypt(&SecretValue::new(b"local value".to_vec()), b"test-context")
        .unwrap();
    assert_eq!(
        crypto
            .decrypt(&ciphertext, b"test-context")
            .unwrap()
            .expose(),
        b"local value"
    );
    let dir = tempfile::tempdir().unwrap();
    let crypto = LocalCrypto::new(
        client.clone(),
        CryptoConfig {
            vault: "aws".into(),
            key_name: "example".into(),
            key_version: version,
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
        .set_secret("local", "test", &SecretValue::new(b"first".to_vec()))
        .unwrap()
        .version
        .unwrap();
    local
        .set_secret("local", "test", &SecretValue::new(b"second".to_vec()))
        .unwrap();
    let rotated = client
        .set_secret(
            "aws",
            "example",
            &neotales_vaults_local_crypto::generate_key().unwrap(),
        )
        .unwrap()
        .version
        .unwrap();
    assert_eq!(
        local
            .get_with(
                "local",
                "test",
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
    let wrong_crypto = LocalCrypto::new(
        client.clone(),
        CryptoConfig {
            vault: "aws".into(),
            key_name: "example".into(),
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
    assert!(wrong.get("local", "test").is_err());
    assert!(
        client
            .list_secrets("aws")
            .unwrap()
            .contains(&"example".to_owned())
    );
    client
        .remove_secret("aws", "example", &Default::default())
        .unwrap();
    assert!(client.get("aws", "example").is_err());
}
