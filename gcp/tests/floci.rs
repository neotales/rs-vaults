//! Opt-in disposable Floci GCP integration test.
use base64::{Engine, engine::general_purpose::STANDARD};
use neotales_vaults_core::{Client, EnsureSecret, GetOptions, RemoveOptions, SecretValue};
use neotales_vaults_gcp::{Config, GcpDriver};
use neotales_vaults_local_crypto::{Config as CryptoConfig, LocalCrypto};
use prost::Message;
use std::{
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const IMAGE: &str = "floci/floci-gcp:0.13.0@sha256:a59403d43d524b1a08282d67d541a6d37bf7868cbd9d1311caa0d2983adf6f46";
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
#[derive(Clone, PartialEq, Message)]
struct CreateRequest {
    #[prost(string, tag = "1")]
    parent: String,
    #[prost(string, tag = "2")]
    secret_id: String,
    #[prost(message, optional, tag = "3")]
    secret: Option<Secret>,
}
#[derive(Clone, PartialEq, Message)]
struct Secret {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    replication: Option<Replication>,
}
#[derive(Clone, PartialEq, Message)]
struct Replication {
    #[prost(message, optional, tag = "1")]
    automatic: Option<Automatic>,
}
#[derive(Clone, PartialEq, Message)]
struct Automatic {}
#[test]
#[ignore = "requires Docker and the locally cached pinned Floci GCP image"]
fn provisioned_secret_versions_round_trip() {
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-d",
            "--pull=never",
            "--publish",
            "127.0.0.1::4588",
            IMAGE,
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "failed to start Floci GCP");
    let c = Container(String::from_utf8(output.stdout).unwrap().trim().to_owned());
    let output = Command::new("docker")
        .args(["port", &c.0, "4588/tcp"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let binding = String::from_utf8(output.stdout).unwrap();
    let port = binding.trim().strip_prefix("127.0.0.1:").unwrap();
    let endpoint = format!("http://127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(60);
    let http = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .new_agent();
    while http.get(&endpoint).call().is_err() {
        assert!(Instant::now() < deadline, "Floci GCP not ready");
        thread::sleep(Duration::from_millis(100));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let channel = tonic::transport::Endpoint::from_shared(endpoint.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready().await.unwrap();
        let request = CreateRequest {
            parent: "projects/test-project".into(),
            secret_id: "example".into(),
            secret: Some(Secret {
                name: String::new(),
                replication: Some(Replication {
                    automatic: Some(Automatic {}),
                }),
            }),
        };
        let _: tonic::Response<Secret> = grpc
            .unary(
                tonic::Request::new(request),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/google.cloud.secretmanager.v1.SecretManagerService/CreateSecret",
                ),
                tonic::codec::ProstCodec::default(),
            )
            .await
            .unwrap();
    });
    let client = Client::new(
        GcpDriver::new(Config {
            vault: "gcp".into(),
            project: "test-project".into(),
            endpoint,
            token: SecretValue::new(b"fixture".to_vec()),
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    let created = client
        .ensure_value("gcp", "ensured", &SecretValue::new(b"created".to_vec()))
        .unwrap();
    assert_eq!(created.value.expose(), b"created");
    let existing = client
        .ensure_value("gcp", "ensured", &SecretValue::new(b"ignored".to_vec()))
        .unwrap();
    assert_eq!(existing.value.expose(), b"created");
    let first = client
        .set_secret("gcp", "example", &SecretValue::new(b"first".to_vec()))
        .unwrap()
        .version
        .unwrap();
    assert_eq!(
        client.get("gcp", "example").unwrap().value.expose(),
        b"first"
    );
    client
        .set_secret("gcp", "example", &SecretValue::new(b"second".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("gcp", "example").unwrap().value.expose(),
        b"second"
    );
    assert_eq!(
        client
            .get_with(
                "gcp",
                "example",
                &GetOptions {
                    version: Some(first.clone()),
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
            "gcp",
            "example",
            &SecretValue::new(STANDARD.encode([42u8; 32]).into_bytes()),
        )
        .unwrap()
        .version
        .unwrap();
    let crypto = LocalCrypto::new(
        client.clone(),
        CryptoConfig {
            vault: "gcp".into(),
            key_name: "example".into(),
            key_version: version.clone(),
        },
    )
    .unwrap();
    let value = SecretValue::new(br#"{"secret":"local-value"}"#.to_vec());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encrypted.json");
    crypto.encrypt_json_file(&value, b"fixture", &path).unwrap();
    assert_eq!(
        crypto
            .decrypt_json_file(&path, b"fixture")
            .unwrap()
            .expose(),
        value.expose()
    );
    let crypto = LocalCrypto::new(
        client.clone(),
        CryptoConfig {
            vault: "gcp".into(),
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
            "gcp",
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
            vault: "gcp".into(),
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
            .list_secrets("gcp")
            .unwrap()
            .contains(&"example".to_owned())
    );
    client
        .remove_secret(
            "gcp",
            "example",
            &RemoveOptions {
                version: Some(first.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        client
            .get_with(
                "gcp",
                "example",
                &GetOptions {
                    version: Some(first.clone()),
                    retry: None
                }
            )
            .is_err()
    );
    client
        .remove_secret(
            "gcp",
            "example",
            &RemoveOptions {
                version: Some(first),
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    client
        .remove_secret("gcp", "example", &RemoveOptions::default())
        .unwrap();
    assert!(client.get("gcp", "example").is_err());
    assert!(
        !client
            .list_secrets("gcp")
            .unwrap()
            .contains(&"example".to_owned())
    );
}
