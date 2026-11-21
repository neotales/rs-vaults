use base64::{Engine, engine::general_purpose::STANDARD};
use neotales_vaults_core::{
    Capability, Certificate, Client, Driver, Error, ErrorKind, GetOptions, Key, Metadata,
    RemoveOptions, Response, SecretMetadata, SecretValue, SetSecretOptions,
};
use neotales_vaults_local_crypto::{Config as CryptoConfig, LocalCrypto};
use neotales_vaults_local_json::{Config, LocalJsonDriver};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};

struct Keys;

#[test]
fn removal_soft_deletes_or_purges_without_resurrecting_old_versions() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path().join("vault.json"), "local");
    let first = client
        .set_secret("local", "name", &SecretValue::new(b"first".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let latest = client
        .set_secret("local", "name", &SecretValue::new(b"latest".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let selected = |version: &str| GetOptions {
        version: Some(version.to_owned()),
        retry: None,
    };
    client
        .remove_secret("local", "name", &RemoveOptions::default())
        .unwrap();
    assert_eq!(
        client.get("local", "name").unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        client
            .get_with("local", "name", &selected(&first))
            .unwrap()
            .value
            .expose(),
        b"first"
    );
    client
        .remove_secret(
            "local",
            "name",
            &RemoveOptions {
                purge: true,
                version: Some(latest),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        client.get("local", "name").unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        client
            .get_with("local", "name", &selected(&first))
            .unwrap()
            .value
            .expose(),
        b"first"
    );
    client
        .remove_secret(
            "local",
            "name",
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(client.list_secrets("local").unwrap().is_empty());
}

#[test]
fn lists_only_names_by_resource_type() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path().join("vault.json"), "local");
    client
        .set_secret("local", "zeta", &SecretValue::new(b"private".to_vec()))
        .unwrap();
    client
        .set_secret("local", "alpha", &SecretValue::new(b"hidden".to_vec()))
        .unwrap();
    assert_eq!(client.list_secrets("local").unwrap(), vec!["alpha", "zeta"]);
    assert!(client.list_certificates("local").unwrap().is_empty());
    assert!(client.list_keys("local").unwrap().is_empty());
    assert_eq!(
        client.list_secrets("other").unwrap_err().kind,
        ErrorKind::NotFound
    );
}

#[test]
fn secret_metadata_is_versioned_and_can_be_reactivated() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path().join("vault.json"), "local");
    let metadata = SecretMetadata {
        tags: [("owner".into(), "team".into())].into(),
        ..Default::default()
    };
    let first = client
        .set_secret_with(
            "local",
            "name",
            &SecretValue::new(b"first".to_vec()),
            &SetSecretOptions {
                metadata: metadata.clone(),
            },
        )
        .unwrap()
        .version
        .unwrap();
    let selected = GetOptions {
        version: Some(first.clone()),
        retry: None,
    };
    assert_eq!(
        client
            .get_with("local", "name", &selected)
            .unwrap()
            .metadata
            .secret,
        Some(metadata.clone())
    );
    client
        .set_secret("local", "name", &SecretValue::new(b"second".to_vec()))
        .unwrap();
    let mut inactive = metadata.clone();
    inactive.enabled = false;
    client
        .update_secret_metadata("local", "name", &first, &inactive)
        .unwrap();
    assert_eq!(
        client
            .get_with("local", "name", &selected)
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    client
        .update_secret_metadata("local", "name", &first, &metadata)
        .unwrap();
    assert_eq!(
        client
            .get_with("local", "name", &selected)
            .unwrap()
            .value
            .expose(),
        b"first"
    );
    assert_eq!(
        client.get("local", "name").unwrap().value.expose(),
        b"second"
    );
    let expired = SecretMetadata {
        expires_at: Some("2000-01-01T00:00:00Z".into()),
        ..Default::default()
    };
    client
        .update_secret_metadata("local", "name", &first, &expired)
        .unwrap();
    assert_eq!(
        client
            .get_with("local", "name", &selected)
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
}
impl Driver for Keys {
    fn supports(&self, c: Capability) -> bool {
        c == Capability::GetSecret
    }
    fn get_secret(&self, _: &str, _: &str, o: &GetOptions) -> Result<Response<SecretValue>, Error> {
        assert_eq!(o.version.as_deref(), Some("key-v1"));
        Ok(Response {
            value: SecretValue::new(STANDARD.encode([42u8; 32]).into_bytes()),
            metadata: Metadata {
                version: Some("key-v1".into()),
                ..Metadata::default()
            },
        })
    }
}
fn client(path: PathBuf, vault: &str) -> Client {
    let crypto = LocalCrypto::new(
        Client::new(Keys),
        CryptoConfig {
            vault: "cloud".into(),
            key_name: "key".into(),
            key_version: "key-v1".into(),
        },
    )
    .unwrap();
    Client::new(
        LocalJsonDriver::new(
            Config {
                vault: vault.into(),
                path,
            },
            crypto,
        )
        .unwrap(),
    )
}

#[test]
fn versioned_values_remain_encrypted_and_bound_to_vault() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let c = client(path.clone(), "local");
    let first = c
        .set_secret(
            "local",
            "example",
            &SecretValue::new(b"private-first".to_vec()),
        )
        .unwrap()
        .version
        .unwrap();
    assert_eq!(uuid::Uuid::parse_str(&first).unwrap().get_version_num(), 7);
    let second = c
        .set_secret(
            "local",
            "example",
            &SecretValue::new(b"private-second".to_vec()),
        )
        .unwrap()
        .version
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        c.get("local", "example").unwrap().value.expose(),
        b"private-second"
    );
    assert_eq!(
        c.get_with(
            "local",
            "example",
            &GetOptions {
                version: Some(first),
                retry: None
            }
        )
        .unwrap()
        .value
        .expose(),
        b"private-first"
    );
    assert!(c.supports(Capability::GetKey));
    let contents = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&contents).contains("private-"));
    assert!(!String::from_utf8_lossy(&contents).contains("example"));
    assert!(
        client(path.clone(), "other")
            .get("other", "example")
            .is_err()
    );
    let mut json: serde_json::Value = serde_json::from_slice(&contents).unwrap();
    json["nonce"] = "bad".into();
    std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(c.get("local", "example").is_err());
}

#[test]
fn certificate_and_key_versions_use_separate_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let client = client(path.clone(), "local");
    let cert = Certificate {
        data: b"certificate".to_vec(),
        content_type: Some("application/pem-certificate-chain".into()),
    };
    let key = Key {
        id: "key-id".into(),
        public_key: Some(b"public".to_vec()),
        private_key: Some(SecretValue::new(b"private-key-value".to_vec())),
    };
    client
        .set_secret("local", "same", &SecretValue::new(b"secret".to_vec()))
        .unwrap();
    let cert_version = client
        .set_certificate("local", "same", &cert)
        .unwrap()
        .version
        .unwrap();
    let key_version = client
        .set_key("local", "same", &key)
        .unwrap()
        .version
        .unwrap();
    assert_eq!(
        client
            .get_certificate(
                "local",
                "same",
                &GetOptions {
                    version: Some(cert_version),
                    retry: None
                }
            )
            .unwrap()
            .value,
        cert
    );
    assert_eq!(
        client
            .get_key(
                "local",
                "same",
                &GetOptions {
                    version: Some(key_version),
                    retry: None
                }
            )
            .unwrap()
            .value,
        key
    );
    assert_eq!(
        client.get("local", "same").unwrap().value.expose(),
        b"secret"
    );
    assert!(
        !std::fs::read_to_string(path)
            .unwrap()
            .contains("private-key-value")
    );
    client
        .remove_certificate("local", "same", &RemoveOptions::default())
        .unwrap();
    client
        .remove_key(
            "local",
            "same",
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        client
            .get_certificate("local", "same", &GetOptions::default())
            .is_err()
    );
    assert!(
        client
            .get_key("local", "same", &GetOptions::default())
            .is_err()
    );
    assert_eq!(
        client.get("local", "same").unwrap().value.expose(),
        b"secret"
    );
}

#[test]
fn registry_resolves_cloud_key_backed_resources_by_uri() {
    use neotales_vaults::{Registry, Resource};
    let dir = tempfile::tempdir().unwrap();
    let local = client(dir.path().join("vault.json"), "local");
    let version = local
        .set_secret("local", "name", &SecretValue::new(b"first".to_vec()))
        .unwrap()
        .version
        .unwrap();
    local
        .set_secret("local", "name", &SecretValue::new(b"second".to_vec()))
        .unwrap();
    let cert = Certificate {
        data: b"certificate".to_vec(),
        content_type: None,
    };
    local.set_certificate("local", "name", &cert).unwrap();
    let key = Key {
        id: "key".into(),
        public_key: None,
        private_key: Some(SecretValue::new(b"private".to_vec())),
    };
    local.set_key("local", "name", &key).unwrap();
    let mut registry = Registry::new();
    registry.register("local", local).unwrap();
    match registry
        .get_uri(&format!("nv://local/secrets/name/{version}"))
        .unwrap()
    {
        Resource::Secret(result) => assert_eq!(result.value.expose(), b"first"),
        _ => panic!("expected secret"),
    }
    match registry.get_uri("nv://local/certs/name").unwrap() {
        Resource::Certificate(result) => assert_eq!(result.value, cert),
        _ => panic!("expected certificate"),
    }
    match registry.get_uri("nv://local/keys/name").unwrap() {
        Resource::Key(result) => assert_eq!(result.value, key),
        _ => panic!("expected key"),
    }
}

#[test]
fn secret_only_documents_remain_readable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.json");
    let crypto = LocalCrypto::new(
        Client::new(Keys),
        CryptoConfig {
            vault: "cloud".into(),
            key_name: "key".into(),
            key_version: "key-v1".into(),
        },
    )
    .unwrap();
    let old = SecretValue::new(
        br#"{"secrets":{"name":{"latest":"v1","versions":{"v1":"b2xk"}}}}"#.to_vec(),
    );
    std::fs::write(
        &path,
        crypto
            .encrypt(&old, b"neotales-vaults-local-json-v1\0local")
            .unwrap(),
    )
    .unwrap();
    let client = client(path, "local");
    assert_eq!(client.get("local", "name").unwrap().value.expose(), b"old");
    client
        .set_certificate(
            "local",
            "cert",
            &Certificate {
                data: b"x".to_vec(),
                content_type: None,
            },
        )
        .unwrap();
    assert_eq!(client.get("local", "name").unwrap().value.expose(), b"old");
}

#[test]
fn concurrent_writers_keep_every_version() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let barrier = Arc::new(Barrier::new(4));
    let mut workers = Vec::new();
    for i in 0..4 {
        let path = path.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let c = client(path, "local");
            barrier.wait();
            c.set_secret("local", "example", &SecretValue::new(format!("value-{i}")))
                .unwrap()
                .version
                .unwrap()
        }));
    }
    let c = client(path, "local");
    for (i, worker) in workers.into_iter().enumerate() {
        let version = worker.join().unwrap();
        assert_eq!(
            c.get_with(
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
            format!("value-{i}").as_bytes()
        );
    }
}
