use neotales_age::AgeKey;
use neotales_vaults_age_json::{AgeJsonDriver, Config};
use neotales_vaults_core::{
    Certificate, Client, ErrorKind, GetOptions, Key, RemoveOptions, SecretMetadata, SecretValue,
    SetSecretOptions,
};
use std::sync::{Arc, Barrier};

fn driver(path: std::path::PathBuf, key: &AgeKey) -> AgeJsonDriver {
    AgeJsonDriver::new(Config {
        vault: "work".into(),
        path,
        recipients: vec![key.public_key.clone()],
        identities: vec![SecretValue::new(key.private_key.as_bytes().to_vec())],
    })
    .unwrap()
}

#[test]
fn removal_authenticates_and_preserves_older_versions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let key = AgeKey::generate().unwrap();
    let c = Client::new(driver(path.clone(), &key));
    let first = c
        .set_secret("work", "token", &SecretValue::new(b"first".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let latest = c
        .set_secret("work", "token", &SecretValue::new(b"latest".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let wrong = Client::new(driver(path, &AgeKey::generate().unwrap()));
    let purge = RemoveOptions {
        purge: true,
        ..Default::default()
    };
    assert!(wrong.remove_secret("work", "token", &purge).is_err());
    assert_eq!(c.get("work", "token").unwrap().value.expose(), b"latest");
    c.remove_secret("work", "token", &RemoveOptions::default())
        .unwrap();
    assert_eq!(
        c.get("work", "token").unwrap_err().kind,
        ErrorKind::NotFound
    );
    c.remove_secret(
        "work",
        "token",
        &RemoveOptions {
            purge: true,
            version: Some(latest),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        c.get("work", "token").unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        c.get_with(
            "work",
            "token",
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
    c.remove_secret("work", "token", &purge).unwrap();
    assert!(c.list_secrets("work").unwrap().is_empty());
}

#[test]
fn versions_encryption_and_context_binding() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let key = AgeKey::generate().unwrap();
    let client = Client::new(driver(path.clone(), &key));
    let first = client
        .set_secret(
            "work",
            "token",
            &SecretValue::new(b"sensitive-first".to_vec()),
        )
        .unwrap()
        .version
        .unwrap();
    let second = client
        .set_secret(
            "work",
            "token",
            &SecretValue::new(b"sensitive-second".to_vec()),
        )
        .unwrap()
        .version
        .unwrap();
    assert_eq!(uuid::Uuid::parse_str(&first).unwrap().get_version_num(), 7);
    assert_ne!(first, second);
    assert_eq!(client.list_secrets("work").unwrap(), vec!["token"]);
    assert!(client.list_certificates("work").unwrap().is_empty());
    assert!(client.list_keys("work").unwrap().is_empty());
    assert_eq!(
        client.list_secrets("other").unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        client.get("work", "token").unwrap().value.expose(),
        b"sensitive-second"
    );
    assert_eq!(
        client
            .get_with(
                "work",
                "token",
                &GetOptions {
                    version: Some(first.clone()),
                    retry: None
                }
            )
            .unwrap()
            .value
            .expose(),
        b"sensitive-first"
    );
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(!contents.contains("sensitive-"));
    let mut json: serde_json::Value = serde_json::from_str(&contents).unwrap();
    json["secrets"]["token"]["versions"][&second]["value"] =
        json["secrets"]["token"]["versions"][&first]["value"].clone();
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(
        client.get("work", "token").unwrap_err().kind,
        ErrorKind::Provider
    );
}

#[test]
fn concurrent_writers_do_not_lose_versions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let key = AgeKey::generate().unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let client = Client::new(driver(path.clone(), &key));
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                client
                    .set_secret("work", "token", &SecretValue::new(format!("value-{i}")))
                    .unwrap()
                    .version
                    .unwrap()
            })
        })
        .collect();
    let versions: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let client = Client::new(driver(path, &key));
    for version in versions {
        client
            .get_with(
                "work",
                "token",
                &GetOptions {
                    version: Some(version),
                    retry: None,
                },
            )
            .unwrap();
    }
}

#[test]
fn wrong_identity_cannot_write_unreadable_data() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let recipient = AgeKey::generate().unwrap();
    let identity = AgeKey::generate().unwrap();
    let client = Client::new(
        AgeJsonDriver::new(Config {
            vault: "work".into(),
            path: path.clone(),
            recipients: vec![recipient.public_key],
            identities: vec![SecretValue::new(identity.private_key.as_bytes().to_vec())],
        })
        .unwrap(),
    );
    assert_eq!(
        client
            .set_secret("work", "x", &SecretValue::new(b"secret".to_vec()))
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
    assert!(!path.exists());
}

#[test]
fn certificate_and_private_key_versions_resolve_through_registry() {
    use neotales_vaults::{Registry, Resource};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let key = AgeKey::generate().unwrap();
    let client = Client::new(driver(path.clone(), &key));
    let mut registry = Registry::new();
    registry.register("work", client.clone()).unwrap();
    let cert = Certificate {
        data: b"cert-v1".to_vec(),
        content_type: Some("application/pkix-cert".into()),
    };
    let first = client
        .set_certificate("work", "tls", &cert)
        .unwrap()
        .version
        .unwrap();
    let second_cert = Certificate {
        data: b"cert-v2".to_vec(),
        content_type: None,
    };
    client.set_certificate("work", "tls", &second_cert).unwrap();
    let key_data = Key {
        id: "signing-key".into(),
        public_key: Some(b"public".to_vec()),
        private_key: Some(SecretValue::new(b"very-private-key".to_vec())),
    };
    let key_version = client
        .set_key("work", "tls", &key_data)
        .unwrap()
        .version
        .unwrap();
    let Resource::Certificate(old) = registry
        .get_uri(&format!("nv://work/certs/tls/{first}"))
        .unwrap()
    else {
        panic!("wrong resource")
    };
    assert_eq!(old.value, cert);
    let Resource::Certificate(latest) = registry.get_uri("nv://work/certs/tls").unwrap() else {
        panic!("wrong resource")
    };
    assert_eq!(latest.value, second_cert);
    let Resource::Key(result) = registry
        .get_uri(&format!("nv://work/keys/tls/{key_version}"))
        .unwrap()
    else {
        panic!("wrong resource")
    };
    assert_eq!(result.value, key_data);
    assert!(!format!("{result:?}").contains("very-private-key"));
    let contents = std::fs::read_to_string(path).unwrap();
    assert!(!contents.contains("very-private-key"));
    assert!(!contents.contains("cert-v1"));
    client
        .set_secret("work", "tls", &SecretValue::new(b"secret".to_vec()))
        .unwrap();
    client
        .remove_certificate("work", "tls", &RemoveOptions::default())
        .unwrap();
    client
        .remove_key(
            "work",
            "tls",
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        client
            .get_certificate("work", "tls", &GetOptions::default())
            .is_err()
    );
    assert!(
        client
            .get_key("work", "tls", &GetOptions::default())
            .is_err()
    );
    assert_eq!(client.get("work", "tls").unwrap().value.expose(), b"secret");
}

#[test]
fn ciphertext_cannot_move_between_resource_kinds() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let client = Client::new(driver(path.clone(), &AgeKey::generate().unwrap()));
    let cert = Certificate {
        data: b"cert".to_vec(),
        content_type: None,
    };
    let version = client
        .set_certificate("work", "same", &cert)
        .unwrap()
        .version
        .unwrap();
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["keys"]["same"] = json["certs"]["same"].clone();
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    let options = GetOptions {
        version: Some(version),
        retry: None,
    };
    assert_eq!(
        client.get_key("work", "same", &options).unwrap_err().kind,
        ErrorKind::Provider
    );
}

#[test]
fn existing_secret_only_documents_remain_readable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault.json");
    let client = Client::new(driver(path.clone(), &AgeKey::generate().unwrap()));
    client
        .set_secret("work", "token", &SecretValue::new(b"old".to_vec()))
        .unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    document.as_object_mut().unwrap().remove("certs");
    document.as_object_mut().unwrap().remove("keys");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(client.get("work", "token").unwrap().value.expose(), b"old");
    client
        .set_certificate(
            "work",
            "cert",
            &Certificate {
                data: vec![1],
                content_type: None,
            },
        )
        .unwrap();
    assert_eq!(client.get("work", "token").unwrap().value.expose(), b"old");
}

#[test]
fn metadata_is_returned_and_cryptographically_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let client = Client::new(driver(path.clone(), &AgeKey::generate().unwrap()));
    let mut metadata = SecretMetadata {
        expires_at: Some("2099-01-01T00:00:00Z".into()),
        ..SecretMetadata::default()
    };
    metadata.tags.insert("team".into(), "payments".into());
    let options = SetSecretOptions {
        metadata: metadata.clone(),
    };
    let written = client
        .set_secret_with("work", "a", &SecretValue::new(b"value".to_vec()), &options)
        .unwrap();
    assert_eq!(written.secret.as_ref(), Some(&metadata));
    let read = client.get("work", "a").unwrap();
    assert_eq!(read.metadata.secret, Some(metadata));
    let version = written.version.unwrap();
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["secrets"]["a"]["versions"][&version]["tags"]["team"] = "other".into();
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(
        client.get("work", "a").unwrap_err().kind,
        ErrorKind::Provider
    );
}

#[test]
fn expiry_and_inactive_states_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let client = Client::new(driver(path.clone(), &AgeKey::generate().unwrap()));
    for (name, metadata) in [
        (
            "expired",
            SecretMetadata {
                expires_at: Some("2000-01-01T00:00:00Z".into()),
                ..SecretMetadata::default()
            },
        ),
        (
            "disabled",
            SecretMetadata {
                enabled: false,
                ..SecretMetadata::default()
            },
        ),
        (
            "deleted",
            SecretMetadata {
                deleted: true,
                ..SecretMetadata::default()
            },
        ),
    ] {
        client
            .set_secret_with(
                "work",
                name,
                &SecretValue::new(b"value".to_vec()),
                &SetSecretOptions { metadata },
            )
            .unwrap();
        assert_eq!(
            client.get("work", name).unwrap_err().kind,
            ErrorKind::NotFound
        );
    }
    let bad = SetSecretOptions {
        metadata: SecretMetadata {
            expires_at: Some("not-a-date".into()),
            ..SecretMetadata::default()
        },
    };
    assert_eq!(
        client
            .set_secret_with("work", "bad", &SecretValue::new(b"x".to_vec()), &bad)
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let version = json["secrets"]["disabled"]["latest"]
        .as_str()
        .unwrap()
        .to_owned();
    json["secrets"]["disabled"]["versions"][&version]["enabled"] = true.into();
    std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(
        client.get("work", "disabled").unwrap_err().kind,
        ErrorKind::Provider
    );
}

#[test]
fn reads_v1_ciphertext_after_metadata_format_upgrade() {
    use base64::Engine;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let key = AgeKey::generate().unwrap();
    let version = uuid::Uuid::now_v7().to_string();
    let mut plaintext = b"neotales-vaults-age-json-secret-v1\0".to_vec();
    for part in ["work", "old", &version] {
        plaintext.extend_from_slice(&(part.len() as u64).to_be_bytes());
        plaintext.extend_from_slice(part.as_bytes());
    }
    plaintext.extend_from_slice(b"old-secret");
    let recipient = neotales_age::AgeRecipient::from_public_key(&key.public_key).unwrap();
    let encrypted = neotales_age::AgeFile::encrypt(&plaintext, &[recipient]).unwrap();
    let value = base64::engine::general_purpose::STANDARD.encode(encrypted);
    let doc = serde_json::json!({ "secrets": { "old": { "latest": version, "versions": { &version: {
        "expiresAt": null, "tags": {}, "value": value, "enabled": true, "deleted": false
    } } } } });
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
    let client = Client::new(driver(path, &key));
    assert_eq!(
        client.get("work", "old").unwrap().value.expose(),
        b"old-secret"
    );
}

#[test]
fn updates_existing_version_without_changing_latest_or_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let client = Client::new(driver(path, &AgeKey::generate().unwrap()));
    let first = client
        .set_secret("work", "token", &SecretValue::new(b"one".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let second = client
        .set_secret("work", "token", &SecretValue::new(b"two".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let disabled = SecretMetadata {
        enabled: false,
        ..SecretMetadata::default()
    };
    let updated = client
        .update_secret_metadata("work", "token", &first, &disabled)
        .unwrap();
    assert_eq!(updated.version.as_deref(), Some(first.as_str()));
    let old = GetOptions {
        version: Some(first.clone()),
        retry: None,
    };
    assert_eq!(
        client.get_with("work", "token", &old).unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        client
            .get("work", "token")
            .unwrap()
            .metadata
            .version
            .as_deref(),
        Some(second.as_str())
    );
    let mut restored = SecretMetadata::default();
    restored.tags.insert("owner".into(), "team".into());
    client
        .update_secret_metadata("work", "token", &first, &restored)
        .unwrap();
    let result = client.get_with("work", "token", &old).unwrap();
    assert_eq!(result.value.expose(), b"one");
    assert_eq!(result.metadata.secret, Some(restored));
}

#[test]
fn metadata_update_rejects_tampered_record_without_modifying_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let client = Client::new(driver(path.clone(), &AgeKey::generate().unwrap()));
    let version = client
        .set_secret("work", "token", &SecretValue::new(b"one".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["secrets"]["token"]["versions"][&version]["deleted"] = true.into();
    let tampered = serde_json::to_vec(&json).unwrap();
    std::fs::write(&path, &tampered).unwrap();
    assert_eq!(
        client
            .update_secret_metadata("work", "token", &version, &SecretMetadata::default())
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
    assert_eq!(std::fs::read(path).unwrap(), tampered);
}
