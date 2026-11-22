use neotales_age::AgeKey;
use neotales_vaults::{Registry, Resource};
use neotales_vaults_age_sqlite::{AgeSqliteDriver, Config};
use neotales_vaults_core::{
    Certificate, Client, EnsureSecret, ErrorKind, GetOptions, Key, RemoveOptions, SecretMetadata,
    SecretValue, SetSecretOptions,
};
use std::sync::{Arc, Barrier};

fn client(path: &std::path::Path, key: &AgeKey) -> Client {
    Client::new(
        AgeSqliteDriver::new(Config {
            vault: "work".into(),
            path: path.into(),
            recipients: vec![key.public_key.clone()],
            identities: vec![SecretValue::new(key.private_key.as_bytes().to_vec())],
        })
        .unwrap(),
    )
}

#[test]
fn ensure_racing_writers_share_one_value_and_do_not_restore_deleted_entry() {
    let dir = tempfile::tempdir().unwrap();
    let c = client(
        &dir.path().join("vault.sqlite"),
        &AgeKey::generate().unwrap(),
    );
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = ["first", "second"]
        .into_iter()
        .map(|candidate| {
            let c = c.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                c.ensure_value(
                    "work",
                    "token",
                    &SecretValue::new(candidate.as_bytes().to_vec()),
                )
                .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results[0], results[1]);
    c.remove_secret("work", "token", &RemoveOptions::default())
        .unwrap();
    assert_eq!(
        c.ensure_value("work", "token", &SecretValue::new(b"replacement".to_vec()))
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
}

#[test]
fn removal_authenticates_and_preserves_older_versions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let key = AgeKey::generate().unwrap();
    let c = client(&path, &key);
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
    let wrong = client(&path, &AgeKey::generate().unwrap());
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
fn all_kinds_versions_and_registry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let key = AgeKey::generate().unwrap();
    let c = client(&path, &key);
    let first = c
        .set_secret("work", "token", &SecretValue::new(b"first secret".to_vec()))
        .unwrap()
        .version
        .unwrap();
    assert_eq!(c.list_secrets("work").unwrap(), vec!["token"]);
    assert!(c.list_certificates("work").unwrap().is_empty());
    assert!(c.list_keys("work").unwrap().is_empty());
    c.set_secret(
        "work",
        "token",
        &SecretValue::new(b"second secret".to_vec()),
    )
    .unwrap();
    assert_eq!(uuid::Uuid::parse_str(&first).unwrap().get_version_num(), 7);
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
        b"first secret"
    );
    assert_eq!(
        c.get("work", "token").unwrap().value.expose(),
        b"second secret"
    );
    let cert = Certificate {
        data: b"certificate-data".to_vec(),
        content_type: Some("application/pkix-cert".into()),
    };
    c.set_certificate("work", "tls", &cert).unwrap();
    let material = Key {
        id: "key-id".into(),
        public_key: Some(b"public".to_vec()),
        private_key: Some(SecretValue::new(b"private-key-data".to_vec())),
    };
    c.set_key("work", "tls", &material).unwrap();
    let mut registry = Registry::new();
    registry.register("work", c.clone()).unwrap();
    let Resource::Certificate(result) = registry.get_uri("nv://work/certs/tls").unwrap() else {
        panic!("wrong resource")
    };
    assert_eq!(result.value, cert);
    let Resource::Key(result) = registry.get_uri("nv://work/keys/tls").unwrap() else {
        panic!("wrong resource")
    };
    assert_eq!(result.value, material);
    assert!(!format!("{result:?}").contains("private-key-data"));
    let bytes = std::fs::read(&path).unwrap();
    for plaintext in [
        b"first secret".as_slice(),
        b"private-key-data".as_slice(),
        b"certificate-data".as_slice(),
    ] {
        assert!(!bytes.windows(plaintext.len()).any(|w| w == plaintext));
    }
    c.set_secret("work", "tls", &SecretValue::new(b"secret".to_vec()))
        .unwrap();
    c.remove_certificate("work", "tls", &RemoveOptions::default())
        .unwrap();
    c.remove_key(
        "work",
        "tls",
        &RemoveOptions {
            purge: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        c.get_certificate("work", "tls", &GetOptions::default())
            .is_err()
    );
    assert!(c.get_key("work", "tls", &GetOptions::default()).is_err());
    assert_eq!(c.get("work", "tls").unwrap().value.expose(), b"secret");
}

#[test]
fn ciphertext_substitution_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let c = client(&path, &AgeKey::generate().unwrap());
    c.set_secret("work", "a", &SecretValue::new(b"one".to_vec()))
        .unwrap();
    c.set_secret("work", "b", &SecretValue::new(b"two".to_vec()))
        .unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE versions SET value=(SELECT value FROM versions WHERE name='a') WHERE name='b'",
        [],
    )
    .unwrap();
    assert_eq!(c.get("work", "b").unwrap_err().kind, ErrorKind::Provider);
}

#[test]
fn does_not_initialize_an_unrelated_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("other.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("CREATE TABLE other (v TEXT)", []).unwrap();
    drop(db);
    let before = std::fs::read(&path).unwrap();
    let c = client(&path, &AgeKey::generate().unwrap());
    assert!(
        c.set_secret("work", "a", &SecretValue::new(b"x".to_vec()))
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn concurrent_writes_keep_all_versions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let key = AgeKey::generate().unwrap();
    let c = client(&path, &key);
    let barrier = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let c = client(&path, &key);
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                c.set_secret("work", "same", &SecretValue::new(format!("value-{i}")))
                    .unwrap()
                    .version
                    .unwrap()
            })
        })
        .collect();
    for handle in handles {
        let version = handle.join().unwrap();
        c.get_with(
            "work",
            "same",
            &GetOptions {
                version: Some(version),
                retry: None,
            },
        )
        .unwrap();
    }
}

#[test]
fn incompatible_identity_does_not_create_a_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let recipient = AgeKey::generate().unwrap();
    let wrong_identity = AgeKey::generate().unwrap();
    let c = Client::new(
        AgeSqliteDriver::new(Config {
            vault: "work".into(),
            path: path.clone(),
            recipients: vec![recipient.public_key],
            identities: vec![SecretValue::new(
                wrong_identity.private_key.as_bytes().to_vec(),
            )],
        })
        .unwrap(),
    );
    assert_eq!(
        c.set_secret("work", "name", &SecretValue::new(b"x".to_vec()))
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
    assert!(!path.exists());
}

#[test]
fn binding_rejects_cross_kind_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let c = client(&path, &AgeKey::generate().unwrap());
    let v = c
        .set_certificate(
            "work",
            "same",
            &Certificate {
                data: vec![1, 2],
                content_type: None,
            },
        )
        .unwrap()
        .version
        .unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("INSERT INTO versions(kind,name,version,value) SELECT 'key',name,version,value FROM versions WHERE kind='certificate'", []).unwrap();
    let options = GetOptions {
        version: Some(v),
        retry: None,
    };
    assert_eq!(
        c.get_key("work", "same", &options).unwrap_err().kind,
        ErrorKind::Provider
    );
}

#[test]
fn metadata_round_trip_expiry_and_status() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let c = client(&path, &AgeKey::generate().unwrap());
    let mut metadata = SecretMetadata {
        expires_at: Some("2099-01-01T00:00:00Z".into()),
        ..SecretMetadata::default()
    };
    metadata.tags.insert("team".into(), "example".into());
    let written = c
        .set_secret_with(
            "work",
            "tagged",
            &SecretValue::new(b"value".to_vec()),
            &SetSecretOptions {
                metadata: metadata.clone(),
            },
        )
        .unwrap();
    assert_eq!(written.secret, Some(metadata.clone()));
    assert_eq!(
        c.get("work", "tagged").unwrap().metadata.secret,
        Some(metadata)
    );
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
        c.set_secret_with(
            "work",
            name,
            &SecretValue::new(b"value".to_vec()),
            &SetSecretOptions { metadata },
        )
        .unwrap();
        assert_eq!(c.get("work", name).unwrap_err().kind, ErrorKind::NotFound);
    }
    let invalid = SecretMetadata {
        expires_at: Some("not-a-time".into()),
        ..SecretMetadata::default()
    };
    assert_eq!(
        c.set_secret_with(
            "work",
            "bad",
            &SecretValue::new(b"x".to_vec()),
            &SetSecretOptions { metadata: invalid }
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidInput
    );
    let bytes = std::fs::read(path).unwrap();
    assert!(
        !bytes
            .windows(b"example".len())
            .any(|window| window == b"example")
    );
}

#[test]
fn reads_ciphertext_from_previous_format() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let key = AgeKey::generate().unwrap();
    let c = client(&path, &key);
    let version = c
        .set_secret("work", "old", &SecretValue::new(b"seed".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let mut plaintext = b"neotales-vaults-age-sqlite-v1\0".to_vec();
    for part in ["secret", "work", "old", &version] {
        plaintext.extend_from_slice(&(part.len() as u64).to_be_bytes());
        plaintext.extend_from_slice(part.as_bytes());
    }
    plaintext.extend_from_slice(b"legacy");
    let recipient = neotales_age::AgeRecipient::from_public_key(&key.public_key).unwrap();
    let ciphertext = neotales_age::AgeFile::encrypt(&plaintext, &[recipient]).unwrap();
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute(
        "UPDATE versions SET value=?1 WHERE name='old' AND version=?2",
        rusqlite::params![ciphertext, version],
    )
    .unwrap();
    let result = c.get("work", "old").unwrap();
    assert_eq!(result.value.expose(), b"legacy");
    assert_eq!(result.metadata.secret, Some(SecretMetadata::default()));
}

#[test]
fn changes_metadata_on_specific_version_and_preserves_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let c = client(&path, &AgeKey::generate().unwrap());
    let first = c
        .set_secret("work", "token", &SecretValue::new(b"first".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let second = c
        .set_secret("work", "token", &SecretValue::new(b"second".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let metadata = SecretMetadata {
        deleted: true,
        ..SecretMetadata::default()
    };
    c.update_secret_metadata("work", "token", &first, &metadata)
        .unwrap();
    let old = GetOptions {
        version: Some(first.clone()),
        retry: None,
    };
    assert_eq!(
        c.get_with("work", "token", &old).unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        c.get("work", "token").unwrap().metadata.version.as_deref(),
        Some(second.as_str())
    );
    c.update_secret_metadata("work", "token", &first, &SecretMetadata::default())
        .unwrap();
    assert_eq!(
        c.get_with("work", "token", &old).unwrap().value.expose(),
        b"first"
    );
}

#[test]
fn metadata_update_does_not_modify_tampered_or_missing_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let c = client(&path, &AgeKey::generate().unwrap());
    assert_eq!(
        c.update_secret_metadata("work", "token", "missing", &SecretMetadata::default())
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    assert!(!path.exists());
    let version = c
        .set_secret("work", "token", &SecretValue::new(b"secret".to_vec()))
        .unwrap()
        .version
        .unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE versions SET value=x'0001' WHERE version=?1",
        [&version],
    )
    .unwrap();
    assert_eq!(
        c.update_secret_metadata("work", "token", &version, &SecretMetadata::default())
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT value FROM versions WHERE version=?1",
            [&version],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bytes, [0, 1]);
}
