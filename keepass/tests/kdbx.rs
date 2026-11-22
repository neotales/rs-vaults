use neotales_keepass::{
    Entry, Field, Group, KdbxFile, KdbxWriteOptions, KeePassDatabase, ProtectedValue,
};
use neotales_vaults_core::{
    Capability, Certificate, Client, EnsureSecret, ErrorKind, GetOptions, Key, RemoveOptions,
    SecretValue,
};
use neotales_vaults_keepass::{Config, KeepassDriver};

#[test]
fn remove_respects_recycle_bin_and_purge_records_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut db = KeePassDatabase::default();
    db.meta.recycle_bin_enabled = true;
    let mut entry = Entry::new("mail");
    entry.password = ProtectedValue::from_text("password");
    let id = entry.id;
    db.root.add_entry(entry);
    let mut data = Vec::new();
    KdbxFile::save_default(&db, &mut data, "db-pass").unwrap();
    std::fs::write(&path, data).unwrap();
    let client = Client::new(
        KeepassDriver::new(Config {
            vault: "local".into(),
            path: path.clone(),
            password: SecretValue::new(b"db-pass".to_vec()),
        })
        .unwrap()
        .with_write_options(KdbxWriteOptions::default()),
    );
    client
        .remove_secret("local", "mail", &RemoveOptions::default())
        .unwrap();
    assert_eq!(
        client.get("local", "mail").unwrap_err().kind,
        ErrorKind::NotFound
    );
    let recycled = KdbxFile::open(std::fs::File::open(&path).unwrap(), "db-pass").unwrap();
    let bin = recycled
        .root
        .groups
        .iter()
        .find(|group| group.id == recycled.meta.recycle_bin_uuid)
        .unwrap();
    assert_eq!(bin.entries[0].id, id);
    assert_eq!(bin.entries[0].previous_parent_group_id, recycled.root.id);
    client
        .remove_secret(
            "local",
            "mail",
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    let purged = KdbxFile::open(std::fs::File::open(&path).unwrap(), "db-pass").unwrap();
    assert!(
        purged
            .deleted_objects
            .iter()
            .any(|deleted| deleted.id == id)
    );
    assert!(
        purged
            .root
            .groups
            .iter()
            .find(|group| group.id == purged.meta.recycle_bin_uuid)
            .unwrap()
            .entries
            .is_empty()
    );
}

#[test]
fn reads_real_database_and_rejects_ambiguity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut db = KeePassDatabase::default();
    let mut entry = Entry::new("mail");
    entry.password = ProtectedValue::from_text("example-value");
    db.root.add_entry(entry);
    let mut data = Vec::new();
    KdbxFile::save_default(&db, &mut data, "database-password").unwrap();
    std::fs::write(&path, &data).unwrap();
    let client = Client::new(
        KeepassDriver::new(Config {
            vault: "local".into(),
            path: path.clone(),
            password: SecretValue::new(b"database-password".to_vec()),
        })
        .unwrap(),
    );
    assert!(client.supports(Capability::GetSecret));
    assert!(!client.supports(Capability::SetSecret));
    assert_eq!(
        client.get("local", "mail").unwrap().value.expose(),
        b"example-value"
    );
    assert_eq!(
        client.get("other", "mail").unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        client
            .get_with(
                "local",
                "mail",
                &GetOptions {
                    version: Some("1".into()),
                    retry: None
                }
            )
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    db.root.add_entry(Entry::new("mail"));
    let mut data = Vec::new();
    KdbxFile::save_default(&db, &mut data, "database-password").unwrap();
    std::fs::write(path, data).unwrap();
    assert_eq!(
        client.get("local", "mail").unwrap_err().kind,
        ErrorKind::Provider
    );
}

#[test]
fn opt_in_writes_preserve_other_fields_and_create_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut db = KeePassDatabase::default();
    let mut entry = Entry::new("existing");
    entry.username = "alice".into();
    entry.notes = "keep this".into();
    entry.set_field(Field::new("Notes", "keep this"));
    entry.password = ProtectedValue::from_text("old");
    db.root.add_entry(entry);
    let mut bytes = Vec::new();
    KdbxFile::save_default(&db, &mut bytes, "db-pass").unwrap();
    std::fs::write(&path, bytes).unwrap();
    let driver = KeepassDriver::new(Config {
        vault: "local".into(),
        path: path.clone(),
        password: SecretValue::new(b"db-pass".to_vec()),
    })
    .unwrap()
    .with_write_options(KdbxWriteOptions::default());
    let client = Client::new(driver);
    assert!(client.supports(Capability::SetSecret));
    assert_eq!(
        client
            .ensure_value("local", "ensured", &SecretValue::new(b"created".to_vec()))
            .unwrap()
            .value
            .expose(),
        b"created"
    );
    assert_eq!(
        client
            .ensure_value("local", "ensured", &SecretValue::new(b"ignored".to_vec()))
            .unwrap()
            .value
            .expose(),
        b"created"
    );
    client
        .set_secret("local", "existing", &SecretValue::new(b"new".to_vec()))
        .unwrap();
    client
        .set_secret(
            "local",
            "created",
            &SecretValue::new(b"created-value".to_vec()),
        )
        .unwrap();
    assert_eq!(
        client.get("local", "existing").unwrap().value.expose(),
        b"new"
    );
    assert_eq!(
        client.get("local", "created").unwrap().value.expose(),
        b"created-value"
    );
    let reopened = KdbxFile::open(std::fs::File::open(path).unwrap(), "db-pass").unwrap();
    let existing = reopened
        .root
        .entries
        .iter()
        .find(|entry| entry.title == "existing")
        .unwrap();
    assert_eq!(existing.username, "alice");
    assert_eq!(
        existing
            .field("Notes")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "keep this"
    );
}

#[test]
fn write_failures_do_not_replace_original_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut db = KeePassDatabase::default();
    db.root.add_entry(Entry::new("duplicate"));
    db.root.add_entry(Entry::new("duplicate"));
    let mut bytes = Vec::new();
    KdbxFile::save_default(&db, &mut bytes, "db-pass").unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let make = |password: &[u8]| {
        Client::new(
            KeepassDriver::new(Config {
                vault: "local".into(),
                path: path.clone(),
                password: SecretValue::new(password.to_vec()),
            })
            .unwrap()
            .with_write_options(KdbxWriteOptions::default()),
        )
    };
    assert_eq!(
        make(b"db-pass")
            .set_secret("local", "duplicate", &SecretValue::new(b"x".to_vec()))
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
    assert_eq!(
        make(b"wrong")
            .set_secret("local", "new", &SecretValue::new(b"x".to_vec()))
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
    assert_eq!(
        make(b"db-pass")
            .set_secret("local", "new", &SecretValue::new(vec![0xff]))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn certificate_and_key_round_trip_in_separate_marked_groups() {
    use neotales_vaults::{Registry, Resource};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut db = KeePassDatabase::default();
    let mut root_entry = Entry::new("same");
    root_entry.password = ProtectedValue::from_text("root-password");
    db.root.add_entry(root_entry);
    let mut bytes = Vec::new();
    KdbxFile::save_default(&db, &mut bytes, "db-pass").unwrap();
    std::fs::write(&path, bytes).unwrap();
    let client = Client::new(
        KeepassDriver::new(Config {
            vault: "local".into(),
            path,
            password: SecretValue::new(b"db-pass".to_vec()),
        })
        .unwrap()
        .with_write_options(KdbxWriteOptions::default()),
    );
    let cert = Certificate {
        data: b"cert-data".to_vec(),
        content_type: Some("application/pkix-cert".into()),
    };
    let key = Key {
        id: "key-id".into(),
        public_key: Some(b"public".to_vec()),
        private_key: Some(SecretValue::new(b"secret-key-material".to_vec())),
    };
    client.set_certificate("local", "same", &cert).unwrap();
    client.set_key("local", "same", &key).unwrap();
    assert_eq!(client.list_certificates("local").unwrap(), vec!["same"]);
    assert_eq!(client.list_keys("local").unwrap(), vec!["same"]);
    assert_eq!(
        client.get("local", "same").unwrap().value.expose(),
        b"root-password"
    );
    let mut registry = Registry::new();
    registry.register("local", client.clone()).unwrap();
    let Resource::Certificate(result) = registry.get_uri("nv://local/certs/same").unwrap() else {
        panic!("wrong resource")
    };
    assert_eq!(result.value, cert);
    let Resource::Key(result) = registry.get_uri("nv://local/keys/same").unwrap() else {
        panic!("wrong resource")
    };
    assert_eq!(result.value, key);
    assert!(!format!("{result:?}").contains("secret-key-material"));
    assert_eq!(
        client
            .get_key(
                "local",
                "same",
                &GetOptions {
                    version: Some("1".into()),
                    retry: None
                }
            )
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    client
        .remove_certificate("local", "same", &RemoveOptions::default())
        .unwrap();
    client
        .remove_key("local", "same", &RemoveOptions::default())
        .unwrap();
    assert!(client.list_certificates("local").unwrap().is_empty());
    assert!(client.list_keys("local").unwrap().is_empty());
    assert_eq!(
        client.get("local", "same").unwrap().value.expose(),
        b"root-password"
    );
}

#[test]
fn preexisting_unmarked_group_is_not_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut db = KeePassDatabase::default();
    db.root.add_group(Group::new("neotales-vaults-keys-v1"));
    let mut bytes = Vec::new();
    KdbxFile::save_default(&db, &mut bytes, "db-pass").unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let client = Client::new(
        KeepassDriver::new(Config {
            vault: "local".into(),
            path: path.clone(),
            password: SecretValue::new(b"db-pass".to_vec()),
        })
        .unwrap()
        .with_write_options(KdbxWriteOptions::default()),
    );
    let key = Key {
        id: "test".into(),
        public_key: None,
        private_key: None,
    };
    assert_eq!(
        client.set_key("local", "x", &key).unwrap_err().kind,
        ErrorKind::Provider
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
