use base64::{Engine, engine::general_purpose::STANDARD};
use neotales_vaults_core::{
    Capability, Client, Driver, Error, ErrorKind, GetOptions, Metadata, Response, SecretValue,
};
use neotales_vaults_local_crypto::{Config, LocalCrypto};

struct KeyProvider {
    reported_version: &'static str,
}

#[test]
fn generated_keys_are_suitable_and_redacted() {
    let first = neotales_vaults_local_crypto::generate_key().unwrap();
    let second = neotales_vaults_local_crypto::generate_key().unwrap();
    assert_eq!(STANDARD.decode(first.expose()).unwrap().len(), 32);
    assert_ne!(first.expose(), second.expose());
    assert!(!format!("{first:?}").contains(std::str::from_utf8(first.expose()).unwrap()));
}
impl Driver for KeyProvider {
    fn supports(&self, capability: Capability) -> bool {
        capability == Capability::GetSecret
    }
    fn get_secret(
        &self,
        _: &str,
        _: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>, Error> {
        assert!(options.version.is_some());
        Ok(Response {
            value: SecretValue::new(STANDARD.encode([42u8; 32]).into_bytes()),
            metadata: Metadata {
                version: Some(self.reported_version.into()),
                ..Default::default()
            },
        })
    }
}
fn cipher(vault: &str, version: &str, reported: &'static str) -> LocalCrypto {
    LocalCrypto::new(
        Client::new(KeyProvider {
            reported_version: reported,
        }),
        Config {
            vault: vault.into(),
            key_name: "key".into(),
            key_version: version.into(),
        },
    )
    .unwrap()
}
#[test]
fn values_are_authenticated_and_bound_to_context_and_reference() {
    let c = cipher("vault", "v1", "v1");
    let value = SecretValue::new(b"private-value".to_vec());
    let a = c.encrypt(&value, b"record-a").unwrap();
    let b = c.encrypt(&value, b"record-a").unwrap();
    assert_ne!(a, b);
    assert!(!String::from_utf8_lossy(&a).contains("private-value"));
    assert_eq!(
        c.decrypt(&a, b"record-a").unwrap().expose(),
        b"private-value"
    );
    assert!(c.decrypt(&a, b"record-b").is_err());
    assert!(
        cipher("other", "v1", "v1")
            .decrypt(&a, b"record-a")
            .is_err()
    );
    assert!(
        cipher("vault", "v2", "v2")
            .decrypt(&a, b"record-a")
            .is_err()
    );
    let mut json: serde_json::Value = serde_json::from_slice(&a).unwrap();
    let mut bytes = STANDARD
        .decode(json["ciphertext"].as_str().unwrap())
        .unwrap();
    bytes[0] ^= 1;
    json["ciphertext"] = STANDARD.encode(bytes).into();
    assert!(
        c.decrypt(&serde_json::to_vec(&json).unwrap(), b"record-a")
            .is_err()
    );
}

#[test]
fn refuses_provider_version_mismatch() {
    assert_eq!(
        cipher("vault", "v1", "v2")
            .encrypt(&SecretValue::new(b"value".to_vec()), b"")
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
}

#[test]
fn encrypted_json_file_never_overwrites_and_checks_context() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("secrets.json");
    let c = cipher("vault", "v1", "v1");
    let json = SecretValue::new(br#"{"password":"sensitive-value","nested":[1,true]}"#.to_vec());
    c.encrypt_json_file(&json, b"file-identity", &path).unwrap();
    let stored = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&stored).contains("sensitive-value"));
    assert_eq!(
        c.decrypt_json_file(&path, b"file-identity")
            .unwrap()
            .expose(),
        json.expose()
    );
    assert!(c.decrypt_json_file(&path, b"other").is_err());
    assert!(c.encrypt_json_file(&json, b"file-identity", &path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), stored);
    let invalid_path = temp.path().join("invalid.json");
    assert!(
        c.encrypt_json_file(&SecretValue::new(b"{broken".to_vec()), b"", &invalid_path)
            .is_err()
    );
    assert!(!invalid_path.exists());
    let mut envelope: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    envelope["nonce"] = "bad".into();
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(c.decrypt_json_file(&path, b"file-identity").is_err());
}
