//! Versioned encrypted JSON resources using a vault-backed encryption key.
#![forbid(unsafe_code)]

use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use neotales_vaults_core::{
    Capability, Certificate, Driver, Error, ErrorKind, GetOptions, Key, Metadata, RemoveOptions,
    Response, Result, SecretMetadata, SecretValue, SetSecretOptions,
};
use neotales_vaults_local_crypto::LocalCrypto;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_FILE: u64 = 6 * 1024 * 1024;
const MAX_VALUE: usize = 1024 * 1024;

/// Settings for a local encrypted JSON vault.
#[derive(Clone, Debug)]
pub struct Config {
    /// Registered name of this local vault.
    pub vault: String,
    /// Path to the encrypted vault file.
    pub path: PathBuf,
}

/// A local JSON vault encrypted with a separately configured vault-backed key.
pub struct LocalJsonDriver {
    config: Config,
    crypto: LocalCrypto,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    secrets: BTreeMap<String, Versions>,
    #[serde(default)]
    certs: BTreeMap<String, Versions>,
    #[serde(default)]
    keys: BTreeMap<String, Versions>,
}
#[derive(Clone, Copy)]
enum Kind {
    Secret,
    Certificate,
    Key,
}
impl Kind {
    fn map(self, doc: &Document) -> &BTreeMap<String, Versions> {
        match self {
            Self::Secret => &doc.secrets,
            Self::Certificate => &doc.certs,
            Self::Key => &doc.keys,
        }
    }
    fn map_mut(self, doc: &mut Document) -> &mut BTreeMap<String, Versions> {
        match self {
            Self::Secret => &mut doc.secrets,
            Self::Certificate => &mut doc.certs,
            Self::Key => &mut doc.keys,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCertificate {
    data: Vec<u8>,
    content_type: Option<String>,
}
#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
struct WireKey {
    id: String,
    public_key: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Versions {
    latest: String,
    versions: BTreeMap<String, Record>,
}
impl Drop for Versions {
    fn drop(&mut self) {
        for value in self.versions.values_mut() {
            match value {
                Record::Legacy(s) => s.zeroize(),
                Record::Current { value, .. } => value.zeroize(),
            }
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Record {
    Legacy(String),
    Current {
        value: String,
        metadata: StoredMetadata,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredMetadata {
    expires_at: Option<String>,
    tags: BTreeMap<String, String>,
    enabled: bool,
    deleted: bool,
}
impl From<&SecretMetadata> for StoredMetadata {
    fn from(value: &SecretMetadata) -> Self {
        Self {
            expires_at: value.expires_at.clone(),
            tags: value.tags.clone(),
            enabled: value.enabled,
            deleted: value.deleted,
        }
    }
}
impl From<&StoredMetadata> for SecretMetadata {
    fn from(value: &StoredMetadata) -> Self {
        Self {
            expires_at: value.expires_at.clone(),
            tags: value.tags.clone(),
            enabled: value.enabled,
            deleted: value.deleted,
        }
    }
}
fn validate_metadata(metadata: &SecretMetadata) -> Result<()> {
    if metadata.tags.len() > 128
        || metadata
            .tags
            .iter()
            .any(|(k, v)| k.is_empty() || k.len() > 256 || v.len() > 4096)
    {
        return Err(err(ErrorKind::InvalidInput, "invalid secret tags"));
    }
    if let Some(expires) = &metadata.expires_at {
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid secret expiration"))?;
    }
    Ok(())
}

fn err(kind: ErrorKind, message: &'static str) -> Error {
    Error::new(kind, message)
}
impl LocalJsonDriver {
    /// Configure a vault without creating or reading a file.
    pub fn new(config: Config, crypto: LocalCrypto) -> Result<Self> {
        if config.vault.is_empty()
            || config.vault.len() > 1024
            || config.path.as_os_str().is_empty()
        {
            return Err(err(
                ErrorKind::InvalidInput,
                "vault name and path are required",
            ));
        }
        Ok(Self { config, crypto })
    }
    fn validate(&self, vault: &str, name: &str) -> Result<()> {
        if vault != self.config.vault {
            return Err(err(ErrorKind::NotFound, "vault is not configured"));
        }
        if name.is_empty() || name.len() > 1024 {
            return Err(err(ErrorKind::InvalidInput, "invalid resource name"));
        }
        Ok(())
    }
    fn list_names(&self, vault: &str, kind: Kind) -> Result<Vec<String>> {
        if vault != self.config.vault {
            return Err(err(ErrorKind::NotFound, "vault is not configured"));
        }
        let doc = self.read(false)?;
        Ok(kind.map(&doc).keys().cloned().collect())
    }
    fn context(&self) -> Vec<u8> {
        let mut out = b"neotales-vaults-local-json-v1\0".to_vec();
        out.extend_from_slice(self.config.vault.as_bytes());
        out
    }
    fn lock(&self) -> Result<File> {
        let mut path = self.config.path.as_os_str().to_os_string();
        path.push(".lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|_| err(ErrorKind::Provider, "vault lock could not be opened"))?;
        file.lock_exclusive()
            .map_err(|_| err(ErrorKind::Provider, "vault lock could not be acquired"))?;
        Ok(file)
    }
    fn read(&self, allow_missing: bool) -> Result<Document> {
        let file = match File::open(&self.config.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && allow_missing => {
                return Ok(Document::default());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(err(ErrorKind::NotFound, "vault file not found"));
            }
            Err(_) => return Err(err(ErrorKind::Provider, "vault file could not be opened")),
        };
        let mut bytes = Vec::new();
        file.take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| err(ErrorKind::Provider, "vault file could not be read"))?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(err(ErrorKind::Provider, "vault file exceeds size limit"));
        }
        let plain = self.crypto.decrypt(&bytes, &self.context())?;
        serde_json::from_slice(plain.expose())
            .map_err(|_| err(ErrorKind::Provider, "vault document is invalid"))
    }
    fn write(&self, doc: &Document) -> Result<()> {
        let plaintext = SecretValue::new(
            serde_json::to_vec(doc)
                .map_err(|_| err(ErrorKind::Provider, "vault document could not be encoded"))?,
        );
        let encrypted = self.crypto.encrypt(&plaintext, &self.context())?;
        let parent = self
            .config
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|_| {
            err(
                ErrorKind::Provider,
                "vault temporary file could not be created",
            )
        })?;
        temp.write_all(&encrypted)
            .and_then(|_| temp.as_file().sync_all())
            .map_err(|_| err(ErrorKind::Provider, "vault file could not be written"))?;
        temp.persist(&self.config.path)
            .map_err(|_| err(ErrorKind::Provider, "vault file could not be replaced"))?;
        #[cfg(unix)]
        File::open(parent).and_then(|d| d.sync_all()).map_err(|_| {
            err(
                ErrorKind::Provider,
                "vault directory could not be synchronized",
            )
        })?;
        Ok(())
    }
    fn get_value(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        self.validate(vault, name)?;
        let doc = self.read(false)?;
        let item = kind
            .map(&doc)
            .get(name)
            .ok_or_else(|| err(ErrorKind::NotFound, "secret not found"))?;
        let version = options.version.as_deref().unwrap_or(&item.latest);
        let record = item
            .versions
            .get(version)
            .ok_or_else(|| err(ErrorKind::NotFound, "secret version not found"))?;
        let (encoded, metadata) = match record {
            Record::Legacy(value) => (value, SecretMetadata::default()),
            Record::Current { value, metadata } => (value, SecretMetadata::from(metadata)),
        };
        validate_metadata(&metadata)
            .map_err(|_| err(ErrorKind::Provider, "invalid stored metadata"))?;
        if metadata.deleted || !metadata.enabled {
            return Err(err(ErrorKind::NotFound, "resource version is inactive"));
        }
        if let Some(expires) = &metadata.expires_at {
            let time = time::OffsetDateTime::parse(
                expires,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| err(ErrorKind::Provider, "invalid stored metadata"))?;
            if time <= time::OffsetDateTime::now_utc() {
                return Err(err(ErrorKind::NotFound, "resource version has expired"));
            }
        }
        let value = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| err(ErrorKind::Provider, "invalid secret value"))?,
        );
        if value.len() > MAX_VALUE {
            return Err(err(ErrorKind::Provider, "secret exceeds size limit"));
        }
        Ok(Response {
            value: SecretValue::new(value.to_vec()),
            metadata: Metadata {
                version: Some(version.to_owned()),
                secret: matches!(kind, Kind::Secret).then_some(metadata),
            },
        })
    }
    fn set_value(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        value: &SecretValue,
        metadata: &SecretMetadata,
    ) -> Result<Metadata> {
        self.validate(vault, name)?;
        validate_metadata(metadata)?;
        if value.expose().len() > MAX_VALUE {
            return Err(err(ErrorKind::InvalidInput, "secret exceeds size limit"));
        }
        let _lock = self.lock()?;
        let mut doc = self.read(true)?;
        let version = uuid::Uuid::now_v7().to_string();
        let item = kind
            .map_mut(&mut doc)
            .entry(name.to_owned())
            .or_insert_with(|| Versions {
                latest: version.clone(),
                versions: BTreeMap::new(),
            });
        if item
            .versions
            .insert(
                version.clone(),
                Record::Current {
                    value: STANDARD.encode(value.expose()),
                    metadata: metadata.into(),
                },
            )
            .is_some()
        {
            return Err(err(ErrorKind::Provider, "duplicate secret version"));
        }
        item.latest = version.clone();
        self.write(&doc)?;
        Ok(Metadata {
            version: Some(version),
            secret: matches!(kind, Kind::Secret).then(|| metadata.clone()),
        })
    }
    fn remove_value(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        options: &RemoveOptions,
    ) -> Result<()> {
        self.validate(vault, name)?;
        if !options.query.is_empty() {
            return Err(err(
                ErrorKind::Unsupported,
                "unsupported local JSON removal option",
            ));
        }
        if options.version.as_ref().is_some_and(|v| v.is_empty()) {
            return Err(err(ErrorKind::InvalidInput, "version must not be empty"));
        }
        let _lock = self.lock()?;
        let mut doc = self.read(false)?;
        let map = kind.map_mut(&mut doc);
        let item = map
            .get_mut(name)
            .ok_or_else(|| err(ErrorKind::NotFound, "resource not found"))?;
        if options.purge && options.version.is_none() {
            map.remove(name);
        } else {
            let version = options
                .version
                .as_deref()
                .unwrap_or(&item.latest)
                .to_owned();
            if options.purge {
                let mut removed = item
                    .versions
                    .remove(&version)
                    .ok_or_else(|| err(ErrorKind::NotFound, "resource version not found"))?;
                match &mut removed {
                    Record::Legacy(value) | Record::Current { value, .. } => value.zeroize(),
                }
                if item.versions.is_empty() {
                    map.remove(name);
                }
            } else {
                let record = item
                    .versions
                    .get_mut(&version)
                    .ok_or_else(|| err(ErrorKind::NotFound, "resource version not found"))?;
                match record {
                    Record::Legacy(value) => {
                        let mut metadata = StoredMetadata::from(&SecretMetadata::default());
                        metadata.deleted = true;
                        *record = Record::Current {
                            value: std::mem::take(value),
                            metadata,
                        };
                    }
                    Record::Current { metadata, .. } => metadata.deleted = true,
                }
            }
        }
        self.write(&doc)
    }
}
impl Driver for LocalJsonDriver {
    fn supports(&self, capability: Capability) -> bool {
        matches!(
            capability,
            Capability::GetSecret
                | Capability::SetSecret
                | Capability::GetCertificate
                | Capability::SetCertificate
                | Capability::GetKey
                | Capability::SetKey
                | Capability::UpdateSecretMetadata
                | Capability::ListSecrets
                | Capability::ListCertificates
                | Capability::ListKeys
                | Capability::RemoveSecret
                | Capability::RemoveCertificate
                | Capability::RemoveKey
        )
    }
    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        self.list_names(vault, Kind::Secret)
    }
    fn list_certificates(&self, vault: &str) -> Result<Vec<String>> {
        self.list_names(vault, Kind::Certificate)
    }
    fn list_keys(&self, vault: &str) -> Result<Vec<String>> {
        self.list_names(vault, Kind::Key)
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.remove_value(Kind::Secret, vault, name, options)
    }
    fn remove_certificate(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.remove_value(Kind::Certificate, vault, name, options)
    }
    fn remove_key(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.remove_value(Kind::Key, vault, name, options)
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        self.get_value(Kind::Secret, vault, name, options)
    }
    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        self.set_value(Kind::Secret, vault, name, value, &SecretMetadata::default())
    }
    fn set_secret_with(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
        options: &SetSecretOptions,
    ) -> Result<Metadata> {
        self.set_value(Kind::Secret, vault, name, value, &options.metadata)
    }
    fn update_secret_metadata(
        &self,
        vault: &str,
        name: &str,
        version: &str,
        metadata: &SecretMetadata,
    ) -> Result<Metadata> {
        self.validate(vault, name)?;
        validate_metadata(metadata)?;
        let _lock = self.lock()?;
        let mut doc = self.read(false)?;
        let item = doc
            .secrets
            .get_mut(name)
            .ok_or_else(|| err(ErrorKind::NotFound, "secret not found"))?;
        let record = item
            .versions
            .get_mut(version)
            .ok_or_else(|| err(ErrorKind::NotFound, "secret version not found"))?;
        match record {
            Record::Legacy(value) => {
                let value = std::mem::take(value);
                *record = Record::Current {
                    value,
                    metadata: metadata.into(),
                };
            }
            Record::Current { metadata: old, .. } => *old = metadata.into(),
        }
        self.write(&doc)?;
        Ok(Metadata {
            version: Some(version.into()),
            secret: Some(metadata.clone()),
        })
    }
    fn get_certificate(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<Certificate>> {
        let value = self.get_value(Kind::Certificate, vault, name, options)?;
        let wire: WireCertificate = serde_json::from_slice(value.value.expose())
            .map_err(|_| err(ErrorKind::Provider, "invalid stored certificate"))?;
        Ok(Response {
            value: Certificate {
                data: wire.data,
                content_type: wire.content_type,
            },
            metadata: value.metadata,
        })
    }
    fn set_certificate(&self, vault: &str, name: &str, value: &Certificate) -> Result<Metadata> {
        let wire = WireCertificate {
            data: value.data.clone(),
            content_type: value.content_type.clone(),
        };
        let encoded = SecretValue::new(
            serde_json::to_vec(&wire)
                .map_err(|_| err(ErrorKind::Provider, "certificate could not be encoded"))?,
        );
        self.set_value(
            Kind::Certificate,
            vault,
            name,
            &encoded,
            &SecretMetadata::default(),
        )
    }
    fn get_key(&self, vault: &str, name: &str, options: &GetOptions) -> Result<Response<Key>> {
        let value = self.get_value(Kind::Key, vault, name, options)?;
        let mut wire: WireKey = serde_json::from_slice(value.value.expose())
            .map_err(|_| err(ErrorKind::Provider, "invalid stored key"))?;
        Ok(Response {
            value: Key {
                id: std::mem::take(&mut wire.id),
                public_key: wire.public_key.take(),
                private_key: wire.private_key.take().map(SecretValue::new),
            },
            metadata: value.metadata,
        })
    }
    fn set_key(&self, vault: &str, name: &str, value: &Key) -> Result<Metadata> {
        let wire = WireKey {
            id: value.id.clone(),
            public_key: value.public_key.clone(),
            private_key: value.private_key.as_ref().map(|v| v.expose().to_vec()),
        };
        let encoded = SecretValue::new(
            serde_json::to_vec(&wire)
                .map_err(|_| err(ErrorKind::Provider, "key could not be encoded"))?,
        );
        self.set_value(Kind::Key, vault, name, &encoded, &SecretMetadata::default())
    }
}
