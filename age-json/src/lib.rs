//! Versioned, age-encrypted secrets, certificates, and keys in a JSON file.
#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use neotales_age::{AgeFile, AgeIdentity, AgeRecipient};
use neotales_vaults_core::{
    Capability, Certificate, Driver, Error, ErrorKind, GetOptions, Key, Metadata, RemoveOptions,
    Response, Result, SecretMetadata, SecretValue, SetSecretOptions,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_VALUE: usize = 1024 * 1024;

/// Configuration for one JSON vault.
#[derive(Clone, Debug)]
pub struct Config {
    /// Registered name of the vault.
    pub vault: String,
    /// JSON file path. Its parent directory must already exist.
    pub path: PathBuf,
    /// Native age public recipients; at least one is required.
    pub recipients: Vec<String>,
    /// Native age private identities, kept redacted in debug output.
    pub identities: Vec<SecretValue>,
}

/// File-backed driver. Cooperating writers use an adjacent lock file.
///
/// JSON names, versions, and status metadata are visible. Individual values
/// are encrypted. This format does not prevent rollback or deletion by an
/// attacker who can modify the JSON file. Do not use multiple independent
/// programs that write the file without taking the same lock.
pub struct AgeJsonDriver {
    vault: String,
    path: PathBuf,
    recipients: Vec<AgeRecipient>,
    identities: Vec<AgeIdentity>,
}

impl std::fmt::Debug for AgeJsonDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeJsonDriver")
            .field("vault", &self.vault)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
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
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Versions {
    latest: String,
    versions: BTreeMap<String, Version>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct Version {
    #[serde(default)]
    format: u8,
    expires_at: Option<String>,
    tags: BTreeMap<String, String>,
    value: String,
    enabled: bool,
    deleted: bool,
}

// This header is inside the age ciphertext. Length-prefixing avoids collisions
// and prevents a ciphertext from being moved to another name or version.
#[derive(Clone, Copy)]
enum Kind {
    Secret,
    Certificate,
    Key,
}

impl Kind {
    fn map(self, document: &Document) -> &BTreeMap<String, Versions> {
        match self {
            Self::Secret => &document.secrets,
            Self::Certificate => &document.certs,
            Self::Key => &document.keys,
        }
    }
    fn map_mut(self, document: &mut Document) -> &mut BTreeMap<String, Versions> {
        match self {
            Self::Secret => &mut document.secrets,
            Self::Certificate => &mut document.certs,
            Self::Key => &mut document.keys,
        }
    }
    fn prefix(self) -> &'static [u8] {
        match self {
            Self::Secret => b"neotales-vaults-age-json-secret-v1\0",
            Self::Certificate => b"neotales-vaults-age-json-certificate-v1\0",
            Self::Key => b"neotales-vaults-age-json-key-v1\0",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCertificate {
    data: Vec<u8>,
    content_type: Option<String>,
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct WireKey {
    id: String,
    public_key: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
}

fn payload(kind: Kind, vault: &str, name: &str, version: &str, value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(kind.prefix().to_vec());
    for part in [vault.as_bytes(), name.as_bytes(), version.as_bytes()] {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(value);
    out
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Binding<'a> {
    expires_at: &'a Option<String>,
    tags: &'a BTreeMap<String, String>,
    enabled: bool,
    deleted: bool,
}

fn payload_v2(
    kind: Kind,
    vault: &str,
    name: &str,
    version: &str,
    metadata: &SecretMetadata,
    value: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(b"neotales-vaults-age-json-metadata-v2\0".to_vec());
    let bound = serde_json::to_vec(&Binding {
        expires_at: &metadata.expires_at,
        tags: &metadata.tags,
        enabled: metadata.enabled,
        deleted: metadata.deleted,
    })
    .map_err(|_| err("resource metadata could not be encoded"))?;
    for part in [
        kind.prefix(),
        vault.as_bytes(),
        name.as_bytes(),
        version.as_bytes(),
        bound.as_slice(),
    ] {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(value);
    Ok(out)
}

fn validate_metadata(metadata: &SecretMetadata) -> Result<()> {
    if metadata.tags.len() > 128
        || metadata
            .tags
            .iter()
            .any(|(k, v)| k.is_empty() || k.len() > 256 || v.len() > 4096)
    {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid secret tags"));
    }
    if let Some(expires) = &metadata.expires_at {
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid secret expiration"))?;
    }
    Ok(())
}

fn err(message: &'static str) -> Error {
    Error::new(ErrorKind::Provider, message)
}

impl AgeJsonDriver {
    /// Validates recipients and identities without creating a file.
    pub fn new(config: Config) -> Result<Self> {
        if config.vault.is_empty()
            || config.path.as_os_str().is_empty()
            || config.recipients.is_empty()
            || config.identities.is_empty()
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "vault, path, recipients, and identities are required",
            ));
        }
        let recipients = config
            .recipients
            .iter()
            .map(|r| {
                AgeRecipient::from_public_key(r)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid age recipient"))
            })
            .collect::<Result<Vec<_>>>()?;
        let identities = config
            .identities
            .iter()
            .map(|i| {
                let value = std::str::from_utf8(i.expose())
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid age identity"))?;
                AgeIdentity::from_private_key(value)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid age identity"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            vault: config.vault,
            path: config.path,
            recipients,
            identities,
        })
    }

    fn validate(&self, vault: &str, name: &str) -> Result<()> {
        if vault != self.vault {
            return Err(Error::new(ErrorKind::NotFound, "vault is not configured"));
        }
        if name.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "resource name must not be empty",
            ));
        }
        Ok(())
    }

    fn lock(&self) -> Result<File> {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(PathBuf::from(name))
            .map_err(|_| err("vault lock could not be opened"))?;
        file.lock_exclusive()
            .map_err(|_| err("vault lock could not be acquired"))?;
        Ok(file)
    }

    fn read_document(&self, missing_is_empty: bool) -> Result<Document> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && missing_is_empty => {
                return Ok(Document::default());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::new(ErrorKind::NotFound, "vault file not found"));
            }
            Err(_) => return Err(err("vault file could not be opened")),
        };
        let mut bytes = Vec::new();
        file.take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| err("vault file could not be read"))?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(err("vault file exceeds size limit"));
        }
        serde_json::from_slice(&bytes).map_err(|_| err("vault file is invalid"))
    }

    fn write_document(&self, document: &Document) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(document)
            .map_err(|_| err("vault file could not be encoded"))?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(err("vault file exceeds size limit"));
        }
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)
            .map_err(|_| err("vault temporary file could not be created"))?;
        file.write_all(&bytes)
            .and_then(|()| file.as_file().sync_all())
            .map_err(|_| err("vault file could not be written"))?;
        file.persist(&self.path)
            .map_err(|_| err("vault file could not be replaced"))?;
        // Sync the containing directory on Unix so the rename is durable.
        #[cfg(unix)]
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| err("vault directory could not be synchronized"))?;
        Ok(())
    }

    fn write_value(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        value: &[u8],
        metadata: &SecretMetadata,
    ) -> Result<Metadata> {
        self.validate(vault, name)?;
        validate_metadata(metadata)?;
        if value.len() > MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "resource exceeds size limit",
            ));
        }
        let _lock = self.lock()?;
        let mut document = self.read_document(true)?;
        let version = uuid::Uuid::now_v7().to_string();
        let record = self.encrypt_record(kind, vault, name, &version, metadata, value)?;
        let versions = kind
            .map_mut(&mut document)
            .entry(name.to_owned())
            .or_insert_with(|| Versions {
                latest: version.clone(),
                versions: BTreeMap::new(),
            });
        if versions.versions.insert(version.clone(), record).is_some() {
            return Err(err("duplicate version"));
        }
        versions.latest = version.clone();
        self.write_document(&document)?;
        Ok(Metadata {
            version: Some(version),
            secret: matches!(kind, Kind::Secret).then(|| metadata.clone()),
        })
    }

    fn encrypt_record(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        version: &str,
        metadata: &SecretMetadata,
        value: &[u8],
    ) -> Result<Version> {
        let plaintext = payload_v2(kind, vault, name, version, metadata, value)?;
        let encrypted = AgeFile::encrypt(&plaintext, &self.recipients)
            .map_err(|_| err("secret could not be encrypted"))?;
        // Refuse a write that the configured identities cannot subsequently read.
        let check = Zeroizing::new(
            AgeFile::decrypt(&encrypted, &self.identities)
                .map_err(|_| err("configured identities cannot decrypt the recipients"))?,
        );
        if check.as_slice() != plaintext.as_slice() {
            return Err(err("encrypted value failed verification"));
        }
        Ok(Version {
            format: 2,
            expires_at: metadata.expires_at.clone(),
            tags: metadata.tags.clone(),
            value: STANDARD.encode(encrypted),
            enabled: metadata.enabled,
            deleted: metadata.deleted,
        })
    }

    fn decrypt_record(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        version: &str,
        record: &Version,
    ) -> Result<(SecretMetadata, SecretValue)> {
        let metadata = SecretMetadata {
            expires_at: record.expires_at.clone(),
            tags: record.tags.clone(),
            enabled: record.enabled,
            deleted: record.deleted,
        };
        validate_metadata(&metadata).map_err(|_| err("resource metadata is invalid"))?;
        let ciphertext = STANDARD
            .decode(&record.value)
            .map_err(|_| err("encrypted value is invalid"))?;
        let plaintext = Zeroizing::new(
            AgeFile::decrypt(&ciphertext, &self.identities)
                .map_err(|_| err("secret could not be decrypted"))?,
        );
        let prefix = match record.format {
            0 if metadata == SecretMetadata::default() => payload(kind, vault, name, version, &[]),
            2 => payload_v2(kind, vault, name, version, &metadata, &[])?,
            _ => return Err(err("unsupported resource format or metadata")),
        };
        let value = plaintext
            .strip_prefix(prefix.as_slice())
            .ok_or_else(|| err("secret context does not match"))?;
        if value.len() > MAX_VALUE {
            return Err(err("resource exceeds size limit"));
        }
        Ok((metadata, SecretValue::new(value.to_vec())))
    }

    fn read_value(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        self.validate(vault, name)?;
        // Writers replace the complete file atomically; readers never see a partial document.
        let document = self.read_document(false)?;
        let versions = kind
            .map(&document)
            .get(name)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "secret not found"))?;
        let version = options.version.as_deref().unwrap_or(&versions.latest);
        let record = versions
            .versions
            .get(version)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "secret version not found"))?;
        let (metadata, value) = self.decrypt_record(kind, vault, name, version, record)?;
        if metadata.deleted || !metadata.enabled {
            return Err(Error::new(
                ErrorKind::NotFound,
                "resource version is inactive",
            ));
        }
        if let Some(expires) = &metadata.expires_at {
            let time = time::OffsetDateTime::parse(
                expires,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| err("resource metadata is invalid"))?;
            if time <= time::OffsetDateTime::now_utc() {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "resource version has expired",
                ));
            }
        }
        Ok(Response {
            value,
            metadata: Metadata {
                version: Some(version.to_owned()),
                secret: matches!(kind, Kind::Secret).then_some(metadata),
            },
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
            return Err(Error::new(
                ErrorKind::Unsupported,
                "unsupported age JSON removal option",
            ));
        }
        if options.version.as_ref().is_some_and(|v| v.is_empty()) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "version must not be empty",
            ));
        }
        let _lock = self.lock()?;
        let mut document = self.read_document(false)?;
        let map = kind.map_mut(&mut document);
        let item = map
            .get_mut(name)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "resource not found"))?;
        if options.purge && options.version.is_none() {
            for (version, record) in &item.versions {
                self.decrypt_record(kind, vault, name, version, record)?;
            }
            map.remove(name);
        } else {
            let version = options
                .version
                .as_deref()
                .unwrap_or(&item.latest)
                .to_owned();
            let record = item
                .versions
                .get(&version)
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "resource version not found"))?;
            let (mut metadata, value) = self.decrypt_record(kind, vault, name, &version, record)?;
            if options.purge {
                item.versions.remove(&version);
                if item.versions.is_empty() {
                    map.remove(name);
                }
            } else {
                metadata.deleted = true;
                let updated =
                    self.encrypt_record(kind, vault, name, &version, &metadata, value.expose())?;
                item.versions.insert(version, updated);
            }
        }
        self.write_document(&document)
    }
}

impl Driver for AgeJsonDriver {
    fn supports(&self, capability: Capability) -> bool {
        matches!(
            capability,
            Capability::GetSecret
                | Capability::SetSecret
                | Capability::UpdateSecretMetadata
                | Capability::GetCertificate
                | Capability::SetCertificate
                | Capability::GetKey
                | Capability::SetKey
                | Capability::ListSecrets
                | Capability::ListCertificates
                | Capability::ListKeys
                | Capability::RemoveSecret
                | Capability::RemoveCertificate
                | Capability::RemoveKey
        )
    }

    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        self.validate(vault, "list")?;
        Ok(self.read_document(false)?.secrets.keys().cloned().collect())
    }
    fn list_certificates(&self, vault: &str) -> Result<Vec<String>> {
        self.validate(vault, "list")?;
        Ok(self.read_document(false)?.certs.keys().cloned().collect())
    }
    fn list_keys(&self, vault: &str) -> Result<Vec<String>> {
        self.validate(vault, "list")?;
        Ok(self.read_document(false)?.keys.keys().cloned().collect())
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

    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        self.write_value(
            Kind::Secret,
            vault,
            name,
            value.expose(),
            &SecretMetadata::default(),
        )
    }
    fn set_secret_with(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
        options: &SetSecretOptions,
    ) -> Result<Metadata> {
        self.write_value(Kind::Secret, vault, name, value.expose(), &options.metadata)
    }
    fn update_secret_metadata(
        &self,
        vault: &str,
        name: &str,
        version: &str,
        metadata: &SecretMetadata,
    ) -> Result<Metadata> {
        self.validate(vault, name)?;
        if version.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "version must not be empty",
            ));
        }
        validate_metadata(metadata)?;
        let _lock = self.lock()?;
        let mut document = self.read_document(false)?;
        let versions = document
            .secrets
            .get_mut(name)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "secret not found"))?;
        let record = versions
            .versions
            .get_mut(version)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "secret version not found"))?;
        let (_, value) = self.decrypt_record(Kind::Secret, vault, name, version, record)?;
        *record =
            self.encrypt_record(Kind::Secret, vault, name, version, metadata, value.expose())?;
        self.write_document(&document)?;
        Ok(Metadata {
            version: Some(version.to_owned()),
            secret: Some(metadata.clone()),
        })
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        self.read_value(Kind::Secret, vault, name, options)
    }
    fn set_certificate(&self, vault: &str, name: &str, value: &Certificate) -> Result<Metadata> {
        let wire = WireCertificate {
            data: value.data.clone(),
            content_type: value.content_type.clone(),
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&wire).map_err(|_| err("certificate could not be encoded"))?,
        );
        self.write_value(
            Kind::Certificate,
            vault,
            name,
            &bytes,
            &SecretMetadata::default(),
        )
    }
    fn get_certificate(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<Certificate>> {
        let response = self.read_value(Kind::Certificate, vault, name, options)?;
        let wire: WireCertificate = serde_json::from_slice(response.value.expose())
            .map_err(|_| err("certificate is invalid"))?;
        Ok(Response {
            value: Certificate {
                data: wire.data,
                content_type: wire.content_type,
            },
            metadata: response.metadata,
        })
    }
    fn set_key(&self, vault: &str, name: &str, value: &Key) -> Result<Metadata> {
        let wire = WireKey {
            id: value.id.clone(),
            public_key: value.public_key.clone(),
            private_key: value.private_key.as_ref().map(|v| v.expose().to_vec()),
        };
        let bytes =
            Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| err("key could not be encoded"))?);
        self.write_value(Kind::Key, vault, name, &bytes, &SecretMetadata::default())
    }
    fn get_key(&self, vault: &str, name: &str, options: &GetOptions) -> Result<Response<Key>> {
        let response = self.read_value(Kind::Key, vault, name, options)?;
        let wire: WireKey =
            serde_json::from_slice(response.value.expose()).map_err(|_| err("key is invalid"))?;
        let key = Key {
            id: wire.id.clone(),
            public_key: wire.public_key.clone(),
            private_key: wire
                .private_key
                .as_ref()
                .map(|v| SecretValue::new(v.clone())),
        };
        Ok(Response {
            value: key,
            metadata: response.metadata,
        })
    }
}
