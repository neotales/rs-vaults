//! An age-encrypted, versioned SQLite vault.
#![forbid(unsafe_code)]

use neotales_age::{AgeFile, AgeIdentity, AgeRecipient};
use neotales_vaults_core::{
    Capability, Certificate, Driver, Error, ErrorKind, GetOptions, Key, Metadata, RemoveOptions,
    Response, Result, SecretMetadata, SecretValue, SetSecretOptions,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

const APPLICATION_ID: i64 = 0x4e56534c;
const SCHEMA_VERSION: i64 = 1;
const MAX_VALUE: usize = 1024 * 1024;
const MAX_CIPHERTEXT: i64 = 4 * 1024 * 1024;

/// Configuration for one SQLite vault.
#[derive(Clone, Debug)]
pub struct Config {
    /// Registered vault name.
    pub vault: String,
    /// SQLite file path. The parent directory must exist.
    pub path: PathBuf,
    /// One or more native age recipients.
    pub recipients: Vec<String>,
    /// Native age identities. At least one must decrypt newly written values.
    pub identities: Vec<SecretValue>,
}

/// Driver for one database. SQLite journal files may exist during transactions.
///
/// Resource names and versions are visible. Values are age-encrypted, bound to
/// their vault, kind, name, and version. An attacker with write access can
/// still delete records or roll back the database.
pub struct AgeSqliteDriver {
    vault: String,
    path: PathBuf,
    recipients: Vec<AgeRecipient>,
    identities: Vec<AgeIdentity>,
}

impl std::fmt::Debug for AgeSqliteDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeSqliteDriver")
            .field("vault", &self.vault)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Secret,
    Certificate,
    Key,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Certificate => "certificate",
            Self::Key => "key",
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireMetadata {
    expires_at: Option<String>,
    tags: BTreeMap<String, String>,
    enabled: bool,
    deleted: bool,
}

impl From<&SecretMetadata> for WireMetadata {
    fn from(value: &SecretMetadata) -> Self {
        Self {
            expires_at: value.expires_at.clone(),
            tags: value.tags.clone(),
            enabled: value.enabled,
            deleted: value.deleted,
        }
    }
}
impl From<WireMetadata> for SecretMetadata {
    fn from(value: WireMetadata) -> Self {
        Self {
            expires_at: value.expires_at,
            tags: value.tags,
            enabled: value.enabled,
            deleted: value.deleted,
        }
    }
}

fn provider(message: &'static str) -> Error {
    Error::new(ErrorKind::Provider, message)
}
fn context(kind: Kind, vault: &str, name: &str, version: &str, value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(b"neotales-vaults-age-sqlite-v1\0".to_vec());
    for part in [kind.name(), vault, name, version] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    bytes.extend_from_slice(value);
    bytes
}

fn context_v2(kind: Kind, vault: &str, name: &str, version: &str) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(b"neotales-vaults-age-sqlite-metadata-v2\0".to_vec());
    for part in [kind.name(), vault, name, version] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    bytes
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

impl AgeSqliteDriver {
    /// Validates the configuration without opening or creating the database.
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
            .map(|identity| {
                let value = std::str::from_utf8(identity.expose())
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
    fn list_names(&self, vault: &str, kind: Kind) -> Result<Vec<String>> {
        self.validate(vault, "list")?;
        let db = self.open(false, false)?;
        let mut statement = db
            .prepare("SELECT name FROM latest WHERE kind = ?1 ORDER BY name")
            .map_err(|_| provider("vault listing failed"))?;
        let rows = statement
            .query_map([kind.name()], |row| row.get::<_, String>(0))
            .map_err(|_| provider("vault listing failed"))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| provider("vault listing failed"))
    }

    fn open(&self, create: bool, writable: bool) -> Result<Connection> {
        // Initialize in a private temporary file, then publish without replacing
        // any existing path. Concurrent first writers can race safely.
        if create && !self.path.exists() {
            let parent = self
                .path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let temp = tempfile::NamedTempFile::new_in(parent)
                .map_err(|_| provider("vault file could not be created"))?;
            let mut initial =
                Connection::open_with_flags(temp.path(), OpenFlags::SQLITE_OPEN_READ_WRITE)
                    .map_err(|_| provider("vault initialization failed"))?;
            let tx = initial
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| provider("vault initialization failed"))?;
            tx.execute_batch("PRAGMA application_id = 1314280268; PRAGMA user_version = 1;
                CREATE TABLE vault_info (name TEXT NOT NULL);
                CREATE TABLE versions (kind TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY(kind,name,version));
                CREATE TABLE latest (kind TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, PRIMARY KEY(kind,name));")
                .map_err(|_| provider("vault initialization failed"))?;
            tx.execute("INSERT INTO vault_info(name) VALUES (?1)", [&self.vault])
                .map_err(|_| provider("vault initialization failed"))?;
            tx.commit()
                .map_err(|_| provider("vault initialization failed"))?;
            initial
                .close()
                .map_err(|_| provider("vault initialization failed"))?;
            match temp.persist_noclobber(&self.path) {
                Ok(_) => {}
                Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(provider("vault file could not be created")),
            }
        }
        let flags = if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let db = Connection::open_with_flags(&self.path, flags).map_err(|e| {
            if !create && !self.path.exists() {
                Error::new(ErrorKind::NotFound, "vault file not found")
            } else {
                let _ = e;
                provider("vault database could not be opened")
            }
        })?;
        db.busy_timeout(Duration::from_secs(5))
            .map_err(|_| provider("database configuration failed"))?;
        let app_id: i64 = db
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(|_| provider("invalid vault database"))?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| provider("invalid vault database"))?;
        if app_id != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(provider("unrecognized vault database"));
        }
        let mut stmt = db
            .prepare("SELECT name FROM vault_info LIMIT 2")
            .map_err(|_| provider("invalid vault database"))?;
        let mut rows = stmt
            .query([])
            .map_err(|_| provider("invalid vault database"))?;
        let name: String = rows
            .next()
            .map_err(|_| provider("invalid vault database"))?
            .ok_or_else(|| provider("invalid vault database"))?
            .get(0)
            .map_err(|_| provider("invalid vault database"))?;
        if rows
            .next()
            .map_err(|_| provider("invalid vault database"))?
            .is_some()
        {
            return Err(provider("invalid vault database"));
        }
        if name != self.vault {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "database belongs to a different vault",
            ));
        }
        drop(rows);
        drop(stmt);
        Ok(db)
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
        let version = uuid::Uuid::now_v7().to_string();
        let encrypted = self.encrypt_value(kind, vault, name, &version, value, metadata)?;
        let mut db = self.open(true, true)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| provider("vault transaction failed"))?;
        tx.execute(
            "INSERT INTO versions(kind,name,version,value) VALUES (?1,?2,?3,?4)",
            params![kind.name(), name, version, encrypted],
        )
        .map_err(|_| provider("resource write failed"))?;
        tx.execute("INSERT INTO latest(kind,name,version) VALUES (?1,?2,?3) ON CONFLICT(kind,name) DO UPDATE SET version=excluded.version", params![kind.name(), name, version]).map_err(|_| provider("resource write failed"))?;
        tx.commit().map_err(|_| provider("vault commit failed"))?;
        Ok(Metadata {
            version: Some(version),
            secret: matches!(kind, Kind::Secret).then(|| metadata.clone()),
        })
    }

    fn encrypt_value(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        version: &str,
        value: &[u8],
        metadata: &SecretMetadata,
    ) -> Result<Vec<u8>> {
        let mut plaintext = context_v2(kind, vault, name, version);
        let metadata_bytes = serde_json::to_vec(&WireMetadata::from(metadata))
            .map_err(|_| provider("metadata could not be encoded"))?;
        plaintext.extend_from_slice(&(metadata_bytes.len() as u64).to_be_bytes());
        plaintext.extend_from_slice(&metadata_bytes);
        plaintext.extend_from_slice(value);
        let encrypted = AgeFile::encrypt(&plaintext, &self.recipients)
            .map_err(|_| provider("resource could not be encrypted"))?;
        let verified = Zeroizing::new(
            AgeFile::decrypt(&encrypted, &self.identities)
                .map_err(|_| provider("configured identities cannot decrypt the recipients"))?,
        );
        if verified.as_slice() != plaintext.as_slice() {
            return Err(provider("encrypted value failed verification"));
        }
        if encrypted.len() as i64 > MAX_CIPHERTEXT {
            return Err(provider("encrypted value exceeds size limit"));
        }
        Ok(encrypted)
    }

    fn read_value(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        self.validate(vault, name)?;
        let db = self.open(false, false)?;
        // One query selects the latest pointer and value within a single SQLite snapshot.
        let row: Option<(String, Vec<u8>)> = db.query_row(
            "SELECT version,value FROM versions WHERE kind=?1 AND name=?2 AND version=COALESCE(?3,(SELECT version FROM latest WHERE kind=?1 AND name=?2)) AND length(value)<=?4",
            params![kind.name(), name, options.version, MAX_CIPHERTEXT], |r| Ok((r.get(0)?, r.get(1)?))
        ).optional().map_err(|_| provider("resource read failed"))?;
        let (version, encrypted) =
            row.ok_or_else(|| Error::new(ErrorKind::NotFound, "resource version not found"))?;
        let (metadata, value) = self.decrypt_value(kind, vault, name, &version, &encrypted)?;
        if metadata.deleted || !metadata.enabled {
            return Err(Error::new(
                ErrorKind::NotFound,
                "resource version is inactive",
            ));
        }
        if let Some(expires) = &metadata.expires_at {
            let expires = time::OffsetDateTime::parse(
                expires,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| provider("resource metadata is invalid"))?;
            if expires <= time::OffsetDateTime::now_utc() {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "resource version has expired",
                ));
            }
        }
        Ok(Response {
            value,
            metadata: Metadata {
                version: Some(version),
                secret: matches!(kind, Kind::Secret).then_some(metadata),
            },
        })
    }

    fn decrypt_value(
        &self,
        kind: Kind,
        vault: &str,
        name: &str,
        version: &str,
        encrypted: &[u8],
    ) -> Result<(SecretMetadata, SecretValue)> {
        let plaintext = Zeroizing::new(
            AgeFile::decrypt(encrypted, &self.identities)
                .map_err(|_| provider("resource could not be decrypted"))?,
        );
        let v2_prefix = context_v2(kind, vault, name, version);
        let (metadata, value) = if let Some(payload) = plaintext.strip_prefix(v2_prefix.as_slice())
        {
            let length: [u8; 8] = payload
                .get(..8)
                .ok_or_else(|| provider("resource metadata is invalid"))?
                .try_into()
                .map_err(|_| provider("resource metadata is invalid"))?;
            let length = usize::try_from(u64::from_be_bytes(length))
                .map_err(|_| provider("resource metadata is invalid"))?;
            if length > MAX_VALUE {
                return Err(provider("resource metadata exceeds size limit"));
            }
            let end = 8usize
                .checked_add(length)
                .ok_or_else(|| provider("resource metadata is invalid"))?;
            let data = payload
                .get(8..end)
                .ok_or_else(|| provider("resource metadata is invalid"))?;
            let wire: WireMetadata = serde_json::from_slice(data)
                .map_err(|_| provider("resource metadata is invalid"))?;
            let metadata = SecretMetadata::from(wire);
            validate_metadata(&metadata).map_err(|_| provider("resource metadata is invalid"))?;
            (
                metadata,
                payload
                    .get(end..)
                    .ok_or_else(|| provider("resource is invalid"))?,
            )
        } else {
            let prefix = context(kind, vault, name, version, &[]);
            let value = plaintext
                .strip_prefix(prefix.as_slice())
                .ok_or_else(|| provider("resource context does not match"))?;
            (SecretMetadata::default(), value)
        };
        if value.len() > MAX_VALUE {
            return Err(provider("resource exceeds size limit"));
        }
        Ok((metadata, SecretValue::new(value.to_vec())))
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
                "unsupported age SQLite removal option",
            ));
        }
        if options.version.as_ref().is_some_and(|v| v.is_empty()) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "version must not be empty",
            ));
        }
        let mut db = self.open(false, true)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| provider("vault transaction failed"))?;
        if options.purge && options.version.is_none() {
            {
                let mut stmt = tx
                    .prepare("SELECT version,CASE WHEN length(value)<=?3 THEN value ELSE NULL END FROM versions WHERE kind=?1 AND name=?2")
                    .map_err(|_| provider("resource read failed"))?;
                let rows = stmt
                    .query_map(params![kind.name(), name, MAX_CIPHERTEXT], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, Option<Vec<u8>>>(1)?))
                    })
                    .map_err(|_| provider("resource read failed"))?;
                let mut count = 0usize;
                for row in rows {
                    let (version, encrypted) = row.map_err(|_| provider("resource read failed"))?;
                    let encrypted =
                        encrypted.ok_or_else(|| provider("encrypted value exceeds size limit"))?;
                    self.decrypt_value(kind, vault, name, &version, &encrypted)?;
                    count += 1;
                }
                if count == 0 {
                    return Err(Error::new(ErrorKind::NotFound, "resource not found"));
                }
            }
            tx.execute(
                "DELETE FROM versions WHERE kind=?1 AND name=?2",
                params![kind.name(), name],
            )
            .map_err(|_| provider("resource removal failed"))?;
            tx.execute(
                "DELETE FROM latest WHERE kind=?1 AND name=?2",
                params![kind.name(), name],
            )
            .map_err(|_| provider("resource removal failed"))?;
        } else {
            let row: Option<(String, Vec<u8>)> = tx.query_row(
                "SELECT version,value FROM versions WHERE kind=?1 AND name=?2 AND version=COALESCE(?3,(SELECT version FROM latest WHERE kind=?1 AND name=?2)) AND length(value)<=?4",
                params![kind.name(), name, options.version, MAX_CIPHERTEXT],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional().map_err(|_| provider("resource read failed"))?;
            let (version, encrypted) =
                row.ok_or_else(|| Error::new(ErrorKind::NotFound, "resource version not found"))?;
            let (mut metadata, value) =
                self.decrypt_value(kind, vault, name, &version, &encrypted)?;
            if options.purge {
                tx.execute(
                    "DELETE FROM versions WHERE kind=?1 AND name=?2 AND version=?3",
                    params![kind.name(), name, version],
                )
                .map_err(|_| provider("resource removal failed"))?;
                tx.execute("DELETE FROM latest WHERE kind=?1 AND name=?2 AND NOT EXISTS (SELECT 1 FROM versions WHERE kind=?1 AND name=?2)", params![kind.name(), name])
                    .map_err(|_| provider("resource removal failed"))?;
            } else {
                metadata.deleted = true;
                let encrypted =
                    self.encrypt_value(kind, vault, name, &version, value.expose(), &metadata)?;
                tx.execute(
                    "UPDATE versions SET value=?4 WHERE kind=?1 AND name=?2 AND version=?3",
                    params![kind.name(), name, version, encrypted],
                )
                .map_err(|_| provider("resource removal failed"))?;
            }
        }
        tx.commit().map_err(|_| provider("vault commit failed"))
    }
}

impl Driver for AgeSqliteDriver {
    fn supports(&self, capability: Capability) -> bool {
        matches!(
            capability,
            Capability::GetSecret
                | Capability::SetSecret
                | Capability::EnsureSecret
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
    fn ensure_secret(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
    ) -> Result<Response<SecretValue>> {
        self.validate(vault, name)?;
        let mut db = self.open(true, true)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| provider("vault transaction failed"))?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM versions WHERE kind=?1 AND name=?2)",
                params![Kind::Secret.name(), name],
                |row| row.get(0),
            )
            .map_err(|_| provider("resource read failed"))?;
        if exists {
            return self.read_value(Kind::Secret, vault, name, &GetOptions::default());
        }
        // A stale latest pointer still denotes a previously existing resource.
        let has_pointer: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM latest WHERE kind=?1 AND name=?2)",
                params![Kind::Secret.name(), name],
                |row| row.get(0),
            )
            .map_err(|_| provider("resource read failed"))?;
        if has_pointer {
            return Err(Error::new(
                ErrorKind::NotFound,
                "resource version not found",
            ));
        }
        if value.expose().len() > MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "resource exceeds size limit",
            ));
        }
        let version = uuid::Uuid::now_v7().to_string();
        let metadata = SecretMetadata::default();
        let encrypted = self.encrypt_value(
            Kind::Secret,
            vault,
            name,
            &version,
            value.expose(),
            &metadata,
        )?;
        tx.execute(
            "INSERT INTO versions(kind,name,version,value) VALUES (?1,?2,?3,?4)",
            params![Kind::Secret.name(), name, version, encrypted],
        )
        .map_err(|_| provider("resource write failed"))?;
        tx.execute(
            "INSERT INTO latest(kind,name,version) VALUES (?1,?2,?3)",
            params![Kind::Secret.name(), name, version],
        )
        .map_err(|_| provider("resource write failed"))?;
        tx.commit().map_err(|_| provider("vault commit failed"))?;
        Ok(Response {
            value: value.clone(),
            metadata: Metadata {
                version: Some(version),
                secret: Some(metadata),
            },
        })
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
        // No database is created by a metadata update.
        let mut db = self.open(false, true)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| provider("vault transaction failed"))?;
        let encrypted: Option<Vec<u8>> = tx.query_row(
            "SELECT value FROM versions WHERE kind='secret' AND name=?1 AND version=?2 AND length(value)<=?3",
            params![name, version, MAX_CIPHERTEXT], |row| row.get(0)
        ).optional().map_err(|_| provider("resource read failed"))?;
        let encrypted =
            encrypted.ok_or_else(|| Error::new(ErrorKind::NotFound, "secret version not found"))?;
        let (_, value) = self.decrypt_value(Kind::Secret, vault, name, version, &encrypted)?;
        let replacement =
            self.encrypt_value(Kind::Secret, vault, name, version, value.expose(), metadata)?;
        let count = tx
            .execute(
                "UPDATE versions SET value=?1 WHERE kind='secret' AND name=?2 AND version=?3",
                params![replacement, name, version],
            )
            .map_err(|_| provider("metadata update failed"))?;
        if count != 1 {
            return Err(provider("metadata update failed"));
        }
        tx.commit().map_err(|_| provider("vault commit failed"))?;
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
            serde_json::to_vec(&wire).map_err(|_| provider("certificate could not be encoded"))?,
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
            .map_err(|_| provider("certificate is invalid"))?;
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
        let bytes = Zeroizing::new(
            serde_json::to_vec(&wire).map_err(|_| provider("key could not be encoded"))?,
        );
        self.write_value(Kind::Key, vault, name, &bytes, &SecretMetadata::default())
    }
    fn get_key(&self, vault: &str, name: &str, options: &GetOptions) -> Result<Response<Key>> {
        let response = self.read_value(Kind::Key, vault, name, options)?;
        let wire: WireKey = serde_json::from_slice(response.value.expose())
            .map_err(|_| provider("key is invalid"))?;
        Ok(Response {
            value: Key {
                id: wire.id.clone(),
                public_key: wire.public_key.clone(),
                private_key: wire
                    .private_key
                    .as_ref()
                    .map(|v| SecretValue::new(v.clone())),
            },
            metadata: response.metadata,
        })
    }
}
