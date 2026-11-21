//! Read and optionally write KeePass secrets, certificates, and keys.
#![forbid(unsafe_code)]

use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use neotales_keepass::{
    DeletedObject, Entry, Group, KdbxCredentials, KdbxFile, KdbxKeyFile, KdbxReadLimits,
    KdbxTimestamp, KdbxUuid, KdbxWriteOptions, KeePassDatabase, ProtectedValue,
};
use neotales_vaults_core::{
    Capability, Certificate, Driver, Error, ErrorKind, GetOptions, Key, Metadata, RemoveOptions,
    Response, Result, SecretValue,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const GROUP_MARKER: &str = "neotales-vaults-kind";
const MAX_VALUE: usize = 1024 * 1024;

#[derive(Clone, Copy)]
enum ResourceKind {
    Certificate,
    Key,
}
impl ResourceKind {
    fn group_name(self) -> &'static str {
        match self {
            Self::Certificate => "neotales-vaults-certificates-v1",
            Self::Key => "neotales-vaults-keys-v1",
        }
    }
    fn marker(self) -> &'static str {
        match self {
            Self::Certificate => "certificate-v1",
            Self::Key => "key-v1",
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

fn group_index(root: &Group, kind: ResourceKind) -> Result<Option<usize>> {
    let mut matches = root
        .groups
        .iter()
        .enumerate()
        .filter(|(_, group)| group.name == kind.group_name());
    let found = matches.next();
    if matches.next().is_some() {
        return Err(Error::new(
            ErrorKind::Provider,
            "KeePass resource group is ambiguous",
        ));
    }
    if let Some((_, group)) = found
        && group.custom_data.get(GROUP_MARKER) != Some(kind.marker())
    {
        return Err(Error::new(
            ErrorKind::Provider,
            "KeePass resource group is not owned by this driver",
        ));
    }
    Ok(found.map(|(i, _)| i))
}

fn entry_index(group: &Group, name: &str) -> Result<Option<usize>> {
    let mut matches = group
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.title == name)
        .map(|(i, _)| i);
    let index = matches.next();
    if matches.next().is_some() {
        return Err(Error::new(
            ErrorKind::Provider,
            "KeePass entry title is ambiguous",
        ));
    }
    Ok(index)
}

fn group_count(group: &Group, id: KdbxUuid) -> usize {
    usize::from(group.id == id)
        + group
            .groups
            .iter()
            .map(|g| group_count(g, id))
            .sum::<usize>()
}
fn group_by_id_mut(group: &mut Group, id: KdbxUuid) -> Option<&mut Group> {
    if group.id == id {
        return Some(group);
    }
    group
        .groups
        .iter_mut()
        .find_map(|child| group_by_id_mut(child, id))
}

fn set_password(group: &mut Group, name: &str, value: &str) -> Result<()> {
    match entry_index(group, name)? {
        Some(index) => {
            let entry = &mut group.entries[index];
            if entry
                .fields
                .iter()
                .filter(|field| field.key == "Password")
                .count()
                > 1
            {
                return Err(Error::new(
                    ErrorKind::Provider,
                    "KeePass password field is ambiguous",
                ));
            }
            let password = ProtectedValue::from_text(value);
            if let Some(field) = entry
                .fields
                .iter_mut()
                .find(|field| field.key == "Password")
            {
                field.value = password.clone();
                field.protected = true;
            }
            entry.password = password;
        }
        None => {
            let mut entry = Entry::new(name);
            entry.password = ProtectedValue::from_text(value);
            group.add_entry(entry);
        }
    }
    Ok(())
}

/// One password-protected KDBX database and its registered vault name.
#[derive(Clone, Debug)]
pub struct Config {
    /// Vault name accepted by this driver.
    pub vault: String,
    /// Path to an existing KDBX file.
    pub path: PathBuf,
    /// Database password, not the password of an entry.
    pub password: SecretValue,
}

/// Driver for root entry passwords and marked certificate/key groups.
///
/// This implementation does not support nested groups or historical versions.
/// Writes are disabled unless explicitly configured
/// with [`KeepassDriver::with_write_options`].
#[derive(Clone, Debug)]
pub struct KeepassDriver {
    config: Config,
    keyfile: Option<SecretValue>,
    write_options: Option<KdbxWriteOptions>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn lookup_keyring(account: &str) -> Result<Option<SecretValue>> {
    #[cfg(target_os = "linux")]
    let builder = keyring::secret_service::default_credential_builder();
    #[cfg(target_os = "macos")]
    let builder = keyring::macos::default_credential_builder();
    #[cfg(target_os = "windows")]
    let builder = keyring::windows::default_credential_builder();
    let credential = builder
        .build(None, "neotales-vaults-keepass", account)
        .map_err(|_| Error::new(ErrorKind::Provider, "OS credential store unavailable"))?;
    match keyring::Entry::new_with_credential(credential).get_secret() {
        Ok(value) => Ok(Some(SecretValue::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(Error::new(
            ErrorKind::Provider,
            "OS credential store unavailable",
        )),
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn lookup_keyring(_: &str) -> Result<Option<SecretValue>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "OS credential store unavailable",
    ))
}

impl KeepassDriver {
    /// Creates a driver without opening the database.
    pub fn new(config: Config) -> Result<Self> {
        if config.vault.is_empty() || config.path.as_os_str().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "vault and path must not be empty",
            ));
        }
        Ok(Self {
            config,
            keyfile: None,
            write_options: None,
        })
    }

    /// Resolve the existing KDBX path and discover credentials. The native
    /// credential store uses service `neotales-vaults-keepass` and the
    /// canonical absolute path as account. Its password takes precedence over
    /// `KEEPASS_SECRET`; `KEEPASS_KEYFILE` adds a key-file component.
    ///
    /// If the native store is unavailable, the environment password is used
    /// when provided. Explicit [`Self::new`] configuration remains independent
    /// of environment variables and the native store.
    pub fn discover(vault: impl Into<String>, path: impl AsRef<Path>) -> Result<Self> {
        let path = std::fs::canonicalize(path)
            .map_err(|_| Error::new(ErrorKind::NotFound, "KeePass file could not be resolved"))?;
        let account = path.to_str().ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "KeePass path is not valid UTF-8")
        })?;
        let password = match lookup_keyring(account) {
            Ok(Some(password)) => Some(password),
            result => {
                let env_password = std::env::var_os("KEEPASS_SECRET")
                    .map(|s| {
                        s.into_string().map(Zeroizing::new).map_err(|_| {
                            Error::new(ErrorKind::InvalidInput, "KEEPASS_SECRET is not valid UTF-8")
                        })
                    })
                    .transpose()?;
                if env_password.is_none() && std::env::var_os("KEEPASS_KEYFILE").is_none() {
                    result?;
                }
                env_password
                    .as_ref()
                    .map(|s| SecretValue::new(s.as_bytes().to_vec()))
            }
        };
        let keyfile = std::env::var_os("KEEPASS_KEYFILE")
            .map(|path| {
                if path.is_empty() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "KEEPASS_KEYFILE is empty",
                    ));
                }
                let file = File::open(path).map_err(|_| {
                    Error::new(ErrorKind::Provider, "KeePass key file could not be opened")
                })?;
                let mut bytes = Zeroizing::new(Vec::new());
                file.take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| {
                        Error::new(ErrorKind::Provider, "KeePass key file could not be read")
                    })?;
                if bytes.len() > 1024 * 1024 {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "KeePass key file exceeds size limit",
                    ));
                }
                KdbxKeyFile::parse(&bytes)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid KeePass key file"))?;
                Ok(SecretValue::new(std::mem::take(&mut *bytes)))
            })
            .transpose()?;
        if password.as_ref().is_some_and(|p| p.expose().is_empty()) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "KeePass password must not be empty",
            ));
        }
        if password.is_none() && keyfile.is_none() {
            return Err(Error::new(
                ErrorKind::NotFound,
                "KeePass credentials not found",
            ));
        }
        let mut driver = Self::new(Config {
            vault: vault.into(),
            path,
            password: password.unwrap_or_else(|| SecretValue::new(Vec::new())),
        })?;
        driver.keyfile = keyfile;
        Ok(driver)
    }

    fn credentials(&self) -> Result<KdbxCredentials> {
        let password =
            (!self.config.password.expose().is_empty()).then(|| self.config.password.expose());
        let mut providers: Vec<Box<dyn neotales_keepass::CredentialProvider + Send>> = Vec::new();
        if let Some(keyfile) = &self.keyfile {
            providers.push(Box::new(KdbxKeyFile::parse(keyfile.expose()).map_err(
                |_| Error::new(ErrorKind::InvalidInput, "invalid KeePass key file"),
            )?));
        }
        KdbxCredentials::from_parts(password, providers)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid KeePass credentials"))
    }

    /// Enables writes with explicit KDBX 4.1 settings.
    ///
    /// Each write rewrites the whole file with these settings. A sidecar lock
    /// coordinates only writers using this driver. Other applications can
    /// still race with the final replacement despite the conflict check.
    pub fn with_write_options(mut self, options: KdbxWriteOptions) -> Self {
        self.write_options = Some(options);
        self
    }

    fn validate(&self, vault: &str, name: &str) -> Result<()> {
        if vault != self.config.vault {
            return Err(Error::new(ErrorKind::NotFound, "vault is not configured"));
        }
        if name.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "entry name must not be empty",
            ));
        }
        Ok(())
    }

    fn load(&self, file: impl Read) -> Result<KeePassDatabase> {
        KdbxFile::open_with_credentials(file, &mut self.credentials()?)
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass database could not be opened"))
    }
    fn list_names(&self, vault: &str, kind: Option<ResourceKind>) -> Result<Vec<String>> {
        self.validate(vault, "list")?;
        let file = File::open(&self.config.path)
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass file could not be opened"))?;
        let database = self.load(file)?;
        let group = match kind {
            None => &database.root,
            Some(kind) => match group_index(&database.root, kind)? {
                Some(index) => &database.root.groups[index],
                None => return Ok(Vec::new()),
            },
        };
        let mut names = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for entry in &group.entries {
            if entry.title.is_empty() {
                continue;
            }
            if !seen.insert(&entry.title) {
                return Err(Error::new(
                    ErrorKind::Provider,
                    "KeePass entry title is ambiguous",
                ));
            }
            names.push(entry.title.clone());
        }
        Ok(names)
    }

    fn lock(&self) -> Result<File> {
        let mut name = self.config.path.as_os_str().to_os_string();
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
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass lock could not be opened"))?;
        file.lock_exclusive()
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass lock could not be acquired"))?;
        Ok(file)
    }

    fn snapshot(&self) -> Result<Vec<u8>> {
        let metadata = std::fs::symlink_metadata(&self.config.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::new(ErrorKind::NotFound, "KeePass file not found")
            } else {
                Error::new(ErrorKind::Provider, "KeePass file could not be inspected")
            }
        })?;
        if !metadata.file_type().is_file() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "KeePass writes require a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "KeePass writes do not support hard links",
                ));
            }
        }
        const MAX_BYTES: u64 = 64 * 1024 * 1024;
        let mut data = Vec::new();
        File::open(&self.config.path)
            .and_then(|file| file.take(MAX_BYTES + 1).read_to_end(&mut data))
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass file could not be read"))?;
        if data.len() as u64 > MAX_BYTES {
            return Err(Error::new(
                ErrorKind::Provider,
                "KeePass file exceeds size limit",
            ));
        }
        Ok(data)
    }
    fn rewrite(&self, update: impl FnOnce(&mut KeePassDatabase) -> Result<()>) -> Result<Metadata> {
        let options = self
            .write_options
            .ok_or_else(|| Error::new(ErrorKind::Unsupported, "KeePass writes are disabled"))?;
        let _lock = self.lock()?;
        let original = self.snapshot()?;
        let original_hash = Sha256::digest(&original);
        let mut database = self.load(original.as_slice())?;
        if !database.can_save_losslessly {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "KeePass database cannot be saved losslessly",
            ));
        }
        update(&mut database)?;
        let parent = self
            .config
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut output = tempfile::NamedTempFile::new_in(parent).map_err(|_| {
            Error::new(
                ErrorKind::Provider,
                "KeePass temporary file could not be created",
            )
        })?;
        let mut credentials = self.credentials()?;
        KdbxFile::save(
            &database,
            output.as_file_mut(),
            &mut credentials,
            options,
            &KdbxReadLimits::default(),
        )
        .map_err(|_| Error::new(ErrorKind::Provider, "KeePass database could not be saved"))?;
        output.as_file().sync_all().map_err(|_| {
            Error::new(
                ErrorKind::Provider,
                "KeePass temporary file could not be synchronized",
            )
        })?;
        if Sha256::digest(self.snapshot()?) != original_hash {
            return Err(Error::new(
                ErrorKind::Provider,
                "KeePass file changed during write",
            ));
        }
        output
            .persist(&self.config.path)
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass file could not be replaced"))?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| {
                Error::new(
                    ErrorKind::Provider,
                    "KeePass directory could not be synchronized",
                )
            })?;
        Ok(Metadata::default())
    }

    fn read_group_value(
        &self,
        kind: ResourceKind,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<SecretValue> {
        self.validate(vault, name)?;
        if options.version.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "KeePass versions are not supported",
            ));
        }
        let file = File::open(&self.config.path)
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass file could not be opened"))?;
        let database = self.load(file)?;
        let index = group_index(&database.root, kind)?
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "KeePass resource not found"))?;
        let group = &database.root.groups[index];
        let index = entry_index(group, name)?
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "KeePass resource not found"))?;
        let entry = &group.entries[index];
        entry
            .password
            .with_revealed_bytes(|bytes| {
                if bytes.len() > MAX_VALUE * 2 {
                    return Err(Error::new(
                        ErrorKind::Provider,
                        "KeePass resource exceeds size limit",
                    ));
                }
                let mut decoded =
                    Zeroizing::new(STANDARD.decode(bytes).map_err(|_| {
                        Error::new(ErrorKind::Provider, "KeePass resource is invalid")
                    })?);
                if decoded.len() > MAX_VALUE {
                    return Err(Error::new(
                        ErrorKind::Provider,
                        "KeePass resource exceeds size limit",
                    ));
                }
                Ok(SecretValue::new(std::mem::take(&mut *decoded)))
            })
            .map_err(|_| {
                Error::new(
                    ErrorKind::Provider,
                    "KeePass resource could not be revealed",
                )
            })?
    }

    fn write_group_value(
        &self,
        kind: ResourceKind,
        vault: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<Metadata> {
        self.validate(vault, name)?;
        if bytes.len() > MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "resource exceeds size limit",
            ));
        }
        let encoded = Zeroizing::new(STANDARD.encode(bytes));
        self.rewrite(|database| {
            let index = match group_index(&database.root, kind)? {
                Some(i) => i,
                None => {
                    let mut group = Group::new(kind.group_name());
                    group.custom_data.set(GROUP_MARKER, kind.marker(), None);
                    database.root.groups.push(group);
                    database.root.groups.len() - 1
                }
            };
            set_password(&mut database.root.groups[index], name, &encoded)
        })
    }
    fn remove_value(
        &self,
        kind: Option<ResourceKind>,
        vault: &str,
        name: &str,
        options: &RemoveOptions,
    ) -> Result<()> {
        self.validate(vault, name)?;
        if options.version.is_some() || !options.query.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "unsupported KeePass removal option",
            ));
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::new(ErrorKind::Provider, "system clock is invalid"))?;
        let timestamp = i64::try_from(timestamp.as_secs())
            .map(KdbxTimestamp::from_unix_seconds)
            .map_err(|_| Error::new(ErrorKind::Provider, "system clock is invalid"))?;
        self.rewrite(|database| {
            let source = match kind {
                Some(kind) => group_index(&database.root, kind)?
                    .map(|index| &database.root.groups[index])
                    .ok_or_else(|| Error::new(ErrorKind::NotFound, "KeePass resource not found"))?,
                None => &database.root,
            };
            let source_id = source.id;
            let index = entry_index(source, name)?;
            if group_count(&database.root, source_id) != 1 {
                return Err(Error::new(
                    ErrorKind::Provider,
                    "ambiguous KeePass group UUID",
                ));
            }
            let bin_id = database.meta.recycle_bin_uuid;
            if bin_id != KdbxUuid::ZERO && group_count(&database.root, bin_id) != 1 {
                return Err(Error::new(
                    ErrorKind::Provider,
                    "invalid KeePass recycle bin",
                ));
            }
            if source_id == bin_id && bin_id != KdbxUuid::ZERO {
                return Err(Error::new(
                    ErrorKind::Provider,
                    "invalid KeePass recycle bin",
                ));
            }
            let entry = if let Some(index) = index {
                group_by_id_mut(&mut database.root, source_id)
                    .ok_or_else(|| Error::new(ErrorKind::Provider, "KeePass group not found"))?
                    .entries
                    .remove(index)
            } else if options.purge && bin_id != KdbxUuid::ZERO {
                let bin = group_by_id_mut(&mut database.root, bin_id).ok_or_else(|| {
                    Error::new(ErrorKind::Provider, "invalid KeePass recycle bin")
                })?;
                let matches: Vec<_> = bin
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| {
                        entry.title == name && entry.previous_parent_group_id == source_id
                    })
                    .map(|(index, _)| index)
                    .collect();
                if matches.len() > 1 {
                    return Err(Error::new(
                        ErrorKind::Provider,
                        "KeePass recycled entry is ambiguous",
                    ));
                }
                let index = matches
                    .first()
                    .copied()
                    .ok_or_else(|| Error::new(ErrorKind::NotFound, "KeePass resource not found"))?;
                bin.entries.remove(index)
            } else {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "KeePass resource not found",
                ));
            };
            if !options.purge && database.meta.recycle_bin_enabled {
                let bin_id = if bin_id == KdbxUuid::ZERO {
                    let bin = Group::new("Recycle Bin");
                    let id = bin.id;
                    database.root.groups.push(bin);
                    database.meta.recycle_bin_uuid = id;
                    database.meta.recycle_bin_changed = Some(timestamp);
                    id
                } else {
                    bin_id
                };
                let mut entry = entry;
                entry.previous_parent_group_id = source_id;
                entry.times.location_changed = timestamp;
                group_by_id_mut(&mut database.root, bin_id)
                    .ok_or_else(|| Error::new(ErrorKind::Provider, "invalid KeePass recycle bin"))?
                    .entries
                    .push(entry);
            } else {
                database
                    .deleted_objects
                    .retain(|deleted| deleted.id != entry.id);
                database.deleted_objects.push(DeletedObject {
                    id: entry.id,
                    deleted_at: timestamp,
                });
            }
            Ok(())
        })?;
        Ok(())
    }
}

impl Driver for KeepassDriver {
    fn supports(&self, capability: Capability) -> bool {
        matches!(
            capability,
            Capability::GetSecret
                | Capability::GetCertificate
                | Capability::GetKey
                | Capability::ListSecrets
                | Capability::ListCertificates
                | Capability::ListKeys
        ) || (matches!(
            capability,
            Capability::SetSecret
                | Capability::SetCertificate
                | Capability::SetKey
                | Capability::RemoveSecret
                | Capability::RemoveCertificate
                | Capability::RemoveKey
        ) && self.write_options.is_some())
    }

    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        self.list_names(vault, None)
    }
    fn list_certificates(&self, vault: &str) -> Result<Vec<String>> {
        self.list_names(vault, Some(ResourceKind::Certificate))
    }
    fn list_keys(&self, vault: &str) -> Result<Vec<String>> {
        self.list_names(vault, Some(ResourceKind::Key))
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.remove_value(None, vault, name, options)
    }
    fn remove_certificate(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.remove_value(Some(ResourceKind::Certificate), vault, name, options)
    }
    fn remove_key(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.remove_value(Some(ResourceKind::Key), vault, name, options)
    }

    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        self.validate(vault, name)?;
        if options.version.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "KeePass versions are not supported",
            ));
        }
        let file = File::open(&self.config.path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::new(ErrorKind::NotFound, "KeePass file not found")
            }
            std::io::ErrorKind::PermissionDenied => {
                Error::new(ErrorKind::PermissionDenied, "KeePass file access denied")
            }
            _ => Error::new(ErrorKind::Provider, "KeePass file could not be opened"),
        })?;
        let database = self.load(file)?;
        let index = entry_index(&database.root, name)?
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "KeePass entry not found"))?;
        let value = database.root.entries[index]
            .password
            .with_revealed_bytes(|bytes| SecretValue::new(bytes.to_vec()))
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass entry could not be revealed"))?;
        Ok(Response {
            value,
            metadata: Metadata::default(),
        })
    }
    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        self.validate(vault, name)?;
        if value.expose().len() > MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "secret exceeds size limit",
            ));
        }
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "KeePass password must be UTF-8"))?;
        self.rewrite(|database| set_password(&mut database.root, name, text))
    }
    fn set_certificate(&self, vault: &str, name: &str, value: &Certificate) -> Result<Metadata> {
        let wire = WireCertificate {
            data: value.data.clone(),
            content_type: value.content_type.clone(),
        };
        let bytes =
            Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| {
                Error::new(ErrorKind::Provider, "certificate could not be encoded")
            })?);
        self.write_group_value(ResourceKind::Certificate, vault, name, &bytes)
    }
    fn get_certificate(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<Certificate>> {
        let value = self.read_group_value(ResourceKind::Certificate, vault, name, options)?;
        let wire: WireCertificate = serde_json::from_slice(value.expose())
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass certificate is invalid"))?;
        Ok(Response {
            value: Certificate {
                data: wire.data,
                content_type: wire.content_type,
            },
            metadata: Metadata::default(),
        })
    }
    fn set_key(&self, vault: &str, name: &str, value: &Key) -> Result<Metadata> {
        let wire = WireKey {
            id: value.id.clone(),
            public_key: value.public_key.clone(),
            private_key: value.private_key.as_ref().map(|v| v.expose().to_vec()),
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&wire)
                .map_err(|_| Error::new(ErrorKind::Provider, "key could not be encoded"))?,
        );
        self.write_group_value(ResourceKind::Key, vault, name, &bytes)
    }
    fn get_key(&self, vault: &str, name: &str, options: &GetOptions) -> Result<Response<Key>> {
        let value = self.read_group_value(ResourceKind::Key, vault, name, options)?;
        let wire: WireKey = serde_json::from_slice(value.expose())
            .map_err(|_| Error::new(ErrorKind::Provider, "KeePass key is invalid"))?;
        Ok(Response {
            value: Key {
                id: wire.id.clone(),
                public_key: wire.public_key.clone(),
                private_key: wire
                    .private_key
                    .as_ref()
                    .map(|v| SecretValue::new(v.clone())),
            },
            metadata: Metadata::default(),
        })
    }
}
