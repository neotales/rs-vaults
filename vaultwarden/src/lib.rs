//! Read and optionally update Vaultwarden login passwords through the Bitwarden CLI.
#![forbid(unsafe_code)]

use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use neotales_vaults_core::{
    Capability, Driver, Error, ErrorKind, GetOptions, Metadata, RemoveOptions, Response, Result,
    SecretValue,
};
use serde::Deserialize;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};
use url::Url;
use wait_timeout::ChildExt;
use zeroize::Zeroize;
use zeroize::Zeroizing;

const MAX_OUTPUT: u64 = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

/// Configuration for an already unlocked Bitwarden CLI profile.
#[derive(Clone, Debug)]
pub struct Config {
    /// Registered vault name.
    pub vault: String,
    /// Path to the Bitwarden `bw` executable.
    pub command: PathBuf,
    /// Expected HTTPS Vaultwarden server URL.
    pub server: String,
    /// Expected Bitwarden account UUID.
    pub account_id: String,
    /// Explicit unlocked CLI session. Passed to the process in `BW_SESSION`.
    pub session: SecretValue,
}

/// Driver using the CLI's local decrypted cache.
///
/// The caller manages login, unlock, and sync. CLI state may be stale.
/// Name selection is restricted to item UUIDs to avoid ambiguous matches.
#[derive(Clone, Debug)]
pub struct VaultwardenDriver {
    config: Config,
    server: Url,
    account: uuid::Uuid,
    write_lock: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    server_url: Option<String>,
    user_id: Option<String>,
    status: String,
}

#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct Login {
    password: Option<String>,
}
#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct Item {
    id: String,
    #[serde(rename = "type")]
    item_type: u64,
    login: Option<Login>,
    deleted_date: Option<String>,
}

fn error(kind: ErrorKind, message: &'static str) -> Error {
    Error::new(kind, message)
}
fn parse_uuid(value: &str) -> Result<uuid::Uuid> {
    let uuid =
        uuid::Uuid::parse_str(value).map_err(|_| error(ErrorKind::InvalidInput, "invalid UUID"))?;
    if uuid.is_nil() || uuid.to_string() != value.to_ascii_lowercase() {
        return Err(error(ErrorKind::InvalidInput, "invalid UUID"));
    }
    Ok(uuid)
}

impl VaultwardenDriver {
    /// Validates the requested server, account, and session without starting the CLI.
    pub fn new(config: Config) -> Result<Self> {
        let server = Url::parse(&config.server)
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid Vaultwarden server"))?;
        if config.vault.is_empty()
            || config.command.as_os_str().is_empty()
            || server.scheme() != "https"
            || server.host_str().is_none()
            || !server.username().is_empty()
            || server.password().is_some()
            || server.query().is_some()
            || server.fragment().is_some()
        {
            return Err(error(
                ErrorKind::InvalidInput,
                "invalid Vaultwarden configuration",
            ));
        }
        let account = parse_uuid(&config.account_id)?;
        let session = std::str::from_utf8(config.session.expose())
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid CLI session"))?;
        if session.is_empty() || session.chars().any(char::is_control) {
            return Err(error(ErrorKind::InvalidInput, "invalid CLI session"));
        }
        Ok(Self {
            config,
            server,
            account,
            write_lock: None,
        })
    }

    /// Enables updates to existing items using a shared advisory lock path.
    ///
    /// Cooperating writers must use the same lock path. This does not protect
    /// against external clients, which can overwrite or race with this update.
    /// The driver syncs before reading the item, then rewrites the whole item.
    pub fn with_write_lock(mut self, path: PathBuf) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(error(
                ErrorKind::InvalidInput,
                "write lock path must not be empty",
            ));
        }
        self.write_lock = Some(path);
        Ok(self)
    }

    fn acquire_write_lock(&self) -> Result<File> {
        let path = self
            .write_lock
            .as_ref()
            .ok_or_else(|| error(ErrorKind::Unsupported, "Vaultwarden writes are disabled"))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|_| error(ErrorKind::Provider, "Vaultwarden lock could not be opened"))?;
        file.lock_exclusive().map_err(|_| {
            error(
                ErrorKind::Provider,
                "Vaultwarden lock could not be acquired",
            )
        })?;
        Ok(file)
    }

    fn run(&self, args: &[&str]) -> Result<Zeroizing<Vec<u8>>> {
        let session = std::str::from_utf8(self.config.session.expose()).expect("validated session");
        let mut child = Command::new(&self.config.command)
            .arg("--nointeraction")
            .args(args)
            .env("BW_SESSION", session)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                Error::new(
                    ErrorKind::Provider,
                    format!("Bitwarden CLI could not be started ({:?})", e.kind()),
                )
            })?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| error(ErrorKind::Provider, "Bitwarden CLI output unavailable"))?;
        let (tx, rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut bytes = Zeroizing::new(Vec::new());
            let result = output.take(MAX_OUTPUT + 1).read_to_end(&mut bytes);
            let _ = tx.send(result.map(|_| bytes));
        });
        let status = match child.wait_timeout(TIMEOUT) {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error(ErrorKind::Provider, "Bitwarden CLI timed out"));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error(ErrorKind::Provider, "Bitwarden CLI failed"));
            }
        };
        if !status.success() {
            return Err(error(ErrorKind::Provider, "Bitwarden CLI failed"));
        }
        let bytes = rx
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| error(ErrorKind::Provider, "Bitwarden CLI output timed out"))?
            .map_err(|_| {
                error(
                    ErrorKind::Provider,
                    "Bitwarden CLI output could not be read",
                )
            })?;
        if bytes.len() as u64 > MAX_OUTPUT {
            return Err(error(
                ErrorKind::Provider,
                "Bitwarden CLI output exceeds size limit",
            ));
        }
        Ok(bytes)
    }

    fn check_profile(&self) -> Result<()> {
        let output = self.run(&["status"])?;
        let status: Status = serde_json::from_slice(&output)
            .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden CLI status"))?;
        let server = status
            .server_url
            .as_deref()
            .ok_or_else(|| error(ErrorKind::Provider, "Bitwarden CLI server is missing"))?;
        let server = Url::parse(server)
            .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden CLI server"))?;
        let user = status.user_id.as_deref().and_then(|s| parse_uuid(s).ok());
        if server.as_str().trim_end_matches('/') != self.server.as_str().trim_end_matches('/')
            || user != Some(self.account)
            || status.status != "unlocked"
        {
            return Err(error(
                ErrorKind::PermissionDenied,
                "Bitwarden CLI profile does not match the configured unlocked account",
            ));
        }
        Ok(())
    }

    fn edit(&self, id: &str, input: Zeroizing<Vec<u8>>) -> Result<()> {
        let session = std::str::from_utf8(self.config.session.expose()).expect("validated session");
        let mut child = Command::new(&self.config.command)
            .args(["--nointeraction", "edit", "item", id])
            .env("BW_SESSION", session)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                Error::new(
                    ErrorKind::Provider,
                    format!("Bitwarden CLI could not be started ({:?})", e.kind()),
                )
            })?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| error(ErrorKind::Provider, "Bitwarden CLI input unavailable"))?;
        let (tx, rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = tx.send(stdin.write_all(&input));
        });
        let status = match child.wait_timeout(TIMEOUT) {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error(
                    ErrorKind::Provider,
                    "Bitwarden CLI write timed out; outcome may be unknown",
                ));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error(
                    ErrorKind::Provider,
                    "Bitwarden CLI write failed; outcome may be unknown",
                ));
            }
        };
        if !status.success() || !matches!(rx.recv_timeout(Duration::from_secs(1)), Ok(Ok(()))) {
            return Err(error(
                ErrorKind::Provider,
                "Bitwarden CLI write failed; outcome may be unknown",
            ));
        }
        Ok(())
    }
}

// CLI item JSON contains passwords and may contain other confidential fields.
struct SecretJson(serde_json::Value);
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn clear(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(s) => s.zeroize(),
                serde_json::Value::Array(values) => values.iter_mut().for_each(clear),
                serde_json::Value::Object(values) => values.values_mut().for_each(clear),
                _ => {}
            }
        }
        clear(&mut self.0);
    }
}

impl Driver for VaultwardenDriver {
    fn can_create_secret(&self) -> bool {
        false
    }
    fn supports(&self, capability: Capability) -> bool {
        matches!(capability, Capability::GetSecret | Capability::ListSecrets)
            || (matches!(capability, Capability::SetSecret | Capability::RemoveSecret)
                && self.write_lock.is_some())
    }
    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        if vault != self.config.vault {
            return Err(error(ErrorKind::NotFound, "vault is not configured"));
        }
        self.check_profile()?;
        let output = self.run(&["list", "items"])?;
        let items: Vec<Item> = serde_json::from_slice(&output)
            .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden item list"))?;
        let mut ids = Vec::new();
        for item in items {
            if item.item_type == 1
                && item
                    .login
                    .as_ref()
                    .and_then(|login| login.password.as_ref())
                    .is_some()
                && item.deleted_date.as_deref().is_none_or(str::is_empty)
            {
                ids.push(
                    parse_uuid(&item.id)
                        .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden item ID"))?
                        .to_string(),
                );
            }
        }
        Ok(ids)
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        if vault != self.config.vault {
            return Err(error(ErrorKind::NotFound, "vault is not configured"));
        }
        if options.version.is_some() || !options.query.is_empty() {
            return Err(error(
                ErrorKind::Unsupported,
                "unsupported Bitwarden removal option",
            ));
        }
        let id = parse_uuid(name)?;
        let _lock = self.acquire_write_lock()?;
        self.check_profile()?;
        self.run(&["sync"]).map_err(|_| {
            error(
                ErrorKind::Provider,
                "Bitwarden sync failed; no removal attempted",
            )
        })?;
        self.check_profile()?;
        let mut found = false;
        for trash in [false, true] {
            if trash && !options.purge {
                break;
            }
            let output = if trash {
                self.run(&["list", "items", "--trash"])?
            } else {
                self.run(&["list", "items"])?
            };
            let items: Vec<Item> = serde_json::from_slice(&output)
                .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden item list"))?;
            for item in items {
                let actual = parse_uuid(&item.id)
                    .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden item ID"))?;
                if actual == id {
                    if found {
                        return Err(error(ErrorKind::Provider, "duplicate Bitwarden item ID"));
                    }
                    if item.item_type != 1
                        || item
                            .login
                            .as_ref()
                            .and_then(|login| login.password.as_ref())
                            .is_none()
                    {
                        return Err(error(
                            ErrorKind::Unsupported,
                            "Bitwarden item is not a login password",
                        ));
                    }
                    found = true;
                }
            }
        }
        if !found {
            return Err(error(ErrorKind::NotFound, "Bitwarden item not found"));
        }
        self.check_profile()?;
        let id = id.to_string();
        let result = if options.purge {
            self.run(&["delete", "item", &id, "--permanent"])
        } else {
            self.run(&["delete", "item", &id])
        };
        result.map_err(|_| {
            error(
                ErrorKind::Provider,
                "Bitwarden removal failed; outcome may be unknown",
            )
        })?;
        Ok(())
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        if vault != self.config.vault {
            return Err(error(ErrorKind::NotFound, "vault is not configured"));
        }
        if options.version.is_some() {
            return Err(error(
                ErrorKind::Unsupported,
                "Vaultwarden versions are not supported",
            ));
        }
        let id = parse_uuid(name)?;
        self.check_profile()?;
        let output = self.run(&["get", "item", &id.to_string()])?;
        let mut item: Item = serde_json::from_slice(&output)
            .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden item"))?;
        let returned_id = parse_uuid(&item.id)
            .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden item"))?;
        if id != returned_id {
            return Err(error(
                ErrorKind::Provider,
                "Bitwarden returned a different item",
            ));
        }
        if item
            .deleted_date
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(error(ErrorKind::NotFound, "Bitwarden item is deleted"));
        }
        if item.item_type != 1 {
            return Err(error(
                ErrorKind::Unsupported,
                "Bitwarden item is not a login",
            ));
        }
        let password = item
            .login
            .as_mut()
            .and_then(|login| login.password.take())
            .ok_or_else(|| error(ErrorKind::NotFound, "Bitwarden item has no login password"))?;
        Ok(Response {
            value: SecretValue::new(password.into_bytes()),
            metadata: Metadata::default(),
        })
    }

    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        if vault != self.config.vault {
            return Err(error(ErrorKind::NotFound, "vault is not configured"));
        }
        if value.expose().len() > 1024 * 1024 {
            return Err(error(ErrorKind::InvalidInput, "secret exceeds size limit"));
        }
        let value = std::str::from_utf8(value.expose()).map_err(|_| {
            error(
                ErrorKind::InvalidInput,
                "Vaultwarden password must be UTF-8",
            )
        })?;
        let id = parse_uuid(name)?.to_string();
        let _lock = self.acquire_write_lock()?;
        self.check_profile()?;
        self.run(&["sync"]).map_err(|_| {
            error(
                ErrorKind::Provider,
                "Bitwarden sync failed; no write attempted",
            )
        })?;
        self.check_profile()?;
        let output = self.run(&["get", "item", &id])?;
        let mut item = SecretJson(
            serde_json::from_slice(&output)
                .map_err(|_| error(ErrorKind::Provider, "invalid Bitwarden item"))?,
        );
        let actual = item
            .0
            .get("id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| parse_uuid(s).ok());
        if actual != Some(parse_uuid(&id)?) {
            return Err(error(
                ErrorKind::Provider,
                "Bitwarden returned a different item",
            ));
        }
        match item.0.get("deletedDate") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(value)) if value.is_empty() => {}
            Some(serde_json::Value::String(_)) => {
                return Err(error(ErrorKind::NotFound, "Bitwarden item is deleted"));
            }
            Some(_) => return Err(error(ErrorKind::Provider, "invalid Bitwarden item")),
        }
        if item.0.get("type").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(error(
                ErrorKind::Unsupported,
                "Bitwarden item is not a login",
            ));
        }
        let login = item
            .0
            .get_mut("login")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| error(ErrorKind::Unsupported, "Bitwarden item is not a login"))?;
        if login
            .get("password")
            .is_some_and(|password| !password.is_null() && !password.is_string())
        {
            return Err(error(
                ErrorKind::Provider,
                "invalid Bitwarden login password",
            ));
        }
        if let Some(serde_json::Value::String(old)) = login.get_mut("password") {
            old.zeroize();
        }
        login.insert(
            "password".into(),
            serde_json::Value::String(value.to_owned()),
        );
        let json = Zeroizing::new(
            serde_json::to_vec(&item.0)
                .map_err(|_| error(ErrorKind::Provider, "Bitwarden item could not be encoded"))?,
        );
        if json.len() > MAX_OUTPUT as usize {
            return Err(error(
                ErrorKind::InvalidInput,
                "Bitwarden item exceeds size limit",
            ));
        }
        let encoded = Zeroizing::new(STANDARD.encode(&*json).into_bytes());
        self.check_profile()?;
        self.edit(&id, encoded)?;
        Ok(Metadata::default())
    }
}
