//! Read and write named secrets in the operating system credential store.
#![forbid(unsafe_code)]

use neotales_vaults_core::{
    Capability, Driver, Error, ErrorKind, GetOptions, Metadata, RemoveOptions, Response, Result,
    SecretValue,
};
use sha2::{Digest, Sha256};

/// Configuration for the native credential store.
#[derive(Clone, Debug)]
pub struct Config {
    /// Service name in the native credential store.
    pub service: String,
}

/// OS credential-store driver. Values are scoped by vault and secret name.
#[derive(Clone, Debug)]
pub struct OsDriver {
    config: Config,
}

impl OsDriver {
    /// Creates a driver. Service names must not be empty.
    pub fn new(config: Config) -> Result<Self> {
        if config.service.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "service must not be empty",
            ));
        }
        Ok(Self { config })
    }

    fn account(vault: &str, name: &str) -> Result<String> {
        if vault.is_empty() || name.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "vault and secret name must not be empty",
            ));
        }
        let mut hash = Sha256::new();
        hash.update(b"neotales-vaults-os-v1\0");
        for part in [vault, name] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn native_entry(service: &str, account: &str) -> Result<keyring::Entry> {
    #[cfg(target_os = "linux")]
    let builder = keyring::secret_service::default_credential_builder();
    #[cfg(target_os = "macos")]
    let builder = keyring::macos::default_credential_builder();
    #[cfg(target_os = "windows")]
    let builder = keyring::windows::default_credential_builder();
    let credential = builder.build(None, service, account).map_err(map_error)?;
    Ok(keyring::Entry::new_with_credential(credential))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn map_error(error: keyring::Error) -> Error {
    match error {
        keyring::Error::NoEntry => Error::new(ErrorKind::NotFound, "OS credential not found"),
        keyring::Error::NoStorageAccess(_) => Error::new(
            ErrorKind::PermissionDenied,
            "OS credential store is locked or inaccessible",
        ),
        _ => Error::new(ErrorKind::Provider, "OS credential store operation failed"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn native_get(service: &str, account: &str) -> Result<Vec<u8>> {
    native_entry(service, account)?
        .get_secret()
        .map_err(map_error)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn native_set(service: &str, account: &str, value: &[u8]) -> Result<()> {
    native_entry(service, account)?
        .set_secret(value)
        .map_err(map_error)
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn native_remove(service: &str, account: &str) -> Result<()> {
    native_entry(service, account)?
        .delete_credential()
        .map_err(map_error)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn native_get(_: &str, _: &str) -> Result<Vec<u8>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "OS credential store is unavailable on this platform",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn native_set(_: &str, _: &str, _: &[u8]) -> Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "OS credential store is unavailable on this platform",
    ))
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn native_remove(_: &str, _: &str) -> Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "OS credential store is unavailable on this platform",
    ))
}

impl Driver for OsDriver {
    fn supports(&self, capability: Capability) -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) && matches!(
            capability,
            Capability::GetSecret | Capability::SetSecret | Capability::RemoveSecret
        )
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        if options.purge || options.version.is_some() || !options.query.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "OS credential store does not support removal options",
            ));
        }
        let account = Self::account(vault, name)?;
        native_remove(&self.config.service, &account)
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        if options.version.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "OS credential store does not support versions",
            ));
        }
        let account = Self::account(vault, name)?;
        Ok(Response {
            value: SecretValue::new(native_get(&self.config.service, &account)?),
            metadata: Metadata::default(),
        })
    }
    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        let account = Self::account(vault, name)?;
        native_set(&self.config.service, &account, value.expose())?;
        Ok(Metadata::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_and_capabilities() {
        let d = OsDriver::new(Config {
            service: "example".into(),
        })
        .unwrap();
        assert_ne!(
            OsDriver::account("ab", "c").unwrap(),
            OsDriver::account("a", "bc").unwrap()
        );
        assert!(!d.supports(Capability::GetCertificate));
        assert_eq!(
            d.get_secret(
                "v",
                "x",
                &GetOptions {
                    version: Some("1".into()),
                    retry: None
                }
            )
            .unwrap_err()
            .kind,
            ErrorKind::Unsupported
        );
    }
}
