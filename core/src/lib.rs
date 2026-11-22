//! Provider-neutral vault interfaces.
//!
//! Providers should use native APIs or libraries before resorting to CLI
//! processes. Capabilities describe operations, not authorization: a supported
//! operation can still be denied by the remote service.
#![forbid(unsafe_code)]

mod generate;
mod uri;
pub use generate::GenerationOptions;
pub use neotales_retry::{Delay, RetryPolicy};
pub use uri::{ResourceKind, VaultUri};

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock},
};

/// An operation a driver implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Capability {
    /// Read a secret.
    GetSecret,
    /// Write a secret.
    SetSecret,
    /// Ensure a secret exists.
    EnsureSecret,
    /// Replace metadata on a particular secret version.
    UpdateSecretMetadata,
    /// Read a certificate.
    GetCertificate,
    /// Write a certificate.
    SetCertificate,
    /// Read a key, including any exportable private material.
    GetKey,
    /// Write a key.
    SetKey,
    /// List secret names.
    ListSecrets,
    /// List certificate names.
    ListCertificates,
    /// List key names.
    ListKeys,
    /// Remove a secret.
    RemoveSecret,
    /// Remove a certificate.
    RemoveCertificate,
    /// Remove a key.
    RemoveKey,
}

impl Capability {
    fn label(self) -> &'static str {
        match self {
            Self::GetSecret => "get_secret",
            Self::SetSecret => "set_secret",
            Self::EnsureSecret => "ensure_secret",
            Self::UpdateSecretMetadata => "update_secret_metadata",
            Self::GetCertificate => "get_certificate",
            Self::SetCertificate => "set_certificate",
            Self::GetKey => "get_key",
            Self::SetKey => "set_key",
            Self::ListSecrets => "list_secrets",
            Self::ListCertificates => "list_certificates",
            Self::ListKeys => "list_keys",
            Self::RemoveSecret => "remove_secret",
            Self::RemoveCertificate => "remove_certificate",
            Self::RemoveKey => "remove_key",
        }
    }
}

fn record_operation<T>(operation: Capability, started: std::time::Instant, result: &Result<T>) {
    let outcome = if result.is_ok() { "success" } else { "failure" };
    metrics::counter!("neotales_vaults_operations_total", "operation" => operation.label(), "outcome" => outcome).increment(1);
    metrics::histogram!("neotales_vaults_operation_duration_seconds", "operation" => operation.label(), "outcome" => outcome).record(started.elapsed().as_secs_f64());
}

/// Common error categories. Only `Transient` is retried automatically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Invalid input or configuration.
    InvalidInput,
    /// The requested item does not exist.
    NotFound,
    /// Authentication failed.
    Authentication,
    /// Access was denied.
    PermissionDenied,
    /// The driver does not implement the operation.
    Unsupported,
    /// The operation may be attempted again.
    Transient,
    /// A provider error that should not automatically be retried.
    Provider,
}

/// A sanitized error. Drivers must not include secret values or credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    /// Classification used for retry decisions.
    pub kind: ErrorKind,
    /// Human-readable, sanitized explanation.
    pub message: String,
}

impl Error {
    /// Creates an error with a sanitized message.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
/// Result of a vault operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Secret bytes. Debug output is always redacted.
#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretValue(Vec<u8>);
impl SecretValue {
    /// Wraps bytes received from a provider.
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(value.into())
    }
    /// Explicitly exposes the bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

/// Common metadata returned with a resource.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Metadata {
    /// Version selected by the provider, if available.
    pub version: Option<String>,
    /// Version metadata when supplied by the provider.
    pub secret: Option<SecretMetadata>,
}

/// Metadata associated with a secret version.
///
/// Tags and expiry may be stored in plaintext by providers; never put secret
/// values in metadata. Expiry is an RFC 3339 timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretMetadata {
    /// Expiration time, or no expiration.
    pub expires_at: Option<String>,
    /// User-defined, non-secret tags.
    pub tags: BTreeMap<String, String>,
    /// Whether this version is enabled.
    pub enabled: bool,
    /// Whether this version is deleted.
    pub deleted: bool,
}
impl Default for SecretMetadata {
    fn default() -> Self {
        Self {
            expires_at: None,
            tags: BTreeMap::new(),
            enabled: true,
            deleted: false,
        }
    }
}

/// Options for writing a secret version.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SetSecretOptions {
    /// Version metadata. Providers reject non-default options they cannot honor.
    pub metadata: SecretMetadata,
}

/// A resource together with its metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response<T> {
    /// Resource value.
    pub value: T,
    /// Provider metadata.
    pub metadata: Metadata,
}

/// Certificate bytes in the provider's documented encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    /// Certificate data, not private-key material.
    pub data: Vec<u8>,
    /// Media type or provider-specific encoding, if known.
    pub content_type: Option<String>,
}

/// Key material. Private bytes are redacted in debug output and zeroized on drop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key {
    /// Provider key identifier.
    pub id: String,
    /// Public key bytes, when exportable.
    pub public_key: Option<Vec<u8>>,
    /// Exportable private key bytes, when provided by the driver.
    pub private_key: Option<SecretValue>,
}

/// Options shared by read operations.
#[derive(Clone, Debug, Default)]
pub struct GetOptions {
    /// Requested version, or the provider's current version when absent.
    pub version: Option<String>,
    /// Override the client and global retry policies for this call.
    pub retry: Option<RetryPolicy>,
}

/// Removal request. Providers reject options they cannot honor.
///
/// `purge` requests permanent removal; its absence does not promise a
/// recoverable deletion. Provider-specific query entries must not contain
/// credentials. Removal is never automatically retried.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemoveOptions {
    /// Request permanent deletion rather than provider-default removal.
    pub purge: bool,
    /// Restrict removal to a provider version, when supported.
    pub version: Option<String>,
    /// Provider-specific named options.
    pub query: BTreeMap<String, String>,
}

/// Driver boundary. Implementations own their provider-specific configuration.
///
/// A driver must return `Unsupported` for operations it does not implement.
pub trait Driver: Send + Sync {
    /// Whether this driver implements an operation.
    fn supports(&self, capability: Capability) -> bool;
    /// Whether the default `set_secret` can create an absent resource.
    fn can_create_secret(&self) -> bool {
        self.supports(Capability::SetSecret)
    }
    /// Return the current secret or create it if the provider reports not found.
    ///
    /// The default read-then-write fallback is not atomic across clients.
    /// Providers should override it with conditional creation when possible.
    /// After a write error, the outcome may be unknown.
    fn ensure_secret(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
    ) -> Result<Response<SecretValue>> {
        match self.get_secret(vault, name, &GetOptions::default()) {
            Ok(existing) => Ok(existing),
            Err(error) if error.kind == ErrorKind::NotFound => {
                let metadata = self.set_secret(vault, name, value)?;
                Ok(Response {
                    value: value.clone(),
                    metadata,
                })
            }
            Err(error) => Err(error),
        }
    }
    /// List secret names without returning values.
    fn list_secrets(&self, _vault: &str) -> Result<Vec<String>> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "secret listing is not supported",
        ))
    }
    /// List certificate names without returning values.
    fn list_certificates(&self, _vault: &str) -> Result<Vec<String>> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "certificate listing is not supported",
        ))
    }
    /// List key names without returning key material.
    fn list_keys(&self, _vault: &str) -> Result<Vec<String>> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "key listing is not supported",
        ))
    }
    /// Remove a secret once; an error may leave the outcome unknown.
    fn remove_secret(&self, _vault: &str, _name: &str, _options: &RemoveOptions) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "secret removal is not supported",
        ))
    }
    /// Remove a certificate once; an error may leave the outcome unknown.
    fn remove_certificate(
        &self,
        _vault: &str,
        _name: &str,
        _options: &RemoveOptions,
    ) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "certificate removal is not supported",
        ))
    }
    /// Remove a key once; an error may leave the outcome unknown.
    fn remove_key(&self, _vault: &str, _name: &str, _options: &RemoveOptions) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "key removal is not supported",
        ))
    }
    /// Fetches a secret.
    fn get_secret(
        &self,
        _vault: &str,
        _name: &str,
        _options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "secret reads are not supported",
        ))
    }
    /// Writes a secret. Implementations must describe their overwrite semantics.
    ///
    /// Errors may leave the outcome unknown. Callers must not blindly retry.
    fn set_secret(&self, _vault: &str, _name: &str, _value: &SecretValue) -> Result<Metadata> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "secret writes are not supported",
        ))
    }
    /// Writes a secret with version metadata when supported.
    fn set_secret_with(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
        options: &SetSecretOptions,
    ) -> Result<Metadata> {
        if options != &SetSecretOptions::default() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "secret metadata is not supported",
            ));
        }
        self.set_secret(vault, name, value)
    }
    /// Replaces metadata for a specific secret version.
    ///
    /// Implementations must authenticate the existing version before changing it.
    fn update_secret_metadata(
        &self,
        _vault: &str,
        _name: &str,
        _version: &str,
        _metadata: &SecretMetadata,
    ) -> Result<Metadata> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "secret metadata updates are not supported",
        ))
    }
    /// Fetches a certificate.
    fn get_certificate(
        &self,
        _vault: &str,
        _name: &str,
        _options: &GetOptions,
    ) -> Result<Response<Certificate>> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "certificate reads are not supported",
        ))
    }
    /// Writes a certificate once. The outcome can be unknown after failure.
    fn set_certificate(&self, _vault: &str, _name: &str, _value: &Certificate) -> Result<Metadata> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "certificate writes are not supported",
        ))
    }
    /// Fetches key metadata and, optionally, exportable key material.
    fn get_key(&self, _vault: &str, _name: &str, _options: &GetOptions) -> Result<Response<Key>> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "key reads are not supported",
        ))
    }
    /// Writes a key once. The outcome can be unknown after failure.
    fn set_key(&self, _vault: &str, _name: &str, _value: &Key) -> Result<Metadata> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "key writes are not supported",
        ))
    }
}

static GLOBAL_RETRY: RwLock<Option<RetryPolicy>> = RwLock::new(None);

/// Sets the process-wide fallback policy. `None` disables the fallback.
///
/// A method override wins over a client override, which wins over this policy.
pub fn set_global_retry_policy(policy: Option<RetryPolicy>) {
    *GLOBAL_RETRY.write().unwrap_or_else(|e| e.into_inner()) = policy;
}

/// Returns the current process-wide fallback policy.
pub fn global_retry_policy() -> Option<RetryPolicy> {
    *GLOBAL_RETRY.read().unwrap_or_else(|e| e.into_inner())
}

/// Client over a configured driver. Calls are synchronous and may block.
#[derive(Clone)]
pub struct Client {
    driver: Arc<dyn Driver>,
    retry: Option<RetryPolicy>,
}
/// Return an existing secret or create it using the supplied value.
///
/// The fallback is not atomic across clients. A transient error is retried
/// according to the configured policy, with another read before each write.
pub trait EnsureSecret {
    /// Generate and create a secret only if it is absent.
    fn ensure_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GenerationOptions,
    ) -> Result<Response<SecretValue>>;
    /// Return the current secret, or create and return `value` if absent.
    fn ensure_value(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
    ) -> Result<Response<SecretValue>>;
}

impl EnsureSecret for Client {
    fn ensure_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GenerationOptions,
    ) -> Result<Response<SecretValue>> {
        options.validate()?;
        match self.get(vault, name) {
            Ok(existing) => Ok(existing),
            Err(error) if error.kind == ErrorKind::NotFound => {
                let value = options.generate()?;
                self.ensure_value(vault, name, &value)
            }
            Err(error) => Err(error),
        }
    }
    fn ensure_value(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
    ) -> Result<Response<SecretValue>> {
        if !self.supports(Capability::EnsureSecret) {
            return self.get(vault, name);
        }
        self.execute(
            Capability::EnsureSecret,
            &GetOptions::default(),
            || match self.driver.get_secret(vault, name, &GetOptions::default()) {
                Ok(existing) => Ok(existing),
                Err(error) if error.kind == ErrorKind::NotFound => {
                    self.driver.ensure_secret(vault, name, value)
                }
                Err(error) => Err(error),
            },
        )
    }
}

impl Client {
    /// Creates a client over a configured driver.
    pub fn new(driver: impl Driver + 'static) -> Self {
        Self {
            driver: Arc::new(driver),
            retry: None,
        }
    }
    /// Creates a client from a shared driver.
    pub fn from_shared(driver: Arc<dyn Driver>) -> Self {
        Self {
            driver,
            retry: None,
        }
    }
    /// Sets the client-level retry policy.
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = Some(retry);
        self
    }
    /// Checks the driver's declared support.
    pub fn supports(&self, capability: Capability) -> bool {
        self.driver.supports(capability)
            || (capability == Capability::EnsureSecret
                && self.driver.supports(Capability::GetSecret)
                && self.driver.can_create_secret())
    }
    /// List secret names.
    pub fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        self.execute(Capability::ListSecrets, &GetOptions::default(), || {
            self.driver.list_secrets(vault)
        })
    }
    /// List certificate names.
    pub fn list_certificates(&self, vault: &str) -> Result<Vec<String>> {
        self.execute(Capability::ListCertificates, &GetOptions::default(), || {
            self.driver.list_certificates(vault)
        })
    }
    /// List key names.
    pub fn list_keys(&self, vault: &str) -> Result<Vec<String>> {
        self.execute(Capability::ListKeys, &GetOptions::default(), || {
            self.driver.list_keys(vault)
        })
    }
    /// Remove a secret without automatic retries.
    pub fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.execute_write(Capability::RemoveSecret, || {
            self.driver.remove_secret(vault, name, options)
        })
    }
    /// Remove a certificate without automatic retries.
    pub fn remove_certificate(
        &self,
        vault: &str,
        name: &str,
        options: &RemoveOptions,
    ) -> Result<()> {
        self.execute_write(Capability::RemoveCertificate, || {
            self.driver.remove_certificate(vault, name, options)
        })
    }
    /// Remove a key without automatic retries.
    pub fn remove_key(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.execute_write(Capability::RemoveKey, || {
            self.driver.remove_key(vault, name, options)
        })
    }
    /// Reads the current secret.
    pub fn get(&self, vault: &str, name: &str) -> Result<Response<SecretValue>> {
        self.get_with(vault, name, &GetOptions::default())
    }
    /// Reads a secret with options.
    pub fn get_with(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        self.execute(Capability::GetSecret, options, || {
            self.driver.get_secret(vault, name, options)
        })
    }
    /// Writes a secret once, without automatic retries.
    ///
    /// A failed write can have an indeterminate outcome. Check the provider
    /// before attempting it again.
    pub fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        self.execute_write(Capability::SetSecret, || {
            self.driver.set_secret(vault, name, value)
        })
    }
    /// Writes a secret with options once, without automatic retries.
    pub fn set_secret_with(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
        options: &SetSecretOptions,
    ) -> Result<Metadata> {
        self.execute_write(Capability::SetSecret, || {
            self.driver.set_secret_with(vault, name, value, options)
        })
    }
    /// Replaces metadata for a specific version once, without automatic retries.
    ///
    /// The entire metadata object is replaced. An empty version is invalid.
    pub fn update_secret_metadata(
        &self,
        vault: &str,
        name: &str,
        version: &str,
        metadata: &SecretMetadata,
    ) -> Result<Metadata> {
        if version.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "version must not be empty",
            ));
        }
        self.execute_write(Capability::UpdateSecretMetadata, || {
            self.driver
                .update_secret_metadata(vault, name, version, metadata)
        })
    }
    /// Reads a certificate with options.
    pub fn get_certificate(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<Certificate>> {
        self.execute(Capability::GetCertificate, options, || {
            self.driver.get_certificate(vault, name, options)
        })
    }
    /// Writes a certificate once, without automatic retries.
    pub fn set_certificate(
        &self,
        vault: &str,
        name: &str,
        value: &Certificate,
    ) -> Result<Metadata> {
        self.execute_write(Capability::SetCertificate, || {
            self.driver.set_certificate(vault, name, value)
        })
    }
    /// Reads a key with options.
    pub fn get_key(&self, vault: &str, name: &str, options: &GetOptions) -> Result<Response<Key>> {
        self.execute(Capability::GetKey, options, || {
            self.driver.get_key(vault, name, options)
        })
    }
    /// Writes a key once, without automatic retries.
    pub fn set_key(&self, vault: &str, name: &str, value: &Key) -> Result<Metadata> {
        self.execute_write(Capability::SetKey, || {
            self.driver.set_key(vault, name, value)
        })
    }
    fn execute_write<T>(
        &self,
        capability: Capability,
        op: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let started = std::time::Instant::now();
        let span = tracing::debug_span!("vault_operation", operation = ?capability);
        let _entered = span.enter();
        let result = if self.supports(capability) {
            op()
        } else {
            Err(Error::new(
                ErrorKind::Unsupported,
                "operation is not supported",
            ))
        };
        record_operation(capability, started, &result);
        result
    }
    fn execute<T>(
        &self,
        capability: Capability,
        options: &GetOptions,
        mut op: impl FnMut() -> Result<T>,
    ) -> Result<T> {
        let started = std::time::Instant::now();
        let span = tracing::debug_span!("vault_operation", operation = ?capability);
        let _entered = span.enter();
        if !self.supports(capability) {
            let result = Err(Error::new(
                ErrorKind::Unsupported,
                "operation is not supported",
            ));
            record_operation::<T>(capability, started, &result);
            return result;
        }
        let policy = options.retry.or(self.retry).or_else(global_retry_policy);
        let result = match policy {
            Some(policy) => {
                // This source only spaces retries; it is not used for security.
                let mut state = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64
                    | 1;
                let pipeline =
                    neotales_resilience::Pipeline::new([neotales_resilience::Policy::retry(
                        policy,
                    )]);
                let outcome = pipeline.execute(
                    |_| op(),
                    &neotales_resilience::Exec::new().idempotent(),
                    |classified| match classified {
                        neotales_resilience::Classified::Failure(error) if error.kind == ErrorKind::Transient => neotales_resilience::Class::Handled,
                        _ => neotales_resilience::Class::Unhandled,
                    },
                    |event| {
                        if event.reason == neotales_resilience::Reason::Retry {
                            metrics::counter!("neotales_vaults_retries_total", "operation" => capability.label()).increment(1);
                            tracing::debug!(attempt = event.attempt, "retrying vault operation");
                        }
                    },
                    || {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state
                    },
                    std::thread::sleep,
                );
                match outcome {
                    neotales_resilience::Outcome::Success { value, .. } => Ok(value),
                    neotales_resilience::Outcome::Failure { error, .. } => Err(error),
                    _ => Err(Error::new(
                        ErrorKind::Provider,
                        "read resilience policy did not complete",
                    )),
                }
            }
            None => op(),
        };
        record_operation(capability, started, &result);
        result
    }
}

/// Client name for secret-oriented callers.
pub type SecretsClient = Client;
