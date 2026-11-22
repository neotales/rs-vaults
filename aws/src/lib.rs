//! AWS Secrets Manager provider using the AWS SDK.
#![forbid(unsafe_code)]

use aws_sdk_secretsmanager::{error::ProvideErrorMetadata, primitives::Blob};
use aws_smithy_types::retry::RetryConfig;
use neotales_vaults_core::{
    Capability, Driver, Error, ErrorKind, GetOptions, Metadata, RemoveOptions, Response, Result,
    SecretValue,
};
use std::{future::Future, time::Duration};

/// Configuration for one registered AWS Secrets Manager vault.
#[derive(Clone)]
pub struct Config {
    /// Name by which the vault is registered.
    pub vault: String,
    /// AWS SDK shared configuration, including region and credentials provider.
    pub sdk: aws_types::SdkConfig,
    /// Permit an HTTP custom endpoint only for a literal loopback IP.
    pub allow_http_loopback: bool,
}

/// AWS Secrets Manager driver. Writes update existing provisioned secrets only.
pub struct AwsDriver {
    vault: String,
    client: aws_sdk_secretsmanager::Client,
}

/// Builds AWS removal options with a seven-to-thirty-day recovery window.
pub fn removal_with_recovery_days(days: u8) -> Result<RemoveOptions> {
    if !(7..=30).contains(&days) {
        return Err(err(
            ErrorKind::InvalidInput,
            "AWS recovery window must be 7 to 30 days",
        ));
    }
    let mut options = RemoveOptions::default();
    options
        .query
        .insert("recovery_window_days".into(), days.to_string());
    Ok(options)
}

fn err(kind: ErrorKind, message: &'static str) -> Error {
    Error::new(kind, message)
}
fn valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_+=.@-".contains(&b))
}
fn execute<T: Send>(f: impl Future<Output = Result<T>> + Send) -> Result<T> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| err(ErrorKind::Provider, "AWS runtime unavailable"))?;
                runtime.block_on(f)
            })
            .join()
            .map_err(|_| err(ErrorKind::Provider, "AWS request worker failed"))?
    })
}
fn kind(code: Option<&str>) -> ErrorKind {
    match code {
        Some("ResourceNotFoundException") => ErrorKind::NotFound,
        Some("AccessDeniedException" | "AccessDenied") => ErrorKind::PermissionDenied,
        Some("UnrecognizedClientException" | "InvalidClientTokenId" | "ExpiredTokenException") => {
            ErrorKind::Authentication
        }
        Some("ThrottlingException" | "InternalServiceError" | "ServiceUnavailableException") => {
            ErrorKind::Transient
        }
        _ => ErrorKind::Provider,
    }
}
impl AwsDriver {
    /// Create the service client. SDK retry is disabled even if enabled globally.
    pub fn new(config: Config) -> Result<Self> {
        if config.vault.is_empty() || config.sdk.region().is_none() {
            return Err(err(
                ErrorKind::InvalidInput,
                "AWS vault and region are required",
            ));
        }
        if let Some(endpoint) = config.sdk.endpoint_url() {
            let url = url::Url::parse(endpoint)
                .map_err(|_| err(ErrorKind::InvalidInput, "invalid AWS endpoint"))?;
            let loopback = url
                .host_str()
                .and_then(|s| s.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback());
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !(url.scheme() == "https"
                    || (config.allow_http_loopback && url.scheme() == "http" && loopback))
            {
                return Err(err(
                    ErrorKind::InvalidInput,
                    "invalid or insecure AWS endpoint",
                ));
            }
        }
        let sdk = aws_sdk_secretsmanager::config::Builder::from(&config.sdk)
            .retry_config(RetryConfig::disabled())
            .timeout_config(
                aws_smithy_types::timeout::TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(20))
                    .build(),
            )
            .build();
        Ok(Self {
            vault: config.vault,
            client: aws_sdk_secretsmanager::Client::from_conf(sdk),
        })
    }
    fn check(&self, vault: &str, name: &str) -> Result<()> {
        if vault != self.vault {
            return Err(err(ErrorKind::NotFound, "vault is not configured"));
        }
        if !valid(name) {
            return Err(err(ErrorKind::InvalidInput, "invalid AWS secret name"));
        }
        Ok(())
    }
}
impl Driver for AwsDriver {
    fn supports(&self, capability: Capability) -> bool {
        matches!(
            capability,
            Capability::GetSecret
                | Capability::SetSecret
                | Capability::EnsureSecret
                | Capability::ListSecrets
                | Capability::RemoveSecret
        )
    }
    fn ensure_secret(
        &self,
        vault: &str,
        name: &str,
        value: &SecretValue,
    ) -> Result<Response<SecretValue>> {
        self.check(vault, name)?;
        if value.expose().len() > 65536 {
            return Err(err(
                ErrorKind::InvalidInput,
                "AWS secret exceeds size limit",
            ));
        }
        let request = self
            .client
            .create_secret()
            .name(name)
            .secret_binary(Blob::new(value.expose().to_vec()));
        let created = execute(async move {
            match request.send().await {
                Ok(output) => Ok(Some(output.version_id().map(str::to_owned))),
                Err(e)
                    if e.as_service_error().and_then(|s| s.code())
                        == Some("ResourceExistsException") =>
                {
                    Ok(None)
                }
                Err(
                    aws_sdk_secretsmanager::error::SdkError::TimeoutError(_)
                    | aws_sdk_secretsmanager::error::SdkError::DispatchFailure(_)
                    | aws_sdk_secretsmanager::error::SdkError::ResponseError(_),
                ) => Err(err(
                    ErrorKind::Transient,
                    "AWS create failed; outcome may be unknown",
                )),
                Err(e) => Err(err(
                    kind(e.as_service_error().and_then(|s| s.code())),
                    "AWS create failed; outcome may be unknown",
                )),
            }
        })?;
        match created {
            Some(version) => Ok(Response {
                value: value.clone(),
                metadata: Metadata {
                    version,
                    ..Default::default()
                },
            }),
            None => self.get_secret(vault, name, &GetOptions::default()),
        }
    }
    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        if vault != self.vault {
            return Err(err(ErrorKind::NotFound, "vault is not configured"));
        }
        execute(async {
            let mut names = Vec::new();
            let mut token = None;
            let mut seen = std::collections::HashSet::new();
            loop {
                let output = self
                    .client
                    .list_secrets()
                    .set_next_token(token)
                    .send()
                    .await
                    .map_err(|e| {
                        err(
                            kind(e.as_service_error().and_then(|s| s.code())),
                            "AWS secret listing failed",
                        )
                    })?;
                for entry in output.secret_list() {
                    let name = entry
                        .name()
                        .ok_or_else(|| err(ErrorKind::Provider, "AWS secret name missing"))?;
                    names.push(name.to_owned());
                }
                match output.next_token() {
                    Some(next) if !next.is_empty() && seen.insert(next.to_owned()) => {
                        token = Some(next.to_owned())
                    }
                    Some(_) => {
                        return Err(err(ErrorKind::Provider, "invalid AWS pagination token"));
                    }
                    None => break,
                }
            }
            Ok(names)
        })
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        self.check(vault, name)?;
        if options.version.is_some()
            || options
                .query
                .keys()
                .any(|key| key != "recovery_window_days")
        {
            return Err(err(
                ErrorKind::Unsupported,
                "unsupported AWS removal option",
            ));
        }
        let days = options
            .query
            .get("recovery_window_days")
            .map(|value| {
                value
                    .parse::<i64>()
                    .ok()
                    .filter(|days| (7..=30).contains(days))
                    .ok_or_else(|| {
                        err(
                            ErrorKind::InvalidInput,
                            "AWS recovery window must be 7 to 30 days",
                        )
                    })
            })
            .transpose()?;
        if options.purge && days.is_some() {
            return Err(err(
                ErrorKind::InvalidInput,
                "AWS purge cannot have a recovery window",
            ));
        }
        let request = self
            .client
            .delete_secret()
            .secret_id(name)
            .set_recovery_window_in_days(days)
            .set_force_delete_without_recovery(options.purge.then_some(true));
        execute(async move {
            request.send().await.map_err(|e| {
                err(
                    kind(e.as_service_error().and_then(|s| s.code())),
                    "AWS deletion failed; outcome may be unknown",
                )
            })?;
            Ok(())
        })
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        self.check(vault, name)?;
        if options.version.as_ref().is_some_and(|v| !valid(v)) {
            return Err(err(ErrorKind::InvalidInput, "invalid AWS secret version"));
        }
        let requested = options.version.clone();
        let mut request = self.client.get_secret_value().secret_id(name);
        if let Some(v) = &requested {
            request = request.version_id(v);
        }
        execute(async move {
            let output = request.send().await.map_err(|e| {
                err(
                    if matches!(
                        e,
                        aws_sdk_secretsmanager::error::SdkError::TimeoutError(_)
                            | aws_sdk_secretsmanager::error::SdkError::DispatchFailure(_)
                            | aws_sdk_secretsmanager::error::SdkError::ResponseError(_)
                    ) {
                        ErrorKind::Transient
                    } else {
                        kind(e.as_service_error().and_then(|s| s.code()))
                    },
                    "AWS secret read failed",
                )
            })?;
            let version = output
                .version_id()
                .ok_or_else(|| err(ErrorKind::Provider, "AWS secret version missing"))?
                .to_owned();
            if requested.as_ref().is_some_and(|v| v != &version) {
                return Err(err(
                    ErrorKind::Provider,
                    "AWS returned a different secret version",
                ));
            }
            let bytes = match (output.secret_string(), output.secret_binary()) {
                (Some(s), None) => s.as_bytes().to_vec(),
                (None, Some(b)) => b.as_ref().to_vec(),
                _ => return Err(err(ErrorKind::Provider, "invalid AWS secret response")),
            };
            Ok(Response {
                value: SecretValue::new(bytes),
                metadata: Metadata {
                    version: Some(version),
                    ..Metadata::default()
                },
            })
        })
    }
    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        self.check(vault, name)?;
        if value.expose().len() > 65536 {
            return Err(err(
                ErrorKind::InvalidInput,
                "AWS secret exceeds size limit",
            ));
        }
        let request = self
            .client
            .put_secret_value()
            .secret_id(name)
            .secret_binary(Blob::new(value.expose().to_vec()));
        execute(async move {
            let output = request.send().await.map_err(|e| {
                err(
                    kind(e.as_service_error().and_then(|s| s.code())),
                    "AWS write failed; outcome may be unknown",
                )
            })?;
            let version = output
                .version_id()
                .ok_or_else(|| err(ErrorKind::Provider, "AWS write response missing version"))?;
            Ok(Metadata {
                version: Some(version.to_owned()),
                ..Metadata::default()
            })
        })
    }
}
