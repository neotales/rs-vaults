//! HashiCorp Vault and OpenBao KV v2 secret provider.
#![forbid(unsafe_code)]

use neotales_vaults_core::{
    Capability, Driver, Error, ErrorKind, GetOptions, Metadata, RemoveOptions, Response, Result,
    SecretValue,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};
use url::Url;
use zeroize::Zeroizing;

const MAX_RESPONSE: u64 = 4 * 1024 * 1024;
const MAX_SECRET: usize = 1024 * 1024;

/// Configuration for a single Vault KV v2 mount.
#[derive(Clone, Debug)]
pub struct Config {
    /// Registered vault name.
    pub vault: String,
    /// Server origin, optionally with a reverse-proxy path prefix.
    pub address: String,
    /// Single KV v2 mount segment.
    pub mount: String,
    /// Vault authentication token; never logged.
    pub token: SecretValue,
    /// Optional Vault Enterprise namespace header.
    pub namespace: Option<String>,
    /// Permit plain HTTP only to a literal loopback IP. Intended for local tests.
    pub allow_http_loopback: bool,
}

/// Direct KV v2 API client. Stores UTF-8 values in the `value` field.
pub struct VaultDriver {
    config: Config,
    base: Url,
    agent: ureq::Agent,
}

impl std::fmt::Debug for VaultDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultDriver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Envelope {
    data: Data,
}
#[derive(Deserialize)]
struct Data {
    data: SecretData,
    metadata: VersionMetadata,
}
#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct SecretData {
    value: String,
}
#[derive(Deserialize)]
struct VersionMetadata {
    version: u64,
    #[serde(default)]
    destroyed: bool,
    #[serde(default)]
    deletion_time: String,
}
#[derive(Serialize)]
struct WriteBody<'a> {
    data: WriteData<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<Cas>,
}
#[derive(Serialize)]
struct WriteData<'a> {
    value: &'a str,
}
#[derive(Serialize)]
struct Cas {
    cas: u8,
}
#[derive(Deserialize)]
struct ListEnvelope {
    data: ListData,
}
#[derive(Deserialize)]
struct ListData {
    keys: Vec<String>,
}

fn error(kind: ErrorKind, message: &'static str) -> Error {
    Error::new(kind, message)
}
fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains(['/', '\\'])
        && !s.chars().any(char::is_control)
}
fn valid_header(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

impl VaultDriver {
    /// Validates configuration without contacting the server.
    pub fn new(config: Config) -> Result<Self> {
        let base = Url::parse(&config.address)
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid Vault address"))?;
        let is_loopback = base
            .host_str()
            .and_then(|s| s.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if !(base.scheme() == "https"
            || (base.scheme() == "http" && config.allow_http_loopback && is_loopback))
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || config.vault.is_empty()
            || !valid_segment(&config.mount)
            || base
                .path_segments()
                .is_none_or(|p| p.filter(|s| !s.is_empty()).any(|s| s == "." || s == ".."))
        {
            return Err(error(
                ErrorKind::InvalidInput,
                "invalid or insecure Vault configuration",
            ));
        }
        let token = std::str::from_utf8(config.token.expose())
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid Vault token"))?;
        if !valid_header(token)
            || config
                .namespace
                .as_deref()
                .is_some_and(|s| !valid_header(s))
        {
            return Err(error(ErrorKind::InvalidInput, "invalid Vault header value"));
        }
        let settings = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(20)))
            .build();
        Ok(Self {
            config,
            base,
            agent: ureq::Agent::new_with_config(settings),
        })
    }

    fn endpoint(&self, vault: &str, name: &str) -> Result<Url> {
        self.endpoint_for(vault, name, "data")
    }

    fn endpoint_for(&self, vault: &str, name: &str, operation: &str) -> Result<Url> {
        if vault != self.config.vault {
            return Err(error(ErrorKind::NotFound, "vault is not configured"));
        }
        if name.is_empty() || !name.split('/').all(valid_segment) {
            return Err(error(ErrorKind::InvalidInput, "invalid Vault secret name"));
        }
        let mut url = self.base.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid Vault address"))?;
        path.pop_if_empty()
            .push("v1")
            .push(&self.config.mount)
            .push(operation);
        for segment in name.split('/') {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }

    fn token(&self) -> &str {
        // Validated during construction; Config is private and immutable.
        std::str::from_utf8(self.config.token.expose()).expect("validated token")
    }

    fn status(status: u16) -> Result<()> {
        match status {
            200..=299 => Ok(()),
            401 => Err(error(
                ErrorKind::Authentication,
                "Vault authentication failed",
            )),
            403 => Err(error(ErrorKind::PermissionDenied, "Vault access denied")),
            404 => Err(error(ErrorKind::NotFound, "Vault secret not found")),
            408 | 429 | 500..=599 => Err(error(
                ErrorKind::Transient,
                "Vault service temporarily unavailable",
            )),
            _ => Err(error(ErrorKind::Provider, "Vault request failed")),
        }
    }

    fn send_write(&self, method: &str, url: &Url, value: &str, create: bool) -> Result<u16> {
        let body = WriteBody {
            data: WriteData { value },
            options: create.then_some(Cas { cas: 0 }),
        };
        let body = Zeroizing::new(
            serde_json::to_vec(&body)
                .map_err(|_| error(ErrorKind::Provider, "Vault request could not be encoded"))?,
        );
        let request = if method == "PATCH" {
            self.agent.patch(url.as_str())
        } else {
            self.agent.post(url.as_str())
        };
        let mut request = request.header("X-Vault-Token", self.token()).header(
            "Content-Type",
            if create {
                "application/json"
            } else {
                "application/merge-patch+json"
            },
        );
        if let Some(namespace) = &self.config.namespace {
            request = request.header("X-Vault-Namespace", namespace.as_str());
        }
        let response = request.send(body.as_slice()).map_err(|_| {
            error(
                ErrorKind::Provider,
                "Vault write transport failed; outcome may be unknown",
            )
        })?;
        Ok(response.status().as_u16())
    }
}

impl Driver for VaultDriver {
    fn supports(&self, capability: Capability) -> bool {
        matches!(
            capability,
            Capability::GetSecret
                | Capability::SetSecret
                | Capability::RemoveSecret
                | Capability::ListSecrets
        )
    }
    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        let mut root = self.endpoint_for(vault, "placeholder", "metadata")?;
        root.path_segments_mut()
            .map_err(|_| error(ErrorKind::Provider, "invalid Vault address"))?
            .pop();
        let mut pending = vec![String::new()];
        let mut names = Vec::new();
        let mut visited = std::collections::HashSet::new();
        while let Some(folder) = pending.pop() {
            if !visited.insert(folder.clone()) || visited.len() > 10_000 {
                return Err(error(
                    ErrorKind::Provider,
                    "Vault listing exceeds traversal limit",
                ));
            }
            let mut url = root.clone();
            if !folder.is_empty() {
                let mut segments = url
                    .path_segments_mut()
                    .map_err(|_| error(ErrorKind::Provider, "invalid Vault address"))?;
                for component in folder.split('/') {
                    segments.push(component);
                }
            }
            url.query_pairs_mut().append_pair("list", "true");
            let mut request = self
                .agent
                .get(url.as_str())
                .header("X-Vault-Token", self.token())
                .header("Accept", "application/json");
            if let Some(namespace) = &self.config.namespace {
                request = request.header("X-Vault-Namespace", namespace);
            }
            let response = request
                .call()
                .map_err(|_| error(ErrorKind::Transient, "Vault listing transport failed"))?;
            if response.status().as_u16() == 404 {
                continue;
            }
            Self::status(response.status().as_u16())?;
            let bytes = response
                .into_body()
                .with_config()
                .limit(MAX_RESPONSE)
                .read_to_vec()
                .map_err(|_| error(ErrorKind::Provider, "Vault listing could not be read"))?;
            let result: ListEnvelope = serde_json::from_slice(&bytes)
                .map_err(|_| error(ErrorKind::Provider, "invalid Vault listing"))?;
            for name in result.data.keys {
                let is_folder = name.ends_with('/');
                let segment = if is_folder {
                    &name[..name.len() - 1]
                } else {
                    &name
                };
                if !valid_segment(segment) {
                    return Err(error(ErrorKind::Provider, "invalid Vault listing name"));
                }
                let path = if folder.is_empty() {
                    segment.to_owned()
                } else {
                    format!("{folder}/{segment}")
                };
                if path.len() > 4096 || path.split('/').count() > 64 {
                    return Err(error(
                        ErrorKind::Provider,
                        "Vault listing exceeds traversal limit",
                    ));
                }
                if is_folder {
                    pending.push(path);
                } else {
                    names.push(path);
                }
                if names.len() + pending.len() > 100_000 {
                    return Err(error(
                        ErrorKind::Provider,
                        "Vault listing exceeds traversal limit",
                    ));
                }
            }
        }
        names.sort();
        Ok(names)
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        if !options.query.is_empty() {
            return Err(error(
                ErrorKind::Unsupported,
                "unsupported Vault removal option",
            ));
        }
        let version = options
            .version
            .as_deref()
            .map(|version| {
                version
                    .parse::<u64>()
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        error(
                            ErrorKind::InvalidInput,
                            "Vault version must be a positive integer",
                        )
                    })
            })
            .transpose()?;
        let segment = match (options.purge, version) {
            (false, None) => "data",
            (false, Some(_)) => "delete",
            (true, None) => "metadata",
            (true, Some(_)) => "destroy",
        };
        let url = self.endpoint_for(vault, name, segment)?;
        let response = if let Some(version) = version {
            let mut request = self
                .agent
                .post(url.as_str())
                .header("X-Vault-Token", self.token())
                .header("Content-Type", "application/json");
            if let Some(namespace) = &self.config.namespace {
                request = request.header("X-Vault-Namespace", namespace);
            }
            request
                .send(format!("{{\"versions\":[{version}]}}"))
                .map_err(|_| {
                    error(
                        ErrorKind::Provider,
                        "Vault removal transport failed; outcome may be unknown",
                    )
                })?
        } else {
            let mut request = self
                .agent
                .delete(url.as_str())
                .header("X-Vault-Token", self.token());
            if let Some(namespace) = &self.config.namespace {
                request = request.header("X-Vault-Namespace", namespace);
            }
            request.call().map_err(|_| {
                error(
                    ErrorKind::Provider,
                    "Vault removal transport failed; outcome may be unknown",
                )
            })?
        };
        Self::status(response.status().as_u16())
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        let mut url = self.endpoint(vault, name)?;
        if let Some(version) = &options.version {
            let value = version
                .parse::<u64>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or_else(|| {
                    error(
                        ErrorKind::InvalidInput,
                        "Vault version must be a positive integer",
                    )
                })?;
            url.query_pairs_mut()
                .append_pair("version", &value.to_string());
        }
        let mut request = self
            .agent
            .get(url.as_str())
            .header("X-Vault-Token", self.token())
            .header("Accept", "application/json");
        if let Some(namespace) = &self.config.namespace {
            request = request.header("X-Vault-Namespace", namespace.as_str());
        }
        let response = request
            .call()
            .map_err(|_| error(ErrorKind::Provider, "Vault read transport failed"))?;
        Self::status(response.status().as_u16())?;
        let bytes = Zeroizing::new(
            response
                .into_body()
                .with_config()
                .limit(MAX_RESPONSE)
                .read_to_vec()
                .map_err(|_| error(ErrorKind::Provider, "Vault response could not be read"))?,
        );
        let mut envelope: Envelope = serde_json::from_slice(&bytes)
            .map_err(|_| error(ErrorKind::Provider, "Vault response is invalid"))?;
        if envelope.data.metadata.version == 0
            || envelope.data.metadata.destroyed
            || !envelope.data.metadata.deletion_time.is_empty()
        {
            return Err(error(ErrorKind::NotFound, "Vault version is unavailable"));
        }
        if options.version.as_ref().is_some_and(|requested| {
            requested.parse::<u64>().ok() != Some(envelope.data.metadata.version)
        }) {
            return Err(error(
                ErrorKind::Provider,
                "Vault returned an unexpected version",
            ));
        }
        if envelope.data.data.value.len() > MAX_SECRET {
            return Err(error(
                ErrorKind::Provider,
                "Vault secret exceeds size limit",
            ));
        }
        let bytes = std::mem::take(&mut envelope.data.data.value).into_bytes();
        Ok(Response {
            value: SecretValue::new(bytes),
            metadata: Metadata {
                version: Some(envelope.data.metadata.version.to_string()),
                ..Metadata::default()
            },
        })
    }
    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        let url = self.endpoint(vault, name)?;
        if value.expose().len() > MAX_SECRET {
            return Err(error(ErrorKind::InvalidInput, "secret exceeds size limit"));
        }
        let value = std::str::from_utf8(value.expose())
            .map_err(|_| error(ErrorKind::InvalidInput, "Vault secret must be UTF-8"))?;
        let status = self.send_write("PATCH", &url, value, false)?;
        // PATCH cannot create a missing KV v2 path. CAS zero prevents a
        // concurrent creator from being overwritten by the fallback POST.
        let status = if status == 404 {
            self.send_write("POST", &url, value, true)?
        } else {
            status
        };
        Self::status(status)?;
        Ok(Metadata::default())
    }
}
