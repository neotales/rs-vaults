//! Azure Key Vault secret data-plane provider.
#![forbid(unsafe_code)]

use neotales_vaults_core::{
    Capability, Driver, Error, ErrorKind, GetOptions, Metadata, RemoveOptions, Response, Result,
    SecretValue,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

/// Configuration for a single Azure Key Vault and bearer token.
#[derive(Clone, Debug)]
pub struct Config {
    /// Registry vault name.
    pub vault: String,
    /// Vault HTTPS endpoint, optionally including an emulator path.
    pub address: String,
    /// Already obtained Azure Key Vault access token.
    pub token: SecretValue,
    /// Permit HTTP only for a literal loopback IP.
    pub allow_http_loopback: bool,
}

/// Azure Key Vault secret provider.
pub struct AzureDriver {
    config: Config,
    base: Url,
    agent: ureq::Agent,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct SecretResponse {
    value: String,
    id: String,
}
#[derive(Serialize)]
struct WriteBody<'a> {
    value: &'a str,
}
#[derive(Deserialize)]
struct ListResponse {
    value: Vec<ListEntry>,
    #[serde(rename = "nextLink")]
    next_link: Option<String>,
}
#[derive(Deserialize)]
struct ListEntry {
    id: String,
}

fn error(kind: ErrorKind, message: &'static str) -> Error {
    Error::new(kind, message)
}
fn segment(s: &str) -> bool {
    !s.is_empty() && s.len() <= 127 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl AzureDriver {
    /// Validate the endpoint and credentials without network access.
    pub fn new(config: Config) -> Result<Self> {
        let base = Url::parse(&config.address)
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid Azure endpoint"))?;
        let loopback = base
            .host_str()
            .and_then(|s| s.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        let token = std::str::from_utf8(config.token.expose())
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid Azure token"))?;
        if config.vault.is_empty()
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !(base.scheme() == "https"
                || (base.scheme() == "http" && config.allow_http_loopback && loopback))
            || token.is_empty()
            || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(error(
                ErrorKind::InvalidInput,
                "invalid or insecure Azure configuration",
            ));
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

    fn endpoint(&self, vault: &str, name: &str, version: Option<&str>) -> Result<Url> {
        if vault != self.config.vault {
            return Err(error(ErrorKind::NotFound, "vault is not configured"));
        }
        if !segment(name) || version.is_some_and(|v| !segment(v)) {
            return Err(error(
                ErrorKind::InvalidInput,
                "invalid Azure secret name or version",
            ));
        }
        let mut url = self.base.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| error(ErrorKind::InvalidInput, "invalid Azure endpoint"))?;
            path.pop_if_empty().push("secrets").push(name);
            if let Some(version) = version {
                path.push(version);
            }
        }
        url.query_pairs_mut().append_pair("api-version", "7.4");
        Ok(url)
    }

    fn auth(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "Bearer {}",
            std::str::from_utf8(self.config.token.expose()).expect("validated token")
        ))
    }
    fn status(status: u16) -> Result<()> {
        match status {
            200..=299 => Ok(()),
            401 => Err(error(
                ErrorKind::Authentication,
                "Azure authentication failed",
            )),
            403 => Err(error(ErrorKind::PermissionDenied, "Azure access denied")),
            404 => Err(error(ErrorKind::NotFound, "Azure secret not found")),
            408 | 429 | 500..=599 => Err(error(
                ErrorKind::Transient,
                "Azure service temporarily unavailable",
            )),
            _ => Err(error(ErrorKind::Provider, "Azure request failed")),
        }
    }
    fn parse(
        mut response: ureq::http::Response<ureq::Body>,
        expected_name: &str,
        expected_version: Option<&str>,
    ) -> Result<Response<SecretValue>> {
        match response.status().as_u16() {
            200..=299 => {}
            401 => {
                return Err(error(
                    ErrorKind::Authentication,
                    "Azure authentication failed",
                ));
            }
            403 => return Err(error(ErrorKind::PermissionDenied, "Azure access denied")),
            404 => return Err(error(ErrorKind::NotFound, "Azure secret not found")),
            408 | 429 | 500..=599 => {
                return Err(error(
                    ErrorKind::Transient,
                    "Azure service temporarily unavailable",
                ));
            }
            _ => return Err(error(ErrorKind::Provider, "Azure request failed")),
        }
        let bytes = Zeroizing::new(
            response
                .body_mut()
                .with_config()
                .limit(4 * 1024 * 1024)
                .read_to_vec()
                .map_err(|_| error(ErrorKind::Provider, "invalid Azure response"))?,
        );
        let mut data: SecretResponse = serde_json::from_slice(&bytes)
            .map_err(|_| error(ErrorKind::Provider, "invalid Azure response"))?;
        let id = Url::parse(&data.id)
            .map_err(|_| error(ErrorKind::Provider, "invalid Azure secret ID"))?;
        let mut segments = id
            .path_segments()
            .ok_or_else(|| error(ErrorKind::Provider, "invalid Azure secret ID"))?;
        let version = segments
            .next_back()
            .filter(|v| segment(v))
            .ok_or_else(|| error(ErrorKind::Provider, "invalid Azure secret version"))?
            .to_owned();
        if id.query().is_some()
            || id.fragment().is_some()
            || segments.next_back() != Some(expected_name)
            || segments.next_back() != Some("secrets")
            || expected_version.is_some_and(|expected| expected != version)
        {
            return Err(error(
                ErrorKind::Provider,
                "Azure returned a different secret or version",
            ));
        }
        Ok(Response {
            value: SecretValue::new(std::mem::take(&mut data.value).into_bytes()),
            metadata: Metadata {
                version: Some(version),
                ..Metadata::default()
            },
        })
    }
}

impl Driver for AzureDriver {
    fn supports(&self, c: Capability) -> bool {
        matches!(
            c,
            Capability::GetSecret
                | Capability::SetSecret
                | Capability::ListSecrets
                | Capability::RemoveSecret
        )
    }
    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        if vault != self.config.vault {
            return Err(error(ErrorKind::NotFound, "vault is not configured"));
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid Azure endpoint"))?
            .pop_if_empty()
            .push("secrets");
        url.query_pairs_mut().append_pair("api-version", "7.4");
        let list_path = url.path().to_owned();
        let mut seen = std::collections::HashSet::new();
        let mut names = Vec::new();
        loop {
            if !seen.insert(url.to_string()) {
                return Err(error(ErrorKind::Provider, "Azure listing pagination loop"));
            }
            let auth = self.auth();
            let mut response = self
                .agent
                .get(url.as_str())
                .header("Authorization", auth.as_str())
                .call()
                .map_err(|_| error(ErrorKind::Transient, "Azure listing request failed"))?;
            Self::status(response.status().as_u16())?;
            let bytes = response
                .body_mut()
                .with_config()
                .limit(4 * 1024 * 1024)
                .read_to_vec()
                .map_err(|_| error(ErrorKind::Provider, "invalid Azure listing"))?;
            let page: ListResponse = serde_json::from_slice(&bytes)
                .map_err(|_| error(ErrorKind::Provider, "invalid Azure listing"))?;
            for entry in page.value {
                let id = Url::parse(&entry.id)
                    .map_err(|_| error(ErrorKind::Provider, "invalid Azure secret ID"))?;
                let prefix = format!("{list_path}/");
                // Floci's loopback emulator emits canonical Azure IDs instead
                // of its loopback URL. Never follow these IDs or relax the
                // same-origin restriction for pagination URLs.
                let emulator_host = self
                    .base
                    .host_str()
                    .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
                    .filter(|ip| ip.is_loopback() && self.config.allow_http_loopback)
                    .and_then(|_| self.base.path_segments()?.rfind(|s| !s.is_empty()))
                    .and_then(|s| s.strip_suffix("-keyvault"))
                    .filter(|s| segment(s))
                    .map(|name| format!("{name}.vault.azure.net"));
                let emulated_id = emulator_host.as_deref().is_some_and(|host| {
                    id.scheme() == "https" && id.host_str() == Some(host) && id.port().is_none()
                });
                let path_prefix = if emulated_id {
                    "/secrets/"
                } else {
                    prefix.as_str()
                };
                let name = id
                    .path()
                    .strip_prefix(path_prefix)
                    .filter(|name| segment(name))
                    .ok_or_else(|| error(ErrorKind::Provider, "invalid Azure secret ID"))?;
                if (!emulated_id && id.origin() != self.base.origin())
                    || id.query().is_some()
                    || id.fragment().is_some()
                    || !id.username().is_empty()
                    || id.password().is_some()
                {
                    return Err(error(ErrorKind::Provider, "invalid Azure secret ID"));
                }
                names.push(name.to_owned());
            }
            match page.next_link {
                None => break,
                Some(next) => {
                    let next = Url::parse(&next)
                        .map_err(|_| error(ErrorKind::Provider, "invalid Azure pagination URL"))?;
                    if next.origin() != self.base.origin()
                        || next.path() != list_path
                        || !next.username().is_empty()
                        || next.password().is_some()
                        || next.fragment().is_some()
                    {
                        return Err(error(ErrorKind::Provider, "invalid Azure pagination URL"));
                    }
                    url = next;
                }
            }
        }
        Ok(names)
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        if options.version.is_some() || !options.query.is_empty() {
            return Err(error(
                ErrorKind::Unsupported,
                "unsupported Azure removal option",
            ));
        }
        let mut url = self.endpoint(vault, name, None)?;
        if options.purge {
            url.path_segments_mut()
                .map_err(|_| error(ErrorKind::Provider, "invalid Azure endpoint"))?
                .pop()
                .pop()
                .push("deletedsecrets")
                .push(name);
        }
        let auth = self.auth();
        let response = self
            .agent
            .delete(url.as_str())
            .header("Authorization", auth.as_str())
            .call()
            .map_err(|_| {
                error(
                    ErrorKind::Provider,
                    "Azure removal failed; outcome may be unknown",
                )
            })?;
        Self::status(response.status().as_u16())
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        let url = self.endpoint(vault, name, options.version.as_deref())?;
        let auth = self.auth();
        let response = self
            .agent
            .get(url.as_str())
            .header("Authorization", auth.as_str())
            .call()
            .map_err(|_| error(ErrorKind::Transient, "Azure request failed"))?;
        Self::parse(response, name, options.version.as_deref())
    }
    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        if value.expose().len() > 25 * 1024 {
            return Err(error(
                ErrorKind::InvalidInput,
                "Azure secret exceeds size limit",
            ));
        }
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| error(ErrorKind::InvalidInput, "Azure secret must be UTF-8"))?;
        let url = self.endpoint(vault, name, None)?;
        let body = Zeroizing::new(
            serde_json::to_vec(&WriteBody { value: text })
                .map_err(|_| error(ErrorKind::Provider, "Azure request could not be encoded"))?,
        );
        let auth = self.auth();
        let response = self
            .agent
            .put(url.as_str())
            .header("Authorization", auth.as_str())
            .header("Content-Type", "application/json")
            .send(body.as_slice())
            .map_err(|_| {
                error(
                    ErrorKind::Transient,
                    "Azure write failed; outcome may be unknown",
                )
            })?;
        Ok(Self::parse(response, name, None)?.metadata)
    }
}
