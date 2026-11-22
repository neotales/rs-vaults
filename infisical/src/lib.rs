//! Direct Infisical v4 shared-secret API provider.
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

/// Configuration for one Infisical project, environment and folder.
#[derive(Clone, Debug)]
pub struct Config {
    /// Registered vault name.
    pub vault: String,
    /// HTTPS server origin, optionally with a reverse-proxy prefix.
    pub address: String,
    /// Infisical project ID.
    pub project_id: String,
    /// Infisical environment slug.
    pub environment: String,
    /// Absolute Infisical secret folder path.
    pub secret_path: String,
    /// Already-obtained Infisical bearer access token.
    pub token: SecretValue,
    /// Allow plain HTTP only for a literal loopback IP.
    pub allow_http_loopback: bool,
}

/// Infisical v4 shared-secret driver.
pub struct InfisicalDriver {
    config: Config,
    base: Url,
    agent: ureq::Agent,
}
impl std::fmt::Debug for InfisicalDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfisicalDriver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Envelope {
    secret: ReturnedSecret,
}
#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ReturnedSecret {
    #[serde(default)]
    secret_value: Option<String>,
    #[serde(default)]
    secret_value_hidden: bool,
}
#[derive(Deserialize)]
struct ListEnvelope {
    secrets: Vec<ListedSecret>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedSecret {
    secret_key: String,
    #[serde(rename = "type")]
    secret_type: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteBody<'a> {
    project_id: &'a str,
    environment: &'a str,
    secret_path: &'a str,
    #[serde(rename = "type")]
    secret_type: &'static str,
}
#[derive(Deserialize)]
struct DeleteEnvelope {
    secret: Option<DeletedSecret>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeletedSecret {
    secret_key: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteBody<'a> {
    project_id: &'a str,
    environment: &'a str,
    secret_path: &'a str,
    secret_value: &'a str,
    #[serde(rename = "type")]
    secret_type: &'static str,
    skip_multiline_encoding: bool,
}

fn err(kind: ErrorKind, message: &'static str) -> Error {
    Error::new(kind, message)
}
fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !value.chars().any(char::is_control)
}
fn valid_path(value: &str) -> bool {
    value == "/" || (value.starts_with('/') && value[1..].split('/').all(valid_segment))
}

impl InfisicalDriver {
    /// Validates configuration without making a network request.
    pub fn new(config: Config) -> Result<Self> {
        let base = Url::parse(&config.address)
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid Infisical address"))?;
        let loopback = base
            .host_str()
            .and_then(|s| s.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        let token = std::str::from_utf8(config.token.expose())
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid Infisical token"))?;
        if !(base.scheme() == "https"
            || (base.scheme() == "http" && config.allow_http_loopback && loopback))
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || config.vault.is_empty()
            || !valid_segment(&config.project_id)
            || !valid_segment(&config.environment)
            || !valid_path(&config.secret_path)
            || token.is_empty()
            || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(err(
                ErrorKind::InvalidInput,
                "invalid or insecure Infisical configuration",
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

    fn endpoint(&self, vault: &str, name: &str) -> Result<Url> {
        if vault != self.config.vault {
            return Err(err(ErrorKind::NotFound, "vault is not configured"));
        }
        if !valid_segment(name) {
            return Err(err(
                ErrorKind::InvalidInput,
                "invalid Infisical secret name",
            ));
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid Infisical address"))?
            .pop_if_empty()
            .push("api")
            .push("v4")
            .push("secrets")
            .push(name);
        url.query_pairs_mut()
            .append_pair("projectId", &self.config.project_id)
            .append_pair("environment", &self.config.environment)
            .append_pair("secretPath", &self.config.secret_path)
            .append_pair("includePersonalOverrides", "false");
        Ok(url)
    }

    fn authorization(&self) -> Zeroizing<String> {
        let token = std::str::from_utf8(self.config.token.expose()).expect("validated token");
        Zeroizing::new(format!("Bearer {token}"))
    }

    fn status(status: u16) -> Result<()> {
        match status {
            200..=299 => Ok(()),
            401 => Err(err(
                ErrorKind::Authentication,
                "Infisical authentication failed",
            )),
            403 => Err(err(ErrorKind::PermissionDenied, "Infisical access denied")),
            404 => Err(err(ErrorKind::NotFound, "Infisical secret not found")),
            408 | 429 | 500..=599 => Err(err(
                ErrorKind::Transient,
                "Infisical service temporarily unavailable",
            )),
            _ => Err(err(ErrorKind::Provider, "Infisical request failed")),
        }
    }

    fn get_response(&self, url: &Url) -> Result<ureq::http::Response<ureq::Body>> {
        let authorization = self.authorization();
        self.agent
            .get(url.as_str())
            .header("Authorization", authorization.as_str())
            .header("Accept", "application/json")
            .call()
            .map_err(|_| err(ErrorKind::Transient, "Infisical transport failed"))
    }
}

impl Driver for InfisicalDriver {
    fn supports(&self, capability: Capability) -> bool {
        matches!(
            capability,
            Capability::GetSecret
                | Capability::SetSecret
                | Capability::ListSecrets
                | Capability::RemoveSecret
        )
    }
    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        let mut url = self.endpoint(vault, "placeholder")?;
        url.path_segments_mut()
            .map_err(|_| err(ErrorKind::Provider, "invalid Infisical address"))?
            .pop();
        url.query_pairs_mut()
            .append_pair("viewSecretValue", "false")
            .append_pair("expandSecretReferences", "false")
            .append_pair("includeImports", "false")
            .append_pair("recursive", "false");
        let response = self.get_response(&url)?;
        Self::status(response.status().as_u16())?;
        let bytes = Zeroizing::new(
            response
                .into_body()
                .with_config()
                .limit(MAX_RESPONSE)
                .read_to_vec()
                .map_err(|_| err(ErrorKind::Provider, "Infisical listing could not be read"))?,
        );
        let page: ListEnvelope = serde_json::from_slice(&bytes)
            .map_err(|_| err(ErrorKind::Provider, "Infisical listing is invalid"))?;
        let mut names = Vec::with_capacity(page.secrets.len());
        for entry in page.secrets {
            if entry.secret_type != "shared" || !valid_segment(&entry.secret_key) {
                return Err(err(
                    ErrorKind::Provider,
                    "Infisical listing contains an invalid secret",
                ));
            }
            names.push(entry.secret_key);
        }
        Ok(names)
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        if options.purge || options.version.is_some() || !options.query.is_empty() {
            return Err(err(
                ErrorKind::Unsupported,
                "unsupported Infisical removal option",
            ));
        }
        let mut url = self.endpoint(vault, name)?;
        url.set_query(None);
        let body = serde_json::to_vec(&DeleteBody {
            project_id: &self.config.project_id,
            environment: &self.config.environment,
            secret_path: &self.config.secret_path,
            secret_type: "shared",
        })
        .map_err(|_| {
            err(
                ErrorKind::Provider,
                "Infisical request could not be encoded",
            )
        })?;
        let authorization = self.authorization();
        let response = self
            .agent
            .delete(url.as_str())
            .force_send_body()
            .header("Authorization", authorization.as_str())
            .header("Content-Type", "application/json")
            .send(body.as_slice())
            .map_err(|_| {
                err(
                    ErrorKind::Provider,
                    "Infisical removal failed; outcome may be unknown",
                )
            })?;
        Self::status(response.status().as_u16())?;
        let bytes = Zeroizing::new(
            response
                .into_body()
                .with_config()
                .limit(MAX_RESPONSE)
                .read_to_vec()
                .map_err(|_| {
                    err(
                        ErrorKind::Provider,
                        "Infisical removal response could not be read",
                    )
                })?,
        );
        let result: DeleteEnvelope = serde_json::from_slice(&bytes)
            .map_err(|_| err(ErrorKind::Provider, "Infisical removal response is invalid"))?;
        if result.secret.as_ref().is_none_or(|s| s.secret_key != name) {
            return Err(err(
                ErrorKind::Provider,
                "Infisical removal was not confirmed; approval may be required",
            ));
        }
        Ok(())
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        if options.version.is_some() {
            return Err(err(
                ErrorKind::Unsupported,
                "Infisical versions are not supported",
            ));
        }
        let url = self.endpoint(vault, name)?;
        let response = self.get_response(&url)?;
        Self::status(response.status().as_u16())?;
        let bytes = Zeroizing::new(
            response
                .into_body()
                .with_config()
                .limit(MAX_RESPONSE)
                .read_to_vec()
                .map_err(|_| err(ErrorKind::Provider, "Infisical response could not be read"))?,
        );
        let mut envelope: Envelope = serde_json::from_slice(&bytes)
            .map_err(|_| err(ErrorKind::Provider, "Infisical response is invalid"))?;
        if envelope.secret.secret_value_hidden {
            return Err(err(
                ErrorKind::PermissionDenied,
                "Infisical secret value is hidden",
            ));
        }
        let value = envelope.secret.secret_value.take().ok_or_else(|| {
            err(
                ErrorKind::Provider,
                "Infisical response has no secret value",
            )
        })?;
        if value.len() > MAX_SECRET {
            let _value = Zeroizing::new(value);
            return Err(err(
                ErrorKind::Provider,
                "Infisical secret exceeds size limit",
            ));
        }
        Ok(Response {
            value: SecretValue::new(value.into_bytes()),
            metadata: Metadata::default(),
        })
    }
    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        if value.expose().len() > MAX_SECRET {
            return Err(err(ErrorKind::InvalidInput, "secret exceeds size limit"));
        }
        let value = std::str::from_utf8(value.expose())
            .map_err(|_| err(ErrorKind::InvalidInput, "Infisical secret must be UTF-8"))?;
        let url = self.endpoint(vault, name)?;
        let existing = self.get_response(&url)?;
        let method = match existing.status().as_u16() {
            200 => "PATCH",
            404 => "POST",
            status => {
                Self::status(status)?;
                return Err(err(ErrorKind::Provider, "unexpected Infisical read status"));
            }
        };
        let body = WriteBody {
            project_id: &self.config.project_id,
            environment: &self.config.environment,
            secret_path: &self.config.secret_path,
            secret_value: value,
            secret_type: "shared",
            skip_multiline_encoding: true,
        };
        let body = Zeroizing::new(serde_json::to_vec(&body).map_err(|_| {
            err(
                ErrorKind::Provider,
                "Infisical request could not be encoded",
            )
        })?);
        let authorization = self.authorization();
        let request = if method == "PATCH" {
            self.agent.patch(url.as_str())
        } else {
            self.agent.post(url.as_str())
        };
        let response = request
            .header("Authorization", authorization.as_str())
            .header("Content-Type", "application/json")
            .send(body.as_slice())
            .map_err(|_| {
                err(
                    ErrorKind::Transient,
                    "Infisical write transport failed; outcome may be unknown",
                )
            })?;
        Self::status(response.status().as_u16())?;
        Ok(Metadata::default())
    }
}
