//! Google Cloud Secret Manager gRPC provider.
#![forbid(unsafe_code)]
use neotales_vaults_core::{
    Capability, Driver, Error, ErrorKind, GetOptions, Metadata, RemoveOptions, Response, Result,
    SecretValue,
};
use prost::Message;
use std::{future::Future, net::IpAddr, time::Duration};
use tonic::{
    Code, Request,
    transport::{Channel, ClientTlsConfig, Endpoint},
};
use zeroize::Zeroizing;

/// Configuration for one project and an already obtained OAuth access token.
#[derive(Clone, Debug)]
pub struct Config {
    /// Registered vault name.
    pub vault: String,
    /// Google Cloud project ID or number.
    pub project: String,
    /// gRPC HTTPS origin; use <https://secretmanager.googleapis.com> for Google Cloud.
    pub endpoint: String,
    /// OAuth bearer token. The caller is responsible for refreshing it.
    pub token: SecretValue,
    /// Allow plain HTTP only for a literal loopback IP.
    pub allow_http_loopback: bool,
}
/// A provider for existing Google Cloud Secret Manager secrets.
pub struct GcpDriver {
    config: Config,
}

/// Builds removal options with a GCP entity-tag precondition.
pub fn removal_with_etag(etag: impl Into<String>) -> Result<RemoveOptions> {
    let etag = etag.into();
    if etag.is_empty() || etag.len() > 1024 || etag.chars().any(char::is_control) {
        return Err(err(ErrorKind::InvalidInput, "invalid GCP entity tag"));
    }
    let mut options = RemoveOptions::default();
    options.query.insert("etag".into(), etag);
    Ok(options)
}

#[derive(Clone, PartialEq, Message)]
struct ListRequest {
    #[prost(string, tag = "1")]
    parent: String,
    #[prost(string, tag = "3")]
    page_token: String,
}
#[derive(Clone, PartialEq, Message)]
struct ListedSecret {
    #[prost(string, tag = "1")]
    name: String,
}
#[derive(Clone, PartialEq, Message)]
struct ListResponse {
    #[prost(message, repeated, tag = "1")]
    secrets: Vec<ListedSecret>,
    #[prost(string, tag = "2")]
    next_page_token: String,
}
#[derive(Clone, PartialEq, Message)]
struct RemovalRequest {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    etag: String,
}
#[derive(Clone, PartialEq, Message)]
struct Empty {}
#[derive(Clone, PartialEq, Message)]
struct CreateSecretRequest {
    #[prost(string, tag = "1")]
    parent: String,
    #[prost(string, tag = "2")]
    secret_id: String,
    #[prost(message, optional, tag = "3")]
    secret: Option<CreateSecret>,
}
#[derive(Clone, PartialEq, Message)]
struct CreateSecret {
    #[prost(message, optional, tag = "2")]
    replication: Option<CreateReplication>,
}
#[derive(Clone, PartialEq, Message)]
struct CreateReplication {
    #[prost(message, optional, tag = "1")]
    automatic: Option<Empty>,
}

// Minimal wire messages mirror Google's published v1 service and resources protos.
#[derive(Clone, PartialEq, Message)]
struct AccessRequest {
    #[prost(string, tag = "1")]
    name: String,
}
#[derive(Clone, PartialEq, Message)]
struct AccessResponse {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    payload: Option<Payload>,
}
#[derive(Clone, PartialEq, Message)]
struct Payload {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
    #[prost(int64, optional, tag = "2")]
    data_crc32c: Option<i64>,
}
impl Drop for Payload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();
    }
}
#[derive(Clone, PartialEq, Message)]
struct AddRequest {
    #[prost(string, tag = "1")]
    parent: String,
    #[prost(message, optional, tag = "2")]
    payload: Option<Payload>,
}
#[derive(Clone, PartialEq, Message)]
struct SecretVersion {
    #[prost(string, tag = "1")]
    name: String,
}

fn err(kind: ErrorKind, msg: &'static str) -> Error {
    Error::new(kind, msg)
}
fn valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn status(error: tonic::Status, write: bool) -> Error {
    let kind = match error.code() {
        Code::NotFound => ErrorKind::NotFound,
        Code::Unauthenticated => ErrorKind::Authentication,
        Code::PermissionDenied => ErrorKind::PermissionDenied,
        Code::Unavailable | Code::ResourceExhausted | Code::DeadlineExceeded => {
            ErrorKind::Transient
        }
        _ => ErrorKind::Provider,
    };
    err(
        kind,
        if write {
            "GCP write failed; outcome may be unknown"
        } else {
            "GCP secret read failed"
        },
    )
}
fn execute<T: Send>(f: impl Future<Output = Result<T>> + Send) -> Result<T> {
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| err(ErrorKind::Provider, "GCP runtime unavailable"))?
                .block_on(f)
        })
        .join()
        .map_err(|_| err(ErrorKind::Provider, "GCP request worker failed"))?
    })
}
impl GcpDriver {
    /// Validate configuration without making a network request.
    pub fn new(config: Config) -> Result<Self> {
        let url = url::Url::parse(&config.endpoint)
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid GCP endpoint"))?;
        let loopback = url
            .host_str()
            .and_then(|s| s.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        let token = std::str::from_utf8(config.token.expose())
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid GCP token"))?;
        if config.vault.is_empty()
            || !valid(&config.project)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !(url.scheme() == "https"
                || (url.scheme() == "http" && config.allow_http_loopback && loopback))
            || token.is_empty()
            || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(err(
                ErrorKind::InvalidInput,
                "invalid or insecure GCP configuration",
            ));
        }
        Ok(Self { config })
    }
    fn parent(&self, vault: &str, name: &str) -> Result<String> {
        if vault != self.config.vault {
            return Err(err(ErrorKind::NotFound, "vault is not configured"));
        }
        if !valid(name) {
            return Err(err(ErrorKind::InvalidInput, "invalid GCP secret name"));
        }
        Ok(format!("projects/{}/secrets/{name}", self.config.project))
    }
    async fn channel(&self) -> Result<Channel> {
        let mut endpoint = Endpoint::from_shared(self.config.endpoint.clone())
            .map_err(|_| err(ErrorKind::InvalidInput, "invalid GCP endpoint"))?
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(10));
        if self.config.endpoint.starts_with("https://") {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .map_err(|_| err(ErrorKind::Provider, "GCP TLS configuration failed"))?;
        }
        endpoint
            .connect()
            .await
            .map_err(|_| err(ErrorKind::Transient, "GCP connection failed"))
    }
    fn request<T>(&self, body: T, parent: &str) -> Result<Request<T>> {
        let mut req = Request::new(body);
        let auth = Zeroizing::new(format!(
            "Bearer {}",
            std::str::from_utf8(self.config.token.expose()).expect("validated")
        ));
        req.metadata_mut().insert(
            "authorization",
            auth.parse()
                .map_err(|_| err(ErrorKind::InvalidInput, "invalid GCP token"))?,
        );
        req.metadata_mut().insert(
            "x-goog-request-params",
            format!("name={parent}")
                .parse()
                .map_err(|_| err(ErrorKind::InvalidInput, "invalid GCP resource"))?,
        );
        Ok(req)
    }
    fn version(parent: &str, name: &str, requested: Option<&str>) -> Result<String> {
        let prefix = format!("{parent}/versions/");
        let version = name
            .strip_prefix(&prefix)
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| err(ErrorKind::Provider, "invalid GCP version response"))?;
        if requested.is_some_and(|r| r != version) {
            return Err(err(ErrorKind::Provider, "GCP returned a different version"));
        }
        Ok(version.to_owned())
    }
}
impl Driver for GcpDriver {
    fn supports(&self, c: Capability) -> bool {
        matches!(
            c,
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
        self.parent(vault, name)?;
        if value.expose().len() > 65536 {
            return Err(err(
                ErrorKind::InvalidInput,
                "GCP secret exceeds size limit",
            ));
        }
        let project = format!("projects/{}", self.config.project);
        execute(async {
            let channel = self.channel().await?;
            let mut client =
                tonic::client::Grpc::new(channel).max_decoding_message_size(1024 * 1024);
            client
                .ready()
                .await
                .map_err(|_| err(ErrorKind::Transient, "GCP service unavailable"))?;
            let mut request = self.request(
                CreateSecretRequest {
                    parent: project.clone(),
                    secret_id: name.to_owned(),
                    secret: Some(CreateSecret {
                        replication: Some(CreateReplication {
                            automatic: Some(Empty {}),
                        }),
                    }),
                },
                &project,
            )?;
            request.metadata_mut().insert(
                "x-goog-request-params",
                format!("parent={project}")
                    .parse()
                    .map_err(|_| err(ErrorKind::InvalidInput, "invalid GCP resource"))?,
            );
            let result: std::result::Result<tonic::Response<ListedSecret>, tonic::Status> = client
                .unary(
                    request,
                    tonic::codegen::http::uri::PathAndQuery::from_static(
                        "/google.cloud.secretmanager.v1.SecretManagerService/CreateSecret",
                    ),
                    tonic::codec::ProstCodec::default(),
                )
                .await;
            match result {
                Ok(_) => Ok(()),
                Err(error) if error.code() == Code::AlreadyExists => Ok(()),
                Err(error) => Err(status(error, true)),
            }
        })?;
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
    fn list_secrets(&self, vault: &str) -> Result<Vec<String>> {
        if vault != self.config.vault {
            return Err(err(ErrorKind::NotFound, "vault is not configured"));
        }
        let parent = format!("projects/{}", self.config.project);
        execute(async {
            let channel = self.channel().await?;
            let mut client =
                tonic::client::Grpc::new(channel).max_decoding_message_size(4 * 1024 * 1024);
            let mut token = String::new();
            let mut seen = std::collections::HashSet::new();
            let mut names = Vec::new();
            loop {
                client
                    .ready()
                    .await
                    .map_err(|_| err(ErrorKind::Transient, "GCP service unavailable"))?;
                let mut request = self.request(
                    ListRequest {
                        parent: parent.clone(),
                        page_token: token,
                    },
                    &parent,
                )?;
                request.metadata_mut().insert(
                    "x-goog-request-params",
                    format!("parent={parent}")
                        .parse()
                        .map_err(|_| err(ErrorKind::InvalidInput, "invalid GCP resource"))?,
                );
                let response: ListResponse = client
                    .unary(
                        request,
                        tonic::codegen::http::uri::PathAndQuery::from_static(
                            "/google.cloud.secretmanager.v1.SecretManagerService/ListSecrets",
                        ),
                        tonic::codec::ProstCodec::default(),
                    )
                    .await
                    .map_err(|e| status(e, false))?
                    .into_inner();
                for secret in response.secrets {
                    let parts: Vec<_> = secret.name.split('/').collect();
                    if parts.len() != 4
                        || parts[0] != "projects"
                        || parts[2] != "secrets"
                        || (parts[1] != self.config.project
                            && (self.config.project.bytes().all(|b| b.is_ascii_digit())
                                || !parts[1].bytes().all(|b| b.is_ascii_digit())))
                        || parts[1].is_empty()
                        || !valid(parts[3])
                    {
                        return Err(err(ErrorKind::Provider, "invalid GCP secret name response"));
                    }
                    names.push(parts[3].to_owned());
                }
                if response.next_page_token.is_empty() {
                    break;
                }
                if !seen.insert(response.next_page_token.clone()) {
                    return Err(err(ErrorKind::Provider, "GCP pagination loop"));
                }
                token = response.next_page_token;
            }
            Ok(names)
        })
    }
    fn remove_secret(&self, vault: &str, name: &str, options: &RemoveOptions) -> Result<()> {
        let parent = self.parent(vault, name)?;
        if options.query.keys().any(|key| key != "etag") {
            return Err(err(
                ErrorKind::Unsupported,
                "unsupported GCP removal option",
            ));
        }
        let etag = options.query.get("etag").cloned().unwrap_or_default();
        if options.query.contains_key("etag")
            && (etag.is_empty() || etag.len() > 1024 || etag.chars().any(char::is_control))
        {
            return Err(err(ErrorKind::InvalidInput, "invalid GCP entity tag"));
        }
        let version = options.version.as_deref();
        if version.is_some_and(|v| {
            v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) || v.bytes().all(|b| b == b'0')
        }) {
            return Err(err(ErrorKind::InvalidInput, "invalid GCP secret version"));
        }
        let resource = version.map_or_else(|| parent.clone(), |v| format!("{parent}/versions/{v}"));
        execute(async {
            let channel = self
                .channel()
                .await
                .map_err(|_| err(ErrorKind::Provider, "GCP connection failed before removal"))?;
            let mut client =
                tonic::client::Grpc::new(channel).max_decoding_message_size(1024 * 1024);
            client.ready().await.map_err(|_| {
                err(
                    ErrorKind::Provider,
                    "GCP service unavailable before removal",
                )
            })?;
            let request = self.request(
                RemovalRequest {
                    name: resource.clone(),
                    etag,
                },
                &resource,
            )?;
            if version.is_none() {
                let _: Empty = client
                    .unary(
                        request,
                        tonic::codegen::http::uri::PathAndQuery::from_static(
                            "/google.cloud.secretmanager.v1.SecretManagerService/DeleteSecret",
                        ),
                        tonic::codec::ProstCodec::default(),
                    )
                    .await
                    .map_err(|e| status(e, true))?
                    .into_inner();
            } else {
                let path = if options.purge {
                    "/google.cloud.secretmanager.v1.SecretManagerService/DestroySecretVersion"
                } else {
                    "/google.cloud.secretmanager.v1.SecretManagerService/DisableSecretVersion"
                };
                let response: SecretVersion = client
                    .unary(
                        request,
                        tonic::codegen::http::uri::PathAndQuery::from_static(path),
                        tonic::codec::ProstCodec::default(),
                    )
                    .await
                    .map_err(|e| status(e, true))?
                    .into_inner();
                Self::version(&parent, &response.name, version)?;
            }
            Ok(())
        })
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>> {
        let parent = self.parent(vault, name)?;
        if options
            .version
            .as_ref()
            .is_some_and(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(err(ErrorKind::InvalidInput, "invalid GCP secret version"));
        }
        let resource = format!(
            "{parent}/versions/{}",
            options.version.as_deref().unwrap_or("latest")
        );
        execute(async {
            let channel = self.channel().await?;
            let mut client =
                tonic::client::Grpc::new(channel).max_decoding_message_size(1024 * 1024);
            client
                .ready()
                .await
                .map_err(|_| err(ErrorKind::Transient, "GCP service unavailable"))?;
            let request = self.request(
                AccessRequest {
                    name: resource.clone(),
                },
                &resource,
            )?;
            let response: AccessResponse = client
                .unary(
                    request,
                    tonic::codegen::http::uri::PathAndQuery::from_static(
                        "/google.cloud.secretmanager.v1.SecretManagerService/AccessSecretVersion",
                    ),
                    tonic::codec::ProstCodec::default(),
                )
                .await
                .map_err(|e| status(e, false))?
                .into_inner();
            let version = Self::version(&parent, &response.name, options.version.as_deref())?;
            let mut payload = response
                .payload
                .ok_or_else(|| err(ErrorKind::Provider, "GCP secret payload missing"))?;
            if payload.data.len() > 65536
                || payload.data_crc32c.is_some_and(|c| {
                    c < 0 || c > u32::MAX as i64 || c as u32 != crc32c::crc32c(&payload.data)
                })
            {
                return Err(err(
                    ErrorKind::Provider,
                    "GCP secret payload integrity check failed",
                ));
            }
            Ok(Response {
                value: SecretValue::new(std::mem::take(&mut payload.data)),
                metadata: Metadata {
                    version: Some(version),
                    ..Metadata::default()
                },
            })
        })
    }
    fn set_secret(&self, vault: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
        let parent = self.parent(vault, name)?;
        if value.expose().len() > 65536 {
            return Err(err(
                ErrorKind::InvalidInput,
                "GCP secret exceeds size limit",
            ));
        }
        execute(async {
            let channel = self
                .channel()
                .await
                .map_err(|_| err(ErrorKind::Provider, "GCP connection failed before write"))?;
            let mut client =
                tonic::client::Grpc::new(channel).max_decoding_message_size(1024 * 1024);
            client
                .ready()
                .await
                .map_err(|_| err(ErrorKind::Provider, "GCP service unavailable before write"))?;
            let payload = Payload {
                data: value.expose().to_vec(),
                data_crc32c: Some(crc32c::crc32c(value.expose()) as i64),
            };
            let mut request = self.request(
                AddRequest {
                    parent: parent.clone(),
                    payload: Some(payload),
                },
                &parent,
            )?;
            request.metadata_mut().insert(
                "x-goog-request-params",
                format!("parent={parent}")
                    .parse()
                    .map_err(|_| err(ErrorKind::InvalidInput, "invalid GCP resource"))?,
            );
            let response: SecretVersion = client
                .unary(
                    request,
                    tonic::codegen::http::uri::PathAndQuery::from_static(
                        "/google.cloud.secretmanager.v1.SecretManagerService/AddSecretVersion",
                    ),
                    tonic::codec::ProstCodec::default(),
                )
                .await
                .map_err(|e| status(e, true))?
                .into_inner();
            Ok(Metadata {
                version: Some(Self::version(&parent, &response.name, None)?),
                ..Metadata::default()
            })
        })
    }
}
