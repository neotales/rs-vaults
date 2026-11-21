//! Named vault registry and `nv://` resource resolution.
#![forbid(unsafe_code)]

use core::{
    Certificate, Client, Driver, Error, ErrorKind, GetOptions, Key, ResourceKind, Response, Result,
    SecretValue, VaultUri,
};
pub use neotales_vaults_core as core;
use std::{collections::HashMap, sync::Arc};

/// Registry of configured vaults. Registration does not contact a provider.
#[derive(Default)]
pub struct Registry {
    clients: HashMap<String, Client>,
}

/// A resource selected by a vault URI.
#[derive(Debug)]
pub enum Resource {
    /// A secret value.
    Secret(Response<SecretValue>),
    /// A certificate.
    Certificate(Response<Certificate>),
    /// Key metadata and any exportable key material.
    Key(Response<Key>),
}

impl Registry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a configured client under a unique name.
    ///
    /// Duplicate names are rejected without replacing the existing client.
    pub fn register(&mut self, name: &str, client: Client) -> Result<()> {
        // Validate exactly the same namespace accepted by URI parsing.
        let uri = format!("nv://{name}/secrets/check");
        let parsed: VaultUri = uri.parse()?;
        if parsed.vault != name {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid registry name"));
        }
        if self.clients.contains_key(name) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "vault is already registered",
            ));
        }
        self.clients.insert(name.to_owned(), client);
        Ok(())
    }

    /// Registers a shared driver using the default client settings.
    pub fn register_driver(&mut self, name: &str, driver: Arc<dyn Driver>) -> Result<()> {
        self.register(name, Client::from_shared(driver))
    }

    /// Gets a client for direct access to its core API.
    pub fn client(&self, name: &str) -> Result<&Client> {
        self.clients
            .get(name)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "vault is not registered"))
    }

    /// Resolves and reads a URI. Query parameters are rejected until defined.
    pub fn get_uri(&self, uri: &str) -> Result<Resource> {
        let uri: VaultUri = uri.parse()?;
        if !uri.params.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "URI query parameters are not supported",
            ));
        }
        let client = self.client(&uri.vault)?;
        let options = GetOptions {
            version: uri.version,
            ..GetOptions::default()
        };
        match uri.kind {
            ResourceKind::Secret => client
                .get_with(&uri.vault, &uri.name, &options)
                .map(Resource::Secret),
            ResourceKind::Certificate => client
                .get_certificate(&uri.vault, &uri.name, &options)
                .map(Resource::Certificate),
            ResourceKind::Key => client
                .get_key(&uri.vault, &uri.name, &options)
                .map(Resource::Key),
        }
    }
}
