use neotales_vaults::{
    Registry, Resource,
    core::{Capability, Client, Driver, ErrorKind, GetOptions, Metadata, Response, SecretValue},
};

struct Mock;
impl Driver for Mock {
    fn supports(&self, capability: Capability) -> bool {
        capability == Capability::GetSecret
    }
    fn get_secret(
        &self,
        vault: &str,
        name: &str,
        options: &GetOptions,
    ) -> neotales_vaults::core::Result<Response<SecretValue>> {
        Ok(Response {
            value: SecretValue::new(format!("{vault}/{name}")),
            metadata: Metadata {
                version: options.version.clone(),
                ..Metadata::default()
            },
        })
    }
}

#[test]
fn resolves_and_rejects_ambiguous_references() {
    let mut registry = Registry::new();
    registry.register("work", Client::new(Mock)).unwrap();
    assert!(registry.register("work", Client::new(Mock)).is_err());
    let Resource::Secret(result) = registry.get_uri("nv://work/secrets/api/v2").unwrap() else {
        panic!("wrong kind")
    };
    assert_eq!(result.value.expose(), b"work/api");
    assert_eq!(result.metadata.version.as_deref(), Some("v2"));
    assert_eq!(
        registry
            .get_uri("nv://work/secrets/api?version=v2")
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(
        registry
            .get_uri("nv://unknown/secrets/api")
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        registry.get_uri("nv://work/certs/api").unwrap_err().kind,
        ErrorKind::Unsupported
    );
}
