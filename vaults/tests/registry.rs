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

#[test]
fn ensure_url_generates_and_reuses_secrets() {
    use neotales_vaults::core::{Error, Result};
    use std::sync::Mutex;
    #[derive(Default)]
    struct Store(Mutex<std::collections::HashMap<String, SecretValue>>);
    impl Driver for Store {
        fn supports(&self, capability: Capability) -> bool {
            matches!(capability, Capability::GetSecret | Capability::SetSecret)
        }
        fn get_secret(&self, _: &str, name: &str, _: &GetOptions) -> Result<Response<SecretValue>> {
            self.0
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .map(|value| Response {
                    value,
                    metadata: Metadata::default(),
                })
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "missing"))
        }
        fn set_secret(&self, _: &str, name: &str, value: &SecretValue) -> Result<Metadata> {
            self.0.lock().unwrap().insert(name.into(), value.clone());
            Ok(Metadata::default())
        }
    }
    let mut registry = Registry::new();
    registry
        .register("work", Client::new(Store::default()))
        .unwrap();
    let Resource::Secret(first) = registry
        .get_uri("nv://work/secrets/token?ensure=1&U=1&size=30")
        .unwrap()
    else {
        panic!("wrong resource")
    };
    let text = std::str::from_utf8(first.value.expose()).unwrap();
    assert_eq!(text.len(), 30);
    assert!(text.chars().any(|c| c.is_ascii_uppercase()));
    assert!(text.chars().any(|c| c.is_ascii_lowercase()));
    assert!(text.chars().any(|c| c.is_ascii_digit()));
    assert!(text.chars().any(|c| !c.is_ascii_alphanumeric()));
    let Resource::Secret(existing) = registry
        .get_uri("nv://work/secrets/token?ensure=true&c=x&s=8")
        .unwrap()
    else {
        panic!("wrong resource")
    };
    assert_eq!(existing.value, first.value);
    let Resource::Secret(custom) = registry
        .get_uri("nv://work/secrets/custom?ensure=true&c=x&s=8&U=0&L=false&D=0&S=false")
        .unwrap()
    else {
        panic!("wrong resource")
    };
    assert_eq!(custom.value.expose(), b"xxxxxxxx");
    let Resource::Secret(default) = registry
        .get_uri("nv://work/secrets/default?ensure=true")
        .unwrap()
    else {
        panic!("wrong resource")
    };
    assert_eq!(
        std::str::from_utf8(default.value.expose())
            .unwrap()
            .chars()
            .count(),
        16
    );
    for url in [
        "nv://work/secrets/a?ensure=1&upper=1&U=0",
        "nv://work/secrets/a?ensure=maybe",
        "nv://work/secrets/a?ensure=0&size=12",
        "nv://work/secrets/a/v1?ensure=1",
        "nv://work/certs/a?ensure=1",
        "nv://work/secrets/a?ensure=1&size=0",
    ] {
        assert_eq!(
            registry.get_uri(url).unwrap_err().kind,
            ErrorKind::InvalidInput
        );
    }
}
