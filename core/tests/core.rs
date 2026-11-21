use neotales_vaults_core::{
    Capability, Client, Delay, Driver, Error, ErrorKind, GetOptions, Metadata, RemoveOptions,
    ResourceKind, Response, RetryPolicy, SecretMetadata, SecretValue, SetSecretOptions, VaultUri,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

struct Example(Arc<AtomicUsize>);
impl Driver for Example {
    fn supports(&self, capability: Capability) -> bool {
        capability == Capability::GetSecret
    }
    fn get_secret(
        &self,
        _: &str,
        _: &str,
        options: &GetOptions,
    ) -> Result<Response<SecretValue>, Error> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(Error::new(ErrorKind::Transient, "temporary"));
        }
        Ok(Response {
            value: SecretValue::new(b"redaction-test-value".to_vec()),
            metadata: Metadata {
                version: options.version.clone(),
                ..Metadata::default()
            },
        })
    }
}

#[test]
fn retry_and_version() {
    let count = Arc::new(AtomicUsize::new(0));
    let client = Client::new(Example(count.clone()))
        .with_retry_policy(RetryPolicy::new(2, Delay::Fixed(Duration::ZERO)).unwrap());
    let result = client
        .get_with(
            "work",
            "key",
            &GetOptions {
                version: Some("2".into()),
                retry: None,
            },
        )
        .unwrap();
    assert_eq!(result.value.expose(), b"redaction-test-value");
    assert_eq!(result.metadata.version.as_deref(), Some("2"));
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(
        client
            .get_key("work", "key", &GetOptions::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert!(!format!("{result:?}").contains("redaction-test-value"));
}

#[test]
fn uri_validation() {
    let uri: VaultUri = "nv://work/secrets/hello%20world/v1?a=b&a=c"
        .parse()
        .unwrap();
    assert_eq!(uri.kind, ResourceKind::Secret);
    assert_eq!(uri.name, "hello world");
    assert_eq!(uri.params.len(), 2);
    for bad in [
        "nsv://work/secrets/x",
        "nv://work/secrets/..",
        "nv://work/secrets/%2F",
        "nv://work/secrets/%",
        "nv://work/secrets/x#frag",
        "nv://u@work/secrets/x",
        "nv://work/secrets/x/",
    ] {
        assert!(bad.parse::<VaultUri>().is_err(), "{bad}");
    }
}

#[test]
fn method_policy_overrides_client_policy() {
    let count = Arc::new(AtomicUsize::new(0));
    let client = Client::new(Example(count.clone()))
        .with_retry_policy(RetryPolicy::new(2, Delay::Fixed(Duration::ZERO)).unwrap());
    let options = GetOptions {
        version: None,
        retry: Some(RetryPolicy::new(1, Delay::Fixed(Duration::ZERO)).unwrap()),
    };
    assert_eq!(
        client.get_with("work", "key", &options).unwrap_err().kind,
        ErrorKind::Transient
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn writes_are_not_retried_even_with_a_retry_policy() {
    struct FailingWriter(Arc<AtomicUsize>);
    impl Driver for FailingWriter {
        fn supports(&self, capability: Capability) -> bool {
            capability == Capability::SetSecret
        }
        fn set_secret(&self, _: &str, _: &str, _: &SecretValue) -> Result<Metadata, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Error::new(ErrorKind::Transient, "unknown outcome"))
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let client = Client::new(FailingWriter(count.clone()))
        .with_retry_policy(RetryPolicy::new(3, Delay::Fixed(Duration::ZERO)).unwrap());
    assert_eq!(
        client
            .set_secret("v", "n", &SecretValue::new(b"value".to_vec()))
            .unwrap_err()
            .kind,
        ErrorKind::Transient
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        Client::new(Example(count.clone()))
            .set_secret("v", "n", &SecretValue::new(vec![]))
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn removal_forwards_options_and_never_retries() {
    struct Remover(Arc<AtomicUsize>);
    impl Driver for Remover {
        fn supports(&self, capability: Capability) -> bool {
            capability == Capability::RemoveSecret
        }
        fn remove_secret(&self, _: &str, _: &str, options: &RemoveOptions) -> Result<(), Error> {
            assert!(options.purge);
            assert_eq!(options.version.as_deref(), Some("version"));
            assert_eq!(
                options.query.get("option").map(String::as_str),
                Some("value")
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Error::new(ErrorKind::Transient, "unknown outcome"))
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let client = Client::new(Remover(count.clone()))
        .with_retry_policy(RetryPolicy::new(3, Delay::Fixed(Duration::ZERO)).unwrap());
    let options = RemoveOptions {
        purge: true,
        version: Some("version".into()),
        query: [("option".into(), "value".into())].into(),
    };
    assert_eq!(
        client
            .remove_secret("v", "name", &options)
            .unwrap_err()
            .kind,
        ErrorKind::Transient
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        client.remove_key("v", "name", &options).unwrap_err().kind,
        ErrorKind::Unsupported
    );
}

#[test]
fn unsupported_metadata_is_never_silently_discarded() {
    struct Writer(Arc<AtomicUsize>);
    impl Driver for Writer {
        fn supports(&self, capability: Capability) -> bool {
            capability == Capability::SetSecret
        }
        fn set_secret(&self, _: &str, _: &str, _: &SecretValue) -> Result<Metadata, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Metadata::default())
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let client = Client::new(Writer(count.clone()));
    let options = SetSecretOptions {
        metadata: SecretMetadata {
            enabled: false,
            ..SecretMetadata::default()
        },
    };
    assert_eq!(
        client
            .set_secret_with("v", "x", &SecretValue::new(b"value".to_vec()), &options)
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn metrics_record_operations_and_retries_without_names_or_values() {
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<metrics::Key>>);
    impl metrics::Recorder for Recorder {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            self.0.lock().unwrap().push(key.clone());
            metrics::Counter::noop()
        }
        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }
        fn register_histogram(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            self.0.lock().unwrap().push(key.clone());
            metrics::Histogram::noop()
        }
    }
    let recorder = Recorder::default();
    metrics::with_local_recorder(&recorder, || {
        let count = Arc::new(AtomicUsize::new(0));
        let client = Client::new(Example(count))
            .with_retry_policy(RetryPolicy::new(2, Delay::Fixed(Duration::ZERO)).unwrap());
        client
            .get("vault-sensitive-name", "secret-sensitive-name")
            .unwrap();
        let _ = client.get_key(
            "vault-sensitive-name",
            "secret-sensitive-name",
            &GetOptions::default(),
        );
    });
    let keys = recorder.0.lock().unwrap();
    assert!(
        keys.iter()
            .any(|key| key.name() == "neotales_vaults_retries_total")
    );
    assert!(
        keys.iter()
            .any(|key| key.name() == "neotales_vaults_operations_total")
    );
    assert!(
        keys.iter()
            .any(|key| key.name() == "neotales_vaults_operation_duration_seconds")
    );
    for key in keys.iter() {
        let text = format!("{key:?}");
        assert!(!text.contains("vault-sensitive-name"));
        assert!(!text.contains("secret-sensitive-name"));
        assert!(!text.contains("redaction-test-value"));
    }
}

#[test]
fn resilience_does_not_retry_nontransient_read_errors() {
    struct Denied(Arc<AtomicUsize>);
    impl Driver for Denied {
        fn supports(&self, capability: Capability) -> bool {
            capability == Capability::GetSecret
        }
        fn get_secret(
            &self,
            _: &str,
            _: &str,
            _: &GetOptions,
        ) -> Result<Response<SecretValue>, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Error::new(ErrorKind::PermissionDenied, "denied"))
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let client = Client::new(Denied(count.clone()))
        .with_retry_policy(RetryPolicy::new(3, Delay::Fixed(Duration::ZERO)).unwrap());
    assert_eq!(
        client.get("v", "n").unwrap_err().kind,
        ErrorKind::PermissionDenied
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}
