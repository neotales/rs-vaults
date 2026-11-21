use neotales_vaults_core::{Client, ErrorKind, GetOptions, RemoveOptions, SecretValue};
use neotales_vaults_gcp::{Config, GcpDriver, removal_with_etag};

fn config(endpoint: &str, allow: bool) -> Config {
    Config {
        vault: "v".into(),
        project: "project".into(),
        endpoint: endpoint.into(),
        token: SecretValue::new(b"test".to_vec()),
        allow_http_loopback: allow,
    }
}

#[test]
fn rejects_insecure_config_and_invalid_resources_before_io() {
    for endpoint in [
        "http://example.com",
        "http://localhost:1",
        "https://user@example.com",
        "https://example.com/prefix",
    ] {
        assert_eq!(
            GcpDriver::new(config(endpoint, true)).err().unwrap().kind,
            ErrorKind::InvalidInput
        );
    }
    assert!(GcpDriver::new(config("http://127.0.0.1:1", false)).is_err());
    let client = Client::new(GcpDriver::new(config("http://127.0.0.1:1", true)).unwrap());
    assert_eq!(
        client.get("v", "../bad").unwrap_err().kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(
        client
            .get_with(
                "v",
                "secret",
                &GetOptions {
                    version: Some("latest".into()),
                    retry: None
                }
            )
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(
        removal_with_etag("").unwrap_err().kind,
        ErrorKind::InvalidInput
    );
    let invalid = RemoveOptions {
        version: Some("0".into()),
        ..Default::default()
    };
    assert_eq!(
        client
            .remove_secret("v", "secret", &invalid)
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    let mut invalid = removal_with_etag("etag").unwrap();
    invalid.query.insert("unknown".into(), "value".into());
    assert_eq!(
        client
            .remove_secret("v", "secret", &invalid)
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
}
