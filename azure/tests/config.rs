use neotales_vaults_azure::{AzureDriver, Config};
use neotales_vaults_core::{Capability, Client, ErrorKind, GetOptions, SecretValue};

fn config(address: &str, allow_http_loopback: bool) -> Config {
    Config {
        vault: "v".into(),
        address: address.into(),
        token: SecretValue::new(b"test-token".to_vec()),
        allow_http_loopback,
    }
}

#[test]
fn rejects_insecure_endpoints_and_bad_inputs_before_network() {
    for address in [
        "http://example.com",
        "http://localhost:1234",
        "https://user@example.com",
        "https://example.com/?token=secret",
    ] {
        assert_eq!(
            AzureDriver::new(config(address, true)).err().unwrap().kind,
            ErrorKind::InvalidInput
        );
    }
    assert!(AzureDriver::new(config("http://127.0.0.1:1", false)).is_err());
    let client = Client::new(AzureDriver::new(config("http://127.0.0.1:1", true)).unwrap());
    assert!(client.supports(Capability::GetSecret));
    assert!(!client.supports(Capability::GetKey));
    assert_eq!(
        client.get("v", "../secret").unwrap_err().kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(
        client
            .get_with(
                "v",
                "secret",
                &GetOptions {
                    version: Some("../bad".into()),
                    retry: None
                }
            )
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(
        client
            .set_secret("v", "secret", &SecretValue::new(vec![0xff]))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
}
