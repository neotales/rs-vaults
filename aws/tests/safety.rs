use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_secretsmanager::config::{BehaviorVersion, Region};
use neotales_vaults_aws::{AwsDriver, Config, removal_with_recovery_days};
use neotales_vaults_core::{Client, ErrorKind, RemoveOptions, SecretValue};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

fn sdk(endpoint: String) -> aws_types::SdkConfig {
    aws_types::SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .retry_config(aws_smithy_types::retry::RetryConfig::standard().with_max_attempts(4))
        .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
            "test", "test", None, None, "fixture",
        )))
        .build()
}

#[test]
fn custom_http_requires_explicit_literal_loopback() {
    for endpoint in [
        "http://example.com",
        "http://localhost:4566",
        "https://user@example.com",
    ] {
        assert_eq!(
            AwsDriver::new(Config {
                vault: "v".into(),
                sdk: sdk(endpoint.into()),
                allow_http_loopback: true
            })
            .err()
            .unwrap()
            .kind,
            ErrorKind::InvalidInput
        );
    }
    assert!(
        AwsDriver::new(Config {
            vault: "v".into(),
            sdk: sdk("http://127.0.0.1:4566".into()),
            allow_http_loopback: false
        })
        .is_err()
    );
}

#[test]
fn deletion_options_are_validated_before_network_access() {
    let client = Client::new(
        AwsDriver::new(Config {
            vault: "v".into(),
            sdk: sdk("http://127.0.0.1:1".into()),
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    assert!(removal_with_recovery_days(6).is_err());
    let mut options = removal_with_recovery_days(7).unwrap();
    options.purge = true;
    assert_eq!(
        client
            .remove_secret("v", "name", &options)
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    let options = RemoveOptions {
        version: Some("v1".into()),
        ..Default::default()
    };
    assert_eq!(
        client
            .remove_secret("v", "name", &options)
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
}

#[test]
fn purge_and_recovery_window_have_distinct_requests() {
    for (options, expected) in [
        (
            RemoveOptions {
                purge: true,
                ..Default::default()
            },
            r#""ForceDeleteWithoutRecovery":true"#,
        ),
        (
            removal_with_recovery_days(7).unwrap(),
            r#""RecoveryWindowInDays":7"#,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut all = Vec::new();
            let mut buf = [0; 4096];
            let end = loop {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                all.extend_from_slice(&buf[..n]);
                if let Some(pos) = all.windows(4).position(|part| part == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let headers = String::from_utf8_lossy(&all[..end]);
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            while all.len() < end + length {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                all.extend_from_slice(&buf[..n]);
            }
            let body = "{}";
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            String::from_utf8(all).unwrap()
        });
        let client = Client::new(
            AwsDriver::new(Config {
                vault: "v".into(),
                sdk: sdk(address),
                allow_http_loopback: true,
            })
            .unwrap(),
        );
        client.remove_secret("v", "name", &options).unwrap();
        let request = worker.join().unwrap();
        assert!(request.contains(expected));
        assert!(
            request
                .to_lowercase()
                .contains("secretsmanager.deletesecret")
        );
    }
}

#[test]
fn sdk_does_not_retry_failed_writes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut count = 0;
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                count += 1;
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut buf = [0; 8192];
                let _ = stream.read(&mut buf);
                let body = r#"{"__type":"InternalServiceError","message":"failed"}"#;
                write!(stream, "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            } else {
                thread::sleep(Duration::from_millis(10));
            }
        }
        count
    });
    let client = Client::new(
        AwsDriver::new(Config {
            vault: "v".into(),
            sdk: sdk(address),
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    assert!(
        client
            .set_secret("v", "secret", &SecretValue::new(b"value".to_vec()))
            .is_err()
    );
    assert_eq!(worker.join().unwrap(), 1);
}
