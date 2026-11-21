use neotales_vaults_azure::{AzureDriver, Config};
use neotales_vaults_core::{Client, ErrorKind, GetOptions, RemoveOptions, SecretValue};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

fn read_from_fixture(id: &'static str, version: Option<&str>) -> ErrorKind {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0; 4096];
        let _ = stream.read(&mut buf).unwrap();
        let body = format!(r#"{{"id":"{id}","value":"sensitive-value"}}"#);
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
    });
    let client = Client::new(
        AzureDriver::new(Config {
            vault: "v".into(),
            address,
            token: SecretValue::new(b"test".to_vec()),
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    let result = client
        .get_with(
            "v",
            "expected",
            &GetOptions {
                version: version.map(str::to_owned),
                retry: None,
            },
        )
        .unwrap_err();
    worker.join().unwrap();
    assert!(!result.to_string().contains("sensitive-value"));
    result.kind
}

#[test]
fn wrong_secret_or_version_is_rejected() {
    assert_eq!(
        read_from_fixture("https://example.test/secrets/other/one", None),
        ErrorKind::Provider
    );
    assert_eq!(
        read_from_fixture("https://example.test/secrets/expected/two", Some("one")),
        ErrorKind::Provider
    );
    assert_eq!(
        read_from_fixture("https://example.test/unrelated/expected/one", None),
        ErrorKind::Provider
    );
    assert_eq!(
        read_from_fixture("https://example.test/secrets/expected/one?other=x", None),
        ErrorKind::Provider
    );
}

#[test]
fn lists_pages_and_deletes_or_purges_separately() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let origin = address.clone();
    let worker = thread::spawn(move || {
        let mut requests = Vec::new();
        for n in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 8192];
            let count = stream.read(&mut buf).unwrap();
            requests.push(String::from_utf8_lossy(&buf[..count]).into_owned());
            let body = match n {
                0 => format!(
                    r#"{{"value":[{{"id":"{origin}/secrets/alpha"}}],"nextLink":"{origin}/secrets?api-version=7.4&skiptoken=next"}}"#
                ),
                1 => format!(r#"{{"value":[{{"id":"{origin}/secrets/beta"}}]}}"#),
                _ => String::new(),
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
        requests
    });
    let client = Client::new(
        AzureDriver::new(Config {
            vault: "v".into(),
            address,
            token: SecretValue::new(b"test".to_vec()),
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    assert_eq!(client.list_secrets("v").unwrap(), vec!["alpha", "beta"]);
    client
        .remove_secret("v", "alpha", &RemoveOptions::default())
        .unwrap();
    client
        .remove_secret(
            "v",
            "alpha",
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    let requests = worker.join().unwrap();
    assert!(requests[2].starts_with("DELETE /secrets/alpha?api-version=7.4 "));
    assert!(requests[3].starts_with("DELETE /deletedsecrets/alpha?api-version=7.4 "));
}

#[test]
fn rejects_untrusted_pagination_before_forwarding_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0; 4096];
        let _ = stream.read(&mut buf).unwrap();
        let body = r#"{"value":[],"nextLink":"https://evil.example/secrets?api-version=7.4"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let client = Client::new(
        AzureDriver::new(Config {
            vault: "v".into(),
            address,
            token: SecretValue::new(b"test".to_vec()),
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    assert_eq!(
        client.list_secrets("v").unwrap_err().kind,
        ErrorKind::Provider
    );
    worker.join().unwrap();
}
