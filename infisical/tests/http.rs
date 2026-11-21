use neotales_vaults_core::{Client, ErrorKind, GetOptions, RemoveOptions, SecretValue};
use neotales_vaults_infisical::{Config, InfisicalDriver};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
};

fn fixture(
    responses: Vec<(u16, &'static str)>,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 2048];
            let header_end = loop {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
                if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap_or(0);
            while bytes.len() < header_end + length {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
            }
            tx.send(String::from_utf8(bytes).unwrap()).unwrap();
            write!(stream, "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    (address, rx, handle)
}

fn client(address: String) -> Client {
    Client::new(
        InfisicalDriver::new(Config {
            vault: "work".into(),
            address,
            project_id: "project".into(),
            environment: "dev".into(),
            secret_path: "/apps/demo".into(),
            token: SecretValue::new(b"test-token".to_vec()),
            allow_http_loopback: true,
        })
        .unwrap(),
    )
}

#[test]
fn lists_shared_names_without_requesting_values() {
    let (address, rx, worker) = fixture(vec![(
        200,
        r#"{"secrets":[{"secretKey":"alpha","type":"shared"}]}"#,
    )]);
    assert_eq!(client(address).list_secrets("work").unwrap(), vec!["alpha"]);
    let request = rx.recv().unwrap();
    assert!(request.starts_with("GET /api/v4/secrets?"));
    assert!(request.contains("viewSecretValue=false"));
    assert!(request.contains("includeImports=false"));
    worker.join().unwrap();
}

#[test]
fn deletion_requires_confirmed_secret_not_approval() {
    let (address, rx, worker) = fixture(vec![
        (
            200,
            r#"{"secret":{"secretKey":"name","secretValue":"hidden"}}"#,
        ),
        (200, r#"{"approval":{"id":"pending"}}"#),
    ]);
    let c = client(address);
    c.remove_secret("work", "name", &RemoveOptions::default())
        .unwrap();
    assert_eq!(
        c.remove_secret("work", "name", &RemoveOptions::default())
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
    let request = rx.recv().unwrap();
    assert!(request.starts_with("DELETE /api/v4/secrets/name "));
    assert!(request.contains(r#""projectId":"project""#));
    assert!(request.contains(r#""type":"shared""#));
    let _ = rx.recv().unwrap();
    worker.join().unwrap();
}

#[test]
fn reads_shared_secret_with_encoded_path() {
    let (address, rx, thread) = fixture(vec![(
        200,
        r#"{"secret":{"secretValue":"hello","secretValueHidden":false}}"#,
    )]);
    assert_eq!(
        client(address).get("work", "a?b").unwrap().value.expose(),
        b"hello"
    );
    let request = rx.recv().unwrap();
    assert!(request.starts_with("GET /api/v4/secrets/a%3Fb?"));
    assert!(request.contains("projectId=project"));
    assert!(request.contains("secretPath=%2Fapps%2Fdemo"));
    assert!(request.contains("includePersonalOverrides=false"));
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer test-token")
    );
    thread.join().unwrap();
}

#[test]
fn chooses_create_only_on_confirmed_not_found() {
    for (status, expected_method) in [(200, "PATCH"), (404, "POST")] {
        let (address, rx, thread) = fixture(vec![(status, "{}"), (200, "{}")]);
        client(address)
            .set_secret("work", "name", &SecretValue::new(b"new-value".to_vec()))
            .unwrap();
        assert!(rx.recv().unwrap().starts_with("GET "));
        let request = rx.recv().unwrap();
        assert!(request.starts_with(expected_method));
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["projectId"], "project");
        assert_eq!(body["environment"], "dev");
        assert_eq!(body["secretPath"], "/apps/demo");
        assert_eq!(body["secretValue"], "new-value");
        assert_eq!(body["type"], "shared");
        assert_eq!(body["skipMultilineEncoding"], true);
        thread.join().unwrap();
    }
}

#[test]
fn access_denied_does_not_become_create() {
    let (address, rx, thread) = fixture(vec![(403, "secret-response")]);
    let error = client(address)
        .set_secret("work", "name", &SecretValue::new(b"x".to_vec()))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::PermissionDenied);
    assert!(!format!("{error:?}").contains("secret-response"));
    rx.recv().unwrap();
    thread.join().unwrap();
}

#[test]
fn rejects_unsafe_or_unavailable_inputs() {
    let c = client("http://127.0.0.1:1".into());
    assert_eq!(
        c.get("work", "../x").unwrap_err().kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(
        c.get_with(
            "work",
            "x",
            &GetOptions {
                version: Some("1".into()),
                retry: None
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(
        c.set_secret("work", "x", &SecretValue::new(vec![0xff]))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    let config = Config {
        vault: "work".into(),
        address: "http://example.com".into(),
        project_id: "project".into(),
        environment: "dev".into(),
        secret_path: "/".into(),
        token: SecretValue::new(b"token".to_vec()),
        allow_http_loopback: true,
    };
    assert!(InfisicalDriver::new(config).is_err());
}

#[test]
fn hidden_secret_is_not_returned() {
    let (address, rx, thread) = fixture(vec![(
        200,
        r#"{"secret":{"secretValue":"do-not-expose","secretValueHidden":true}}"#,
    )]);
    let error = client(address).get("work", "x").unwrap_err();
    assert_eq!(error.kind, ErrorKind::PermissionDenied);
    assert!(!format!("{error:?}").contains("do-not-expose"));
    rx.recv().unwrap();
    thread.join().unwrap();
}
