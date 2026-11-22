use neotales_vaults_core::{
    Client, EnsureSecret, ErrorKind, GetOptions, RemoveOptions, SecretValue,
};
use neotales_vaults_vault::{Config, VaultDriver};
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
        VaultDriver::new(Config {
            vault: "work".into(),
            address,
            mount: "secret".into(),
            token: SecretValue::new(b"test-token".to_vec()),
            namespace: Some("ns".into()),
            allow_http_loopback: true,
        })
        .unwrap(),
    )
}

#[test]
fn ensure_creates_with_cas_and_reads_concurrent_winner() {
    let (address, rx, worker) = fixture(vec![
        (404, "{}"),
        (400, "{}"),
        (
            200,
            r#"{"data":{"data":{"value":"winner"},"metadata":{"version":1}}}"#,
        ),
    ]);
    let result = client(address)
        .ensure_value("work", "name", &SecretValue::new(b"candidate".to_vec()))
        .unwrap();
    assert_eq!(result.value.expose(), b"winner");
    assert!(rx.recv().unwrap().starts_with("GET "));
    let create = rx.recv().unwrap();
    assert!(create.starts_with("POST /v1/secret/data/name "));
    assert!(create.contains(r#""cas":0"#));
    assert!(rx.recv().unwrap().starts_with("GET "));
    worker.join().unwrap();
}

#[test]
fn removal_selects_kv_v2_endpoints() {
    let (address, rx, thread) = fixture(vec![(204, ""), (204, ""), (204, ""), (204, "")]);
    let c = client(address);
    for (purge, version) in [
        (false, None),
        (false, Some("2")),
        (true, Some("3")),
        (true, None),
    ] {
        c.remove_secret(
            "work",
            "token",
            &RemoveOptions {
                purge,
                version: version.map(str::to_owned),
                ..Default::default()
            },
        )
        .unwrap();
    }
    let requests: Vec<_> = (0..4).map(|_| rx.recv().unwrap()).collect();
    assert!(requests[0].starts_with("DELETE /v1/secret/data/token "));
    assert!(requests[1].starts_with("POST /v1/secret/delete/token "));
    assert!(requests[1].ends_with("{\"versions\":[2]}"));
    assert!(requests[2].starts_with("POST /v1/secret/destroy/token "));
    assert!(requests[2].ends_with("{\"versions\":[3]}"));
    assert!(requests[3].starts_with("DELETE /v1/secret/metadata/token "));
    thread.join().unwrap();
}

#[test]
fn listing_traverses_folders_and_uses_metadata_api() {
    let (address, rx, worker) = fixture(vec![
        (200, r#"{"data":{"keys":["alpha","nested/","zeta"]}}"#),
        (200, r#"{"data":{"keys":["token"]}}"#),
    ]);
    assert_eq!(
        client(address).list_secrets("work").unwrap(),
        vec!["alpha", "nested/token", "zeta"]
    );
    let request = rx.recv().unwrap();
    assert!(request.starts_with("GET /v1/secret/metadata?list=true "));
    assert!(request.to_lowercase().contains("x-vault-namespace: ns"));
    assert!(
        rx.recv()
            .unwrap()
            .starts_with("GET /v1/secret/metadata/nested?list=true ")
    );
    worker.join().unwrap();
}

#[test]
fn empty_vault_list_is_empty() {
    let (address, _rx, worker) = fixture(vec![(404, "{}")]);
    assert!(client(address).list_secrets("work").unwrap().is_empty());
    worker.join().unwrap();
}

#[test]
fn reads_version_with_safe_escaping() {
    let (address, rx, thread) = fixture(vec![(
        200,
        r#"{"data":{"data":{"value":"hello"},"metadata":{"version":3,"destroyed":false,"deletion_time":""}}}"#,
    )]);
    let result = client(address)
        .get_with(
            "work",
            "a?b",
            &GetOptions {
                version: Some("3".into()),
                retry: None,
            },
        )
        .unwrap();
    assert_eq!(result.value.expose(), b"hello");
    assert_eq!(result.metadata.version.as_deref(), Some("3"));
    let request = rx.recv().unwrap().to_lowercase();
    assert!(request.starts_with("get /v1/secret/data/a%3fb?version=3 "));
    assert!(request.contains("x-vault-token: test-token"));
    assert!(request.contains("x-vault-namespace: ns"));
    thread.join().unwrap();
}

#[test]
fn create_fallback_is_cas_protected() {
    let (address, rx, thread) = fixture(vec![(404, "{}"), (200, "{}")]);
    client(address)
        .set_secret("work", "key", &SecretValue::new(b"hello".to_vec()))
        .unwrap();
    let patch = rx.recv().unwrap();
    let post = rx.recv().unwrap();
    assert!(patch.starts_with("PATCH /v1/secret/data/key "));
    assert!(
        patch
            .to_lowercase()
            .contains("content-type: application/merge-patch+json")
    );
    assert!(post.starts_with("POST /v1/secret/data/key "));
    let body: serde_json::Value =
        serde_json::from_str(post.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["options"]["cas"], 0);
    assert_eq!(body["data"]["value"], "hello");
    thread.join().unwrap();
}

#[test]
fn rejects_insecure_config_and_invalid_names_before_io() {
    let c = Config {
        vault: "work".into(),
        address: "http://example.com".into(),
        mount: "secret".into(),
        token: SecretValue::new(b"test".to_vec()),
        namespace: None,
        allow_http_loopback: true,
    };
    assert!(VaultDriver::new(c).is_err());
    let c = client("http://127.0.0.1:1".into());
    assert_eq!(
        c.get("work", "../other").unwrap_err().kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(
        c.get_with(
            "work",
            "x",
            &GetOptions {
                version: Some("0".into()),
                retry: None
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidInput
    );
    assert_eq!(
        c.set_secret("work", "x", &SecretValue::new(vec![0xff]))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
}

#[test]
fn does_not_expose_response_body_on_error() {
    let (address, rx, thread) = fixture(vec![(403, "sensitive-response")]);
    let error = client(address).get("work", "x").unwrap_err();
    assert_eq!(error.kind, ErrorKind::PermissionDenied);
    assert!(!format!("{error:?}").contains("sensitive-response"));
    rx.recv().unwrap();
    thread.join().unwrap();
}

#[test]
fn rejects_unexpected_server_version() {
    let (address, rx, thread) = fixture(vec![(
        200,
        r#"{"data":{"data":{"value":"hello"},"metadata":{"version":2}}}"#,
    )]);
    let error = client(address)
        .get_with(
            "work",
            "x",
            &GetOptions {
                version: Some("3".into()),
                retry: None,
            },
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Provider);
    rx.recv().unwrap();
    thread.join().unwrap();
}
