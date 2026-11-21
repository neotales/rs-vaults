//! Disposable Vaultwarden and Bitwarden Lite tests using a real Bitwarden CLI.
#![cfg(unix)]

use aes::Aes256;
use base64::{Engine, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use neotales_vaults_core::{Client, RemoveOptions, SecretValue};
use neotales_vaults_vaultwarden::{Config, VaultwardenDriver};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use testcontainers::{
    GenericImage, ImageExt,
    bollard::models::PortBinding,
    core::{ExecCommand, IntoContainerPort, WaitFor},
    runners::SyncRunner,
};
use wait_timeout::ChildExt;

const EMAIL: &str = "vaults-test@example.invalid";
const PASSWORD: &str = "disposable-test-password";
const IMAGE_NAME: &str = "vaultwarden/server:1.37.5@sha256";
const IMAGE_DIGEST: &str = "4fe17f415f90087377d37c755e0ea3cf189dcc6794e49cdd2a9adbb4937d9e1f";

struct Proxy(Child);
impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn post(agent: &ureq::Agent, url: &str, body: Value) -> String {
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .unwrap();
    if !response.status().is_success() {
        let status = response.status();
        let body = response.body_mut().read_to_string().unwrap_or_default();
        let detail: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let fields = detail["validationErrors"]
            .as_object()
            .map(|m| m.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let reasons = detail["validationErrors"][""]
            .as_array()
            .cloned()
            .unwrap_or_default();
        panic!(
            "fixture registration failed ({status}) at {url}: {} fields={fields:?} reasons={reasons:?}",
            detail["message"].as_str().unwrap_or("no message")
        );
    }
    response.body_mut().read_to_string().unwrap()
}
fn pbkdf(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut output = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);
    output
}
fn expand(key: &[u8], info: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(info);
    mac.update(&[1]);
    mac.finalize().into_bytes().into()
}
fn encstring(enc: &[u8], mac_key: &[u8], plaintext: &[u8]) -> String {
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).unwrap();
    let ciphertext = cbc::Encryptor::<Aes256>::new_from_slices(enc, &iv)
        .unwrap()
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
    mac.update(&iv);
    mac.update(&ciphertext);
    format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(&ciphertext),
        STANDARD.encode(mac.finalize().into_bytes())
    )
}
fn register(base: &str, mail: Option<&str>) {
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent();
    let mut token = post(
        &agent,
        &format!("{base}/identity/accounts/register/send-verification-email"),
        json!({"email":EMAIL,"name":"disposable"}),
    );
    if token.trim().is_empty() {
        let mail = mail.expect("registration requires a disposable SMTP capture");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let mut response = agent.get(format!("{mail}/api/v1/messages")).call().unwrap();
            let listing: Value =
                serde_json::from_str(&response.body_mut().read_to_string().unwrap()).unwrap();
            if let Some(id) = listing["messages"]
                .as_array()
                .and_then(|m| m.first())
                .and_then(|m| m["ID"].as_str())
            {
                let mut response = agent
                    .get(format!("{mail}/api/v1/message/{id}"))
                    .call()
                    .unwrap();
                let message: Value =
                    serde_json::from_str(&response.body_mut().read_to_string().unwrap()).unwrap();
                let text = message["Text"].as_str().unwrap_or("");
                let link = text
                    .split_whitespace()
                    .find(|part| part.contains("emailVerificationToken="))
                    .expect("registration email verification link");
                let link = link.trim_matches(|c| c == '<' || c == '>');
                let url = url::Url::parse(link).expect("registration email URL");
                token = url
                    .query_pairs()
                    .find(|(key, _)| key == "emailVerificationToken")
                    .map(|(_, v)| v.into_owned())
                    .expect("registration email token");
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "registration email not received"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    let iterations = if mail.is_some() { 600_000 } else { 100_000 };
    let master = pbkdf(PASSWORD.as_bytes(), EMAIL.as_bytes(), iterations);
    let mut user_key = [0u8; 64];
    getrandom::fill(&mut user_key).unwrap();
    let key = encstring(
        &expand(&master, b"enc"),
        &expand(&master, b"mac"),
        &user_key,
    );
    let asymmetric = if mail.is_some() {
        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let private_der = private.to_pkcs8_der().unwrap();
        let public_der = rsa::RsaPublicKey::from(&private)
            .to_public_key_der()
            .unwrap();
        Some(json!({
            "publicKey": STANDARD.encode(public_der.as_ref()),
            "encryptedPrivateKey": encstring(&user_key[..32], &user_key[32..], private_der.as_bytes()),
        }))
    } else {
        None
    };
    let mut request = json!({
        "email":EMAIL,"kdf":0,"kdfIterations":iterations,"key":key,
        "masterPasswordHash":STANDARD.encode(pbkdf(&master, PASSWORD.as_bytes(), 1)),
        "masterPasswordHint":null,"emailVerificationToken":token.trim()
    });
    if let Some(asymmetric) = asymmetric {
        request["userSymmetricKey"] = key.into();
        request["userAsymmetricKeys"] = asymmetric;
    }
    post(
        &agent,
        &format!("{base}/identity/accounts/register/finish"),
        request,
    );
}
fn run(command: &Path, args: &[&str], session: Option<&str>, input: Option<&[u8]>) -> Vec<u8> {
    let mut cmd = Command::new(command);
    cmd.env_remove("BW_SESSION")
        .env_remove("BW_CLIENTID")
        .env_remove("BW_CLIENTSECRET")
        .arg("--nointeraction")
        .args(args)
        .env("BW_PASSWORD", PASSWORD)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(session) = session {
        cmd.env("BW_SESSION", session);
    }
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd.spawn().expect("start Bitwarden CLI");
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    if child
        .wait_timeout(Duration::from_secs(45))
        .expect("wait for fixture CLI")
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("fixture CLI command {:?} timed out", args.first());
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "fixture CLI command {:?} failed: {}",
        args.first(),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
#[ignore = "requires Docker, openssl, python3 and a pinned Bitwarden CLI"]
fn vaultwarden_cli_reads_and_updates_real_server() {
    let image = GenericImage::new(IMAGE_NAME, IMAGE_DIGEST)
        .with_exposed_port(80.tcp())
        .with_wait_for(WaitFor::message_on_either_std("Rocket has launched"))
        .with_startup_timeout(Duration::from_secs(120))
        .with_env_var("SIGNUPS_ALLOWED", "true")
        .with_env_var("I_REALLY_WANT_VOLATILE_STORAGE", "true")
        .with_env_var("WEB_VAULT_ENABLED", "false")
        .with_host_config_modifier(|config| {
            config.publish_all_ports = Some(false);
            config.port_bindings = Some(std::collections::HashMap::from([(
                "80/tcp".to_owned(),
                Some(vec![PortBinding {
                    host_ip: Some("127.0.0.1".into()),
                    host_port: Some("0".into()),
                }]),
            )]));
        });
    let container = image.start().expect("start isolated Vaultwarden container");
    let port = container.get_host_port_ipv4(80.tcp()).unwrap();
    register(&format!("http://127.0.0.1:{port}"), None);
    exercise_cli(port);
}

#[test]
#[ignore = "requires Docker, openssl, python3 and a pinned Bitwarden CLI"]
fn bitwarden_lite_cli_reads_and_updates_real_server() {
    let mail = GenericImage::new(
        "axllent/mailpit:v1.28.0@sha256",
        "c076638db1e15662150be4fb62b8a6e96ef6ba5bde90c838a0239225854830f7",
    )
    .with_exposed_port(8025.tcp())
    .with_wait_for(WaitFor::Nothing)
    .with_host_config_modifier(|config| {
        config.publish_all_ports = Some(false);
        config.port_bindings = Some(std::collections::HashMap::from([(
            "8025/tcp".to_owned(),
            Some(vec![PortBinding {
                host_ip: Some("127.0.0.1".into()),
                host_port: Some("0".into()),
            }]),
        )]));
    })
    .start()
    .expect("start disposable SMTP capture");
    let smtp_ip = mail.get_bridge_ip_address().expect("SMTP bridge address");
    let mail_url = format!(
        "http://127.0.0.1:{}",
        mail.get_host_port_ipv4(8025.tcp()).unwrap()
    );
    let postgres = GenericImage::new(
        "postgres:17-alpine@sha256",
        "e5d2edd28b1f8d40a0a6c0c9cdc545b19b56a0d5d88f94bc11a97d970d4700d0",
    )
    .with_wait_for(WaitFor::message_on_either_std(
        "database system is ready to accept connections",
    ))
    .with_env_var("POSTGRES_USER", "bitwarden")
    .with_env_var("POSTGRES_PASSWORD", "disposable-test-password")
    .with_env_var("POSTGRES_DB", "bitwarden")
    .start()
    .expect("start disposable Bitwarden database");
    let db_ip = postgres
        .get_bridge_ip_address()
        .expect("PostgreSQL bridge address");
    // A fresh PostgreSQL container starts a temporary server for initdb, then
    // stops it and starts the actual server. Waiting for only the first ready
    // message lets Bitwarden race the shutdown and lose its startup migrations.
    let db_deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let stderr = postgres
            .stderr_to_vec()
            .expect("read PostgreSQL startup log");
        let stdout = postgres
            .stdout_to_vec()
            .expect("read PostgreSQL initialization log");
        let ready_count = [&stdout, &stderr]
            .iter()
            .map(|log| {
                String::from_utf8_lossy(log)
                    .matches("database system is ready to accept connections")
                    .count()
            })
            .sum::<usize>();
        if ready_count >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < db_deadline,
            "PostgreSQL did not complete initialization"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let image = GenericImage::new(
        "ghcr.io/bitwarden/lite:2026.11.0@sha256",
        "89c1844364fa6fe09e145e73b035c0e01d6194d317fb10853e30bc672a4648fb",
    )
    .with_exposed_port(8080.tcp())
    .with_wait_for(WaitFor::Nothing)
    .with_env_var("BW_DOMAIN", "localhost")
    .with_env_var("BW_DB_PROVIDER", "postgresql")
    .with_env_var("BW_DB_SERVER", db_ip.to_string())
    .with_env_var("BW_DB_DATABASE", "bitwarden")
    .with_env_var("BW_DB_USERNAME", "bitwarden")
    .with_env_var("BW_DB_PASSWORD", "disposable-test-password")
    // Non-secret fixture values. Never use a real installation in this test.
    .with_env_var("BW_INSTALLATION_ID", "11111111-1111-4111-8111-111111111111")
    .with_env_var("BW_INSTALLATION_KEY", "disposable-placeholder")
    .with_env_var("globalSettings__disableUserRegistration", "false")
    .with_env_var(
        "globalSettings__mail__replyToEmail",
        "noreply@example.invalid",
    )
    .with_env_var("globalSettings__mail__smtp__host", smtp_ip.to_string())
    .with_env_var("globalSettings__mail__smtp__port", "1025")
    .with_env_var("globalSettings__mail__smtp__ssl", "false")
    .with_host_config_modifier(|config| {
        config.publish_all_ports = Some(false);
        config.port_bindings = Some(std::collections::HashMap::from([(
            "8080/tcp".to_owned(),
            Some(vec![PortBinding {
                host_ip: Some("127.0.0.1".into()),
                host_port: Some("0".into()),
            }]),
        )]));
    });
    let container = image
        .start()
        .expect("start disposable Bitwarden Lite container");
    let port = container.get_host_port_ipv4(8080.tcp()).unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .new_agent();
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    while !agent
        .get(format!("{base}/api/config"))
        .call()
        .is_ok_and(|r| r.status().is_success())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "Bitwarden Lite did not become ready"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    loop {
        let mut check = postgres.exec(ExecCommand::new([
            "psql", "-U", "bitwarden", "-d", "bitwarden", "-tAc",
            "SELECT count(*) FROM information_schema.columns WHERE lower(table_name) = 'user' AND lower(column_name) = 'lastapikeyrotationdate'",
        ])).expect("inspect disposable schema");
        let output = check
            .stdout_to_vec()
            .expect("read disposable schema status");
        if String::from_utf8_lossy(&output).trim() == "1" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Bitwarden Lite database migrations did not complete"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    while !agent
        .post(format!("{base}/identity/accounts/prelogin"))
        .header("Content-Type", "application/json")
        .send(json!({"email": EMAIL}).to_string())
        .is_ok_and(|r| r.status().is_success())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "Bitwarden Lite database did not become ready"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    register(&base, Some(&mail_url));
    exercise_cli(port);
}

fn exercise_cli(port: u16) {
    let bw = std::env::var_os("NEOTALES_TEST_BW")
        .expect("set NEOTALES_TEST_BW to pinned @bitwarden/cli 2025.6.1 executable");
    let version = Command::new(&bw)
        .arg("--version")
        .output()
        .expect("run CLI version");
    assert!(
        version.status.success() && String::from_utf8_lossy(&version.stdout).trim() == "2025.6.1",
        "fixture requires Bitwarden CLI 2025.6.1"
    );
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let result = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(result.success(), "create disposable TLS certificate");
    let script = r#"
import socket, ssl, sys, threading
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1],sys.argv[2])
s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); print(s.getsockname()[1],flush=True)
def run(c):
 try:
  c=ctx.wrap_socket(c,server_side=True); upstream=socket.create_connection(('127.0.0.1',int(sys.argv[3])))
  def pump(a,b):
   try:
    while True:
     data=a.recv(65536)
     if not data: break
     b.sendall(data)
   except OSError: pass
   try: b.shutdown(socket.SHUT_WR)
   except OSError: pass
  t=threading.Thread(target=pump,args=(c,upstream),daemon=True); t.start(); pump(upstream,c); t.join(); c.close(); upstream.close()
 except (OSError,ssl.SSLError): pass
while True:
 c,_=s.accept(); threading.Thread(target=run,args=(c,),daemon=True).start()
"#;
    let mut proxy = Proxy(
        Command::new("python3")
            .args(["-u", "-c", script])
            .arg(&cert)
            .arg(&key)
            .arg(port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(proxy.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let tls_port: u16 = line.trim().parse().unwrap();
    let base = format!("https://127.0.0.1:{tls_port}");
    let wrapper = dir.path().join("bw");
    let quote = |s: &Path| format!("'{}'", s.to_string_lossy().replace('\'', "'\\''"));
    let script = format!(
        "#!/bin/sh\nunset BW_CLIENTID BW_CLIENTSECRET\nexport BITWARDENCLI_APPDATA_DIR={}\nexport NODE_EXTRA_CA_CERTS={}\nexec {} \"$@\"\n",
        quote(&dir.path().join("state")),
        quote(&cert),
        quote(Path::new(&bw))
    );
    std::fs::write(&wrapper, script).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    run(&wrapper, &["config", "server", &base], None, None);
    let session = String::from_utf8(run(
        &wrapper,
        &["login", EMAIL, "--passwordenv", "BW_PASSWORD", "--raw"],
        None,
        None,
    ))
    .unwrap()
    .trim()
    .to_owned();
    // Login with --raw returns the unlocked session; use it directly rather
    // than issuing a second unlock without passing the existing session.
    assert!(!session.is_empty());
    let status: Value =
        serde_json::from_slice(&run(&wrapper, &["status"], Some(&session), None)).unwrap();
    assert_eq!(
        status["status"], "unlocked",
        "fixture session must be unlocked"
    );
    let account = status["userId"].as_str().unwrap();
    let item = json!({"type":1,"name":"fixture","notes":"keep","login":{"username":"alice","password":"initial"}});
    let encoded = STANDARD.encode(item.to_string());
    let item: Value = serde_json::from_slice(&run(
        &wrapper,
        &["create", "item"],
        Some(&session),
        Some(encoded.as_bytes()),
    ))
    .unwrap();
    let id = item["id"].as_str().unwrap();
    let driver = VaultwardenDriver::new(Config {
        vault: "test".into(),
        command: wrapper.clone(),
        server: base,
        account_id: account.into(),
        session: SecretValue::new(session.as_bytes().to_vec()),
    })
    .unwrap()
    .with_write_lock(dir.path().join("lock"))
    .unwrap();
    let client = Client::new(driver);
    assert_eq!(client.get("test", id).unwrap().value.expose(), b"initial");
    client
        .set_secret("test", id, &SecretValue::new(b"updated".to_vec()))
        .unwrap();
    assert_eq!(client.get("test", id).unwrap().value.expose(), b"updated");
    let actual: Value =
        serde_json::from_slice(&run(&wrapper, &["get", "item", id], Some(&session), None)).unwrap();
    assert_eq!(actual["login"]["username"], "alice");
    assert_eq!(actual["notes"], "keep");
    assert!(
        client
            .list_secrets("test")
            .unwrap()
            .contains(&id.to_owned())
    );
    client
        .remove_secret("test", id, &RemoveOptions::default())
        .unwrap();
    assert!(
        !client
            .list_secrets("test")
            .unwrap()
            .contains(&id.to_owned())
    );
    client
        .remove_secret(
            "test",
            id,
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
}
