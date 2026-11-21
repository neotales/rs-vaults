//! Opt-in integration against disposable, locally cached Docker images.
use neotales_vaults_core::{Client, SecretValue};
use neotales_vaults_infisical::{Config, InfisicalDriver};
use serde_json::{Value, json};
use std::{
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const POSTGRES: &str =
    "postgres:17-alpine@sha256:e5d2edd28b1f8d40a0a6c0c9cdc545b19b56a0d5d88f94bc11a97d970d4700d0";
const REDIS: &str =
    "redis:7.4-alpine@sha256:7f7d30b7fdd09467bac58198a1f166dd69789d348d4fe859cccb20e0cf287fbe";
const INFISICAL: &str = "infisical/infisical:v0.167.11@sha256:4cefd7fec942f99b4a458130417ad5b2ad0b15e71300c5d7df8f5a877082fe8d";

struct Container(String);
impl Container {
    fn start(args: &[&str]) -> Self {
        let output = Command::new("docker")
            .args(["run", "--rm", "-d", "--pull=never"])
            .args(args)
            .output()
            .expect("run docker");
        assert!(
            output.status.success(),
            "failed to start fixture container: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self(String::from_utf8(output.stdout).unwrap().trim().to_owned())
    }
    fn inspect(&self, format: &str) -> String {
        let output = Command::new("docker")
            .args(["inspect", "--format", format, &self.0])
            .output()
            .unwrap();
        assert!(output.status.success(), "inspect fixture container");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}
impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["stop", "--time", "2", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
fn post(agent: &ureq::Agent, url: &str, token: Option<&str>, body: Value) -> Value {
    let mut request = agent.post(url).header("Content-Type", "application/json");
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let mut response = request.send(body.to_string()).expect("fixture request");
    assert_eq!(
        response.status().as_u16(),
        200,
        "fixture bootstrap request failed"
    );
    serde_json::from_str(&response.body_mut().read_to_string().unwrap()).unwrap()
}

#[test]
#[ignore = "requires Docker and locally cached pinned images; starts disposable services"]
fn infisical_shared_secret_round_trip() {
    let db = Container::start(&[
        "-e",
        "POSTGRES_USER=infisical",
        "-e",
        "POSTGRES_PASSWORD=disposable-test-password",
        "-e",
        "POSTGRES_DB=infisical",
        POSTGRES,
    ]);
    let redis = Container::start(&[REDIS]);
    let ip = |c: &Container| c.inspect("{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}");
    let db_uri = format!(
        "DB_CONNECTION_URI=postgres://infisical:disposable-test-password@{}:5432/infisical?sslmode=disable",
        ip(&db)
    );
    let redis_uri = format!("REDIS_URL=redis://{}:6379", ip(&redis));
    for (container, port) in [(&db, 5432), (&redis, 6379)] {
        let address = format!("{}:{port}", ip(container));
        let deadline = Instant::now() + Duration::from_secs(60);
        while std::net::TcpStream::connect(&address).is_err() {
            assert!(Instant::now() < deadline, "dependency not ready");
            thread::sleep(Duration::from_millis(200));
        }
    }
    let app = Container::start(&[
        "--publish",
        "127.0.0.1::8080",
        "-e",
        "ENCRYPTION_KEY=00000000000000000000000000000000",
        "-e",
        "AUTH_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "-e",
        &db_uri,
        "-e",
        &redis_uri,
        "-e",
        "SITE_URL=http://localhost:8080",
        "-e",
        "HOST=0.0.0.0",
        "-e",
        "NODE_ENV=production",
        "-e",
        "TELEMETRY_ENABLED=false",
        "-e",
        "DISABLE_UPDATE_CHECK=true",
        INFISICAL,
    ]);
    let port = app.inspect("{{(index (index .NetworkSettings.Ports \"8080/tcp\") 0).HostPort}}");
    let base = format!("http://127.0.0.1:{port}");
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .new_agent();
    let deadline = Instant::now() + Duration::from_secs(300);
    while !agent
        .get(format!("{base}/api/status"))
        .call()
        .is_ok_and(|r| r.status().as_u16() == 200)
    {
        assert!(Instant::now() < deadline, "Infisical not ready");
        thread::sleep(Duration::from_millis(500));
    }
    let bootstrap = post(
        &agent,
        &format!("{base}/api/v1/admin/bootstrap"),
        None,
        json!({"email":"test@example.invalid","password":"not-a-real-password","organization":"disposable test"}),
    );
    let token = bootstrap["identity"]["credentials"]["token"]
        .as_str()
        .unwrap();
    let project = post(
        &agent,
        &format!("{base}/api/v1/projects"),
        Some(token),
        json!({"projectName":"disposable test","projectDescription":"isolated fixture","slug":"disposable-test","template":"default","type":"secret-manager"}),
    );
    let client = Client::new(
        InfisicalDriver::new(Config {
            vault: "test".into(),
            address: base,
            project_id: project["project"]["id"].as_str().unwrap().into(),
            environment: "dev".into(),
            secret_path: "/".into(),
            token: SecretValue::new(token.as_bytes().to_vec()),
            allow_http_loopback: true,
        })
        .unwrap(),
    );
    client
        .set_secret("test", "TEST_SECRET", &SecretValue::new(b"first".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("test", "TEST_SECRET").unwrap().value.expose(),
        b"first"
    );
    client
        .set_secret(
            "test",
            "TEST_SECRET",
            &SecretValue::new(b"replacement".to_vec()),
        )
        .unwrap();
    assert_eq!(
        client.get("test", "TEST_SECRET").unwrap().value.expose(),
        b"replacement"
    );
    assert!(
        client
            .list_secrets("test")
            .unwrap()
            .contains(&"TEST_SECRET".to_owned())
    );
    client
        .remove_secret("test", "TEST_SECRET", &Default::default())
        .unwrap();
    assert!(client.get("test", "TEST_SECRET").is_err());
    assert!(
        !client
            .list_secrets("test")
            .unwrap()
            .contains(&"TEST_SECRET".to_owned())
    );
}
