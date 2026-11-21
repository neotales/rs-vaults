//! Native Secret Service test in a disposable D-Bus session and temporary home.
#![cfg(target_os = "linux")]

use neotales_vaults_core::{Capability, Client, ErrorKind, GetOptions, RemoveOptions, SecretValue};
use neotales_vaults_os::{Config, OsDriver};
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

#[test]
#[ignore = "requires dbus-run-session, dbus-send, and gnome-keyring-daemon"]
fn isolated_secret_service_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let runtime = dir.path().join("runtime");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let executable = std::env::current_exe().unwrap();
    let script = r#"
set -eu
printf '%s\n' disposable-test-password | gnome-keyring-daemon --foreground --unlock --components=secrets >/dev/null 2>&1 &
service=$!
trap 'kill "$service" 2>/dev/null || true; wait "$service" 2>/dev/null || true' EXIT
ready=0
for i in $(seq 1 50); do
  if dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true'; then ready=1; break; fi
  sleep 0.1
done
test "$ready" = 1
"$1" --exact isolated_child --ignored --nocapture
"#;
    let mut child = Command::new("dbus-run-session")
        .args(["--", "sh", "-c", script, "isolated"])
        .arg(executable)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("NEOTALES_TEST_ISOLATED_KEYRING", "1")
        .stdin(Stdio::null())
        .spawn()
        .expect("start isolated D-Bus session");
    let status = child.wait_timeout(Duration::from_secs(30)).unwrap();
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("isolated keyring test timed out");
    }
    assert!(status.unwrap().success(), "isolated keyring test failed");
}

#[test]
#[ignore = "invoked only by the isolated Secret Service parent"]
fn isolated_child() {
    assert_eq!(
        std::env::var("NEOTALES_TEST_ISOLATED_KEYRING").as_deref(),
        Ok("1")
    );
    let client = Client::new(
        OsDriver::new(Config {
            service: "neotales-vaults-disposable-test".into(),
        })
        .unwrap(),
    );
    assert!(client.supports(Capability::SetSecret));
    assert!(!client.supports(Capability::GetCertificate));
    assert_eq!(
        client.get("test", "missing").unwrap_err().kind,
        ErrorKind::NotFound
    );
    client
        .set_secret("test", "token", &SecretValue::new(b"first-value".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("test", "token").unwrap().value.expose(),
        b"first-value"
    );
    client
        .set_secret("test", "token", &SecretValue::new(b"replacement".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("test", "token").unwrap().value.expose(),
        b"replacement"
    );
    assert_eq!(
        client.get("other", "token").unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        client
            .get_with(
                "test",
                "token",
                &GetOptions {
                    version: Some("1".into()),
                    retry: None
                }
            )
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    let options = RemoveOptions {
        purge: true,
        ..Default::default()
    };
    assert_eq!(
        client
            .remove_secret("test", "token", &options)
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(
        client.get("test", "token").unwrap().value.expose(),
        b"replacement"
    );
    client
        .remove_secret("test", "token", &RemoveOptions::default())
        .unwrap();
    assert_eq!(
        client.get("test", "token").unwrap_err().kind,
        ErrorKind::NotFound
    );
}
