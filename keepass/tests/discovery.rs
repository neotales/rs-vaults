//! Native credential lookup in an isolated Linux D-Bus session.
#![cfg(target_os = "linux")]
use neotales_keepass::{
    Entry, KdbxCredentials, KdbxFile, KdbxKeyFile, KdbxWriteOptions, KeePassDatabase,
    ProtectedValue,
};
use neotales_vaults_core::{Client, SecretValue};
use neotales_vaults_keepass::KeepassDriver;
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

#[test]
#[ignore = "requires dbus-run-session, dbus-send, and gnome-keyring-daemon"]
fn isolated_credential_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let runtime = dir.path().join("runtime");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = [7u8; 32];
    let keyfile = dir.path().join("keyfile");
    std::fs::write(&keyfile, key).unwrap();
    std::fs::write(dir.path().join("wrong-keyfile"), [9u8; 32]).unwrap();
    for (name, password) in [
        ("keyring", Some("real-password")),
        ("env", Some("real-password")),
        ("keyonly", None),
        ("passwordonly", Some("real-password")),
        ("wrongkey", Some("real-password")),
        ("missing", Some("real-password")),
    ] {
        let mut db = KeePassDatabase::default();
        let mut entry = Entry::new("entry");
        entry.password = ProtectedValue::from_text("test-value");
        db.root.add_entry(entry);
        let providers: Vec<Box<dyn neotales_keepass::CredentialProvider + Send>> =
            if name == "passwordonly" || name == "missing" {
                Vec::new()
            } else {
                vec![Box::new(KdbxKeyFile::parse(&key).unwrap())]
            };
        let mut credentials =
            KdbxCredentials::from_parts(password.map(str::as_bytes), providers).unwrap();
        let mut bytes = Vec::new();
        KdbxFile::save_default_with_credentials(&db, &mut bytes, &mut credentials).unwrap();
        std::fs::write(dir.path().join(format!("{name}.kdbx")), bytes).unwrap();
    }
    let script = r#"
set -eu
printf '%s\n' disposable-password | gnome-keyring-daemon --foreground --unlock --components=secrets >/dev/null 2>&1 &
service=$!
trap 'kill "$service" 2>/dev/null || true; wait "$service" 2>/dev/null || true' EXIT
ready=0
for i in $(seq 1 50); do
  if dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true'; then ready=1; break; fi
  sleep 0.1
done
test "$ready" = 1
MODE=keyring KEEPASS_SECRET=wrong-password "$1" --exact discovery_child --ignored
MODE=env KEEPASS_SECRET=real-password "$1" --exact discovery_child --ignored
MODE=keyonly env -u KEEPASS_SECRET "$1" --exact discovery_child --ignored
MODE=passwordonly KEEPASS_SECRET=real-password env -u KEEPASS_KEYFILE "$1" --exact discovery_child --ignored
MODE=wrongkey KEEPASS_SECRET=real-password KEEPASS_KEYFILE="$NEOTALES_KEEPASS_TEST_DIR/wrong-keyfile" "$1" --exact discovery_child --ignored
MODE=missing env -u KEEPASS_SECRET -u KEEPASS_KEYFILE "$1" --exact discovery_child --ignored
"#;
    let mut child = Command::new("dbus-run-session")
        .args(["--", "sh", "-c", script, "fixture"])
        .arg(std::env::current_exe().unwrap())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("KEEPASS_KEYFILE", &keyfile)
        .env("NEOTALES_KEEPASS_TEST_DIR", dir.path())
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let status = child.wait_timeout(Duration::from_secs(60)).unwrap();
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("isolated discovery timed out");
    }
    assert!(status.unwrap().success());
}

#[test]
#[ignore = "invoked only in an isolated credential-store session"]
fn discovery_child() {
    let mode = std::env::var("MODE").unwrap();
    let path = std::path::PathBuf::from(std::env::var_os("NEOTALES_KEEPASS_TEST_DIR").unwrap())
        .join(format!("{mode}.kdbx"));
    if mode == "missing" {
        assert!(KeepassDriver::discover("local", &path).is_err());
        return;
    }
    if mode == "wrongkey" {
        let original = std::fs::read(&path).unwrap();
        let driver = KeepassDriver::discover("local", &path)
            .unwrap()
            .with_write_options(KdbxWriteOptions::default());
        let client = Client::new(driver);
        assert!(client.get("local", "entry").is_err());
        assert!(
            client
                .set_secret("local", "entry", &SecretValue::new(b"replacement".to_vec()))
                .is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), original);
        return;
    }
    if mode == "keyring" {
        let path = std::fs::canonicalize(&path).unwrap();
        let credential = keyring::secret_service::default_credential_builder()
            .build(None, "neotales-vaults-keepass", path.to_str().unwrap())
            .unwrap();
        keyring::Entry::new_with_credential(credential)
            .set_secret(b"real-password")
            .unwrap();
    }
    let driver = KeepassDriver::discover("local", &path)
        .unwrap()
        .with_write_options(KdbxWriteOptions::default());
    let client = Client::new(driver);
    assert_eq!(
        client.get("local", "entry").unwrap().value.expose(),
        b"test-value"
    );
    client
        .set_secret("local", "entry", &SecretValue::new(b"replacement".to_vec()))
        .unwrap();
    assert_eq!(
        client.get("local", "entry").unwrap().value.expose(),
        b"replacement"
    );
}
