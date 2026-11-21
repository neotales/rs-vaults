#![cfg(unix)]

use neotales_vaults_core::{Capability, Client, ErrorKind, GetOptions, RemoveOptions, SecretValue};
use neotales_vaults_vaultwarden::{Config, VaultwardenDriver};
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

const ACCOUNT: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const ITEM: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
static NEXT_SCRIPT: AtomicUsize = AtomicUsize::new(0);
// Concurrent fork can inherit another test's writable executable before exec.
static SCRIPT_TEST_LOCK: Mutex<()> = Mutex::new(());

fn script(dir: &Path, status: &str, item: &str) -> std::path::PathBuf {
    let path = dir.join(format!(
        "fake-bw-{}",
        NEXT_SCRIPT.fetch_add(1, Ordering::Relaxed)
    ));
    let capture = dir.join("captured");
    let code = format!(
        r#"#!/bin/sh
test "$BW_SESSION" = "test-session" || exit 7
test "$1" = "--nointeraction" || exit 8
case "$2" in
status) printf '%s' '{status}' ;;
get) test "$3" = "item" && test "$4" = "{ITEM}" || exit 9
     printf '%s' '{item}' ;;
sync) printf '%s' '{{"success":true}}' ;;
list) if test "$4" = "--trash"; then printf '[]'; else printf '%s' '[{item}]'; fi ;;
delete) test "$3" = "item" && test "$4" = "{ITEM}" || exit 11
        printf '%s' "$5" > '{capture}' ;;
edit) test "$3" = "item" && test "$4" = "{ITEM}" || exit 11
      cat > '{capture}' ;;
*) exit 10 ;;
esac
"#,
        capture = capture.display()
    );
    std::fs::write(&path, code).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn lists_login_ids_and_deletes_only_with_write_opt_in() {
    let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let status = format!(
        r#"{{"serverUrl":"https://vault.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(r#"{{"id":"{ITEM}","type":1,"login":{{"password":"private"}}}}"#);
    let config = Config {
        vault: "work".into(),
        command: script(dir.path(), &status, &item),
        server: "https://vault.example".into(),
        account_id: ACCOUNT.into(),
        session: SecretValue::new(b"test-session".to_vec()),
    };
    let read_only = Client::new(VaultwardenDriver::new(config.clone()).unwrap());
    assert_eq!(read_only.list_secrets("work").unwrap(), vec![ITEM]);
    assert_eq!(
        read_only
            .remove_secret("work", ITEM, &RemoveOptions::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    let client = Client::new(
        VaultwardenDriver::new(config)
            .unwrap()
            .with_write_lock(dir.path().join("lock"))
            .unwrap(),
    );
    client
        .remove_secret("work", ITEM, &RemoveOptions::default())
        .unwrap();
    assert_eq!(std::fs::read(dir.path().join("captured")).unwrap(), b"");
    client
        .remove_secret(
            "work",
            ITEM,
            &RemoveOptions {
                purge: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("captured")).unwrap(),
        b"--permanent"
    );
}

#[test]
fn explicit_write_updates_password_and_preserves_item_fields() {
    let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
    use base64::Engine;
    let dir = tempfile::tempdir().unwrap();
    let status = format!(
        r#"{{"serverUrl":"https://vault.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(
        r#"{{"id":"{ITEM}","type":1,"name":"entry","notes":"keep","login":{{"username":"alice","password":"old"}},"fields":[{{"name":"a","value":"b"}}],"deletedDate":null}}"#
    );
    let driver = VaultwardenDriver::new(Config {
        vault: "work".into(),
        command: script(dir.path(), &status, &item),
        server: "https://vault.example".into(),
        account_id: ACCOUNT.into(),
        session: SecretValue::new(b"test-session".to_vec()),
    })
    .unwrap()
    .with_write_lock(dir.path().join("lock"))
    .unwrap();
    let c = Client::new(driver);
    assert!(c.supports(Capability::SetSecret));
    c.set_secret("work", ITEM, &SecretValue::new(b"new-secret".to_vec()))
        .unwrap();
    let encoded = std::fs::read(dir.path().join("captured")).unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(result["login"]["password"], "new-secret");
    assert_eq!(result["login"]["username"], "alice");
    assert_eq!(result["notes"], "keep");
    assert_eq!(result["fields"][0]["value"], "b");
}

#[test]
fn rejects_non_login_and_never_edits_it() {
    let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let status = format!(
        r#"{{"serverUrl":"https://vault.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(r#"{{"id":"{ITEM}","type":2,"login":{{"password":"secret"}}}}"#);
    let driver = VaultwardenDriver::new(Config {
        vault: "work".into(),
        command: script(dir.path(), &status, &item),
        server: "https://vault.example".into(),
        account_id: ACCOUNT.into(),
        session: SecretValue::new(b"test-session".to_vec()),
    })
    .unwrap()
    .with_write_lock(dir.path().join("lock"))
    .unwrap();
    let client = Client::new(driver);
    assert_eq!(
        client.get("work", ITEM).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    let result = client.set_secret("work", ITEM, &SecretValue::new(b"value".to_vec()));
    let error = result.unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported, "{error:?}");
    assert!(!dir.path().join("captured").exists());
}

#[test]
fn rejects_item_without_type() {
    let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let status = format!(
        r#"{{"serverUrl":"https://vault.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(r#"{{"id":"{ITEM}","login":{{"password":"secret"}}}}"#);
    assert_eq!(
        client(script(dir.path(), &status, &item))
            .get("work", ITEM)
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
}

#[test]
fn failed_sync_does_not_attempt_an_edit() {
    let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let status = format!(
        r#"{{"serverUrl":"https://vault.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(r#"{{"id":"{ITEM}","type":1,"login":{{"password":"old"}}}}"#);
    let command = script(dir.path(), &status, &item);
    let body = std::fs::read_to_string(&command).unwrap().replace(
        r#"sync) printf '%s' '{"success":true}' ;;"#,
        "sync) exit 17 ;;",
    );
    std::fs::write(&command, body).unwrap();
    let driver = VaultwardenDriver::new(Config {
        vault: "work".into(),
        command,
        server: "https://vault.example".into(),
        account_id: ACCOUNT.into(),
        session: SecretValue::new(b"test-session".to_vec()),
    })
    .unwrap()
    .with_write_lock(dir.path().join("lock"))
    .unwrap();
    assert_eq!(
        Client::new(driver)
            .set_secret("work", ITEM, &SecretValue::new(b"value".to_vec()))
            .unwrap_err()
            .kind,
        ErrorKind::Provider
    );
    assert!(!dir.path().join("captured").exists());
}
fn client(command: std::path::PathBuf) -> Client {
    Client::new(
        VaultwardenDriver::new(Config {
            vault: "work".into(),
            command,
            server: "https://vault.example".into(),
            account_id: ACCOUNT.into(),
            session: SecretValue::new(b"test-session".to_vec()),
        })
        .unwrap(),
    )
}

#[test]
fn reads_only_matching_unlocked_profile_and_item() {
    let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let status = format!(
        r#"{{"serverUrl":"https://vault.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(
        r#"{{"id":"{ITEM}","type":1,"login":{{"password":"sensitive-value"}},"deletedDate":null}}"#
    );
    let c = client(script(dir.path(), &status, &item));
    assert!(c.supports(Capability::GetSecret));
    assert!(!c.supports(Capability::SetSecret));
    let result = c.get("work", ITEM).unwrap();
    assert_eq!(result.value.expose(), b"sensitive-value");
    assert!(!format!("{result:?}").contains("sensitive-value"));
    assert_eq!(
        c.get_with(
            "work",
            ITEM,
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
        c.get("work", "--help").unwrap_err().kind,
        ErrorKind::InvalidInput
    );
}

#[test]
fn mismatch_and_deleted_item_fail_closed() {
    let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let status = format!(
        r#"{{"serverUrl":"https://other.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(r#"{{"id":"{ITEM}","type":1,"login":{{"password":"secret"}}}}"#);
    assert_eq!(
        client(script(dir.path(), &status, &item))
            .get("work", ITEM)
            .unwrap_err()
            .kind,
        ErrorKind::PermissionDenied
    );
    let status = format!(
        r#"{{"serverUrl":"https://vault.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(
        r#"{{"id":"{ITEM}","type":1,"login":{{"password":"secret"}},"deletedDate":"2025-01-01T00:00:00Z"}}"#
    );
    let error = client(script(dir.path(), &status, &item))
        .get("work", ITEM)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::NotFound, "{error:?}");
}

#[test]
fn wrong_item_does_not_leak_output() {
    let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let status = format!(
        r#"{{"serverUrl":"https://vault.example","userId":"{ACCOUNT}","status":"unlocked"}}"#
    );
    let item = format!(r#"{{"id":"{ACCOUNT}","type":1,"login":{{"password":"secret-value"}}}}"#);
    let error = client(script(dir.path(), &status, &item))
        .get("work", ITEM)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Provider);
    assert!(!format!("{error:?}").contains("secret-value"));
}
