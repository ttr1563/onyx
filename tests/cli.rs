use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};

use assert_cmd::prelude::*;
use osmanthus_guard::auth;
use osmanthus_guard::config::{self, Config};
use osmanthus_guard::policy::{CustomRule, PolicyFile, RiskLevel};
use osmanthus_guard::state::{self, EventStatus, GuardEvent};
use predicates::prelude::*;
use tempfile::TempDir;
use time::OffsetDateTime;

fn osmanthus(state: &Path) -> Command {
    let mut command = Command::cargo_bin("osmanthus").unwrap();
    command.arg("--state-dir").arg(state);
    command
}

fn initialize(root: &Path) {
    osmanthus(root)
        .args(["init", "--no-qr", "--account", "test-server"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Osmanthus initialized"));
}

#[test]
fn init_creates_private_state_and_status() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);

    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(root.join(config::CONFIG_FILE)).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(root.join(config::POLICY_FILE)).unwrap().mode() & 0o777,
        0o600
    );
    let stored = config::load_config(&root).unwrap();
    let audit = fs::read_to_string(root.join(config::AUDIT_FILE)).unwrap();
    assert!(!audit.contains(&stored.totp_secret_base32));
    osmanthus(&root)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Authenticator: TOTP (test-server)",
        ));
}

#[test]
fn init_prints_a_compact_enrollment_qr() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let output = osmanthus(&root)
        .args([
            "init",
            "--issuer",
            "Osmanthus",
            "--account",
            "ttr1563-production-deploy",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let qr = stdout
        .split("Scan this QR code with a TOTP authenticator:\n")
        .nth(1)
        .unwrap()
        .trim_end();
    let lines: Vec<&str> = qr.lines().collect();
    assert!(lines.len() <= 23, "QR is {} rows high", lines.len());
    assert!(
        lines.iter().all(|line| line.chars().count() <= 41),
        "QR exceeds 41 terminal columns"
    );
    assert!(qr.contains(['▀', '▄', '█']));
}

#[test]
fn safe_command_runs_and_preserves_exit_status() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);
    let safe_command = temp.path().join("safe-command");
    fs::write(&safe_command, "#!/bin/sh\nexit 7\n").unwrap();
    fs::set_permissions(&safe_command, fs::Permissions::from_mode(0o755)).unwrap();

    osmanthus(&root)
        .arg("run")
        .arg("--")
        .arg(&safe_command)
        .assert()
        .code(7);
    let audit = fs::read_to_string(root.join(config::AUDIT_FILE)).unwrap();
    assert!(audit.contains("\"action\":\"allowed\""));
    assert!(audit.contains("\"result\":7"));
}

#[test]
fn dangerous_command_requires_and_consumes_one_permit() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);

    let fake_rm = temp.path().join("rm");
    fs::write(&fake_rm, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&fake_rm, fs::Permissions::from_mode(0o755)).unwrap();
    let command = vec![
        fake_rm.clone().into_os_string(),
        OsString::from("-rf"),
        OsString::from("/protected/path"),
    ];

    osmanthus(&root)
        .arg("run")
        .arg("--")
        .args(&command)
        .assert()
        .code(77)
        .stderr(predicate::str::contains("BLOCKED by Osmanthus"));

    let event = state::list_events(&root).unwrap().remove(0);
    assert_eq!(event.status, EventStatus::Pending);
    let config = config::load_config(&root).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let code = osmanthus_guard::totp::code_at(&config.totp_secret_base32, now).unwrap();
    auth::approve_with_code(&root, &config, &event.id, &code, now).unwrap();

    osmanthus(&root)
        .arg("run")
        .arg("--")
        .args(&command)
        .assert()
        .success();
    osmanthus(&root)
        .arg("run")
        .arg("--")
        .args(&command)
        .assert()
        .code(77);
}

#[test]
fn totp_code_cannot_approve_two_events() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let config = Config::new("Osmanthus".to_owned(), "test".to_owned()).unwrap();
    config::initialize(&root, &config).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let findings = osmanthus_guard::policy::evaluate(&[
        OsString::from("rm"),
        OsString::from("-rf"),
        OsString::from("/one"),
    ]);
    let first = GuardEvent::new(now, 600, "1".repeat(64), vec!["rm".to_owned()], &findings);
    let second = GuardEvent::new(now, 600, "2".repeat(64), vec!["rm".to_owned()], &findings);
    state::save_event(&root, &first).unwrap();
    state::save_event(&root, &second).unwrap();
    let code = osmanthus_guard::totp::code_at(&config.totp_secret_base32, now).unwrap();

    auth::approve_with_code(&root, &config, &first.id, &code, now).unwrap();
    assert!(matches!(
        auth::approve_with_code(&root, &config, &second.id, &code, now),
        Err(osmanthus_guard::OsmanthusError::InvalidCode)
    ));
}

#[test]
fn concurrent_totp_approvals_allow_only_one_event() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let config = Config::new("Osmanthus".to_owned(), "test".to_owned()).unwrap();
    config::initialize(&root, &config).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let findings = osmanthus_guard::policy::evaluate(&[
        OsString::from("rm"),
        OsString::from("-rf"),
        OsString::from("/one"),
    ]);
    let events = [
        GuardEvent::new(now, 600, "a".repeat(64), vec!["rm".to_owned()], &findings),
        GuardEvent::new(now, 600, "b".repeat(64), vec!["rm".to_owned()], &findings),
    ];
    for event in &events {
        state::save_event(&root, event).unwrap();
    }
    let code = osmanthus_guard::totp::code_at(&config.totp_secret_base32, now).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = events
        .iter()
        .map(|event| {
            let root = root.clone();
            let event_id = event.id.clone();
            let code = code.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let config = config::load_config(&root).unwrap();
                barrier.wait();
                auth::approve_with_code(&root, &config, &event_id, &code, now)
            })
        })
        .collect();
    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(osmanthus_guard::OsmanthusError::InvalidCode)))
            .count(),
        1
    );
}

#[test]
fn refuses_symlinked_config() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);
    let original = root.join("real-config.json");
    fs::rename(root.join(config::CONFIG_FILE), &original).unwrap();
    std::os::unix::fs::symlink(&original, root.join(config::CONFIG_FILE)).unwrap();

    osmanthus(&root)
        .arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("symbolic link"));
}

#[test]
fn refuses_non_regular_and_oversized_state_files() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);
    let config_path = root.join(config::CONFIG_FILE);
    let original = root.join("saved-config.json");
    fs::rename(&config_path, &original).unwrap();
    fs::create_dir(&config_path).unwrap();

    osmanthus(&root)
        .arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a regular file"));

    fs::remove_dir(&config_path).unwrap();
    fs::write(&config_path, vec![b' '; 1_048_577]).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    osmanthus(&root)
        .arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("exceeds 1 MiB"));
}

#[test]
fn refuses_symlinked_state_root() {
    let temp = TempDir::new().unwrap();
    let real_root = temp.path().join("real-state");
    initialize(&real_root);
    let linked_root = temp.path().join("linked-state");
    std::os::unix::fs::symlink(&real_root, &linked_root).unwrap();

    osmanthus(&linked_root)
        .arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("symbolic link"));
}

#[test]
fn five_invalid_codes_trigger_temporary_lock() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let config = Config::new("Osmanthus".to_owned(), "test".to_owned()).unwrap();
    config::initialize(&root, &config).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let findings = osmanthus_guard::policy::evaluate(&[
        OsString::from("rm"),
        OsString::from("-rf"),
        OsString::from("/one"),
    ]);
    let event = GuardEvent::new(now, 600, "3".repeat(64), vec!["rm".to_owned()], &findings);
    state::save_event(&root, &event).unwrap();

    for _ in 0..5 {
        assert!(matches!(
            auth::approve_with_code(&root, &config, &event.id, "not-a-code", now),
            Err(osmanthus_guard::OsmanthusError::InvalidCode)
        ));
    }
    assert!(matches!(
        auth::approve_with_code(&root, &config, &event.id, "not-a-code", now),
        Err(osmanthus_guard::OsmanthusError::AuthenticationLocked(_))
    ));
}

#[test]
fn event_and_audit_redact_secret_arguments() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);

    osmanthus(&root)
        .args([
            "run",
            "--",
            "curl",
            "--token=do-not-store",
            "/root/.ssh/id_ed25519",
        ])
        .assert()
        .code(77);
    let event = state::list_events(&root).unwrap().remove(0);
    let audit = fs::read_to_string(root.join(config::AUDIT_FILE)).unwrap();
    assert!(!event.command.join(" ").contains("do-not-store"));
    assert!(!audit.contains("do-not-store"));
}

#[test]
fn concurrent_audit_records_remain_valid_json_lines() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let config = Config::new("Osmanthus".to_owned(), "test".to_owned()).unwrap();
    config::initialize(&root, &config).unwrap();
    let mut workers = Vec::new();
    for _ in 0..8 {
        let root = root.clone();
        workers.push(std::thread::spawn(move || {
            let record = osmanthus_guard::audit::AuditRecord::new("concurrent").unwrap();
            osmanthus_guard::audit::append(&root, &record).unwrap();
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let audit = fs::read_to_string(root.join(config::AUDIT_FILE)).unwrap();
    let concurrent: Vec<serde_json::Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|record: &serde_json::Value| record["action"] == "concurrent")
        .collect();
    assert_eq!(concurrent.len(), 8);
}

#[test]
fn legacy_user_policy_remains_enforced_until_system_policy_is_initialized() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);

    let mut policy = PolicyFile::default();
    policy
        .add(CustomRule {
            id: "production-terraform".to_owned(),
            executable: "terraform".to_owned(),
            argument_contains: vec!["apply".to_owned(), "production".to_owned()],
            risk: RiskLevel::Critical,
            reason: "production infrastructure change".to_owned(),
        })
        .unwrap();
    policy.save(&root).unwrap();

    osmanthus(&root)
        .args(["policy", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Policy source: legacy user"))
        .stdout(predicate::str::contains("production-terraform"));
    osmanthus(&root)
        .args(["check", "--", "terraform", "apply", "production.tfplan"])
        .assert()
        .code(77)
        .stdout(predicate::str::contains("production-terraform"));
    osmanthus(&root)
        .args(["check", "--", "terraform", "plan", "production.tfplan"])
        .assert()
        .success();
}

#[test]
fn audit_write_failure_prevents_safe_command_execution() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);
    let marker = temp.path().join("executed");
    let safe_command = temp.path().join("safe-command");
    fs::write(
        &safe_command,
        format!("#!/bin/sh\ntouch {}\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&safe_command, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        root.join(config::AUDIT_FILE),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();

    osmanthus(&root)
        .arg("run")
        .arg("--")
        .arg(&safe_command)
        .assert()
        .failure();
    assert!(!marker.exists());
}

#[test]
fn failed_spawn_does_not_leave_reusable_permit() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    initialize(&root);
    let missing_rm = temp.path().join("missing").join("rm");
    let command = vec![
        missing_rm.into_os_string(),
        OsString::from("-rf"),
        OsString::from("/protected/path"),
    ];

    osmanthus(&root)
        .arg("run")
        .arg("--")
        .args(&command)
        .assert()
        .code(77);
    let event = state::list_events(&root).unwrap().remove(0);
    let config = config::load_config(&root).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let code = osmanthus_guard::totp::code_at(&config.totp_secret_base32, now).unwrap();
    auth::approve_with_code(&root, &config, &event.id, &code, now).unwrap();

    osmanthus(&root)
        .arg("run")
        .arg("--")
        .args(&command)
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to execute command"));
    assert_eq!(
        state::load_event(&root, &event.id).unwrap().status,
        EventStatus::Consumed
    );
    osmanthus(&root)
        .arg("run")
        .arg("--")
        .args(&command)
        .assert()
        .code(77);
    let audit = fs::read_to_string(root.join(config::AUDIT_FILE)).unwrap();
    assert!(audit.contains("\"action\":\"execution_failed\""));
}
