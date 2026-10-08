use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{OnyxError, Result};

pub const CONFIG_FILE: &str = "config.json";
pub const AUTH_STATE_FILE: &str = "auth-state.json";
pub const EVENTS_DIR: &str = "events";
pub const AUDIT_FILE: &str = "audit.jsonl";
pub const LOCK_FILE: &str = ".lock";
pub const POLICY_FILE: &str = "policy.json";
const MAX_STATE_JSON_BYTES: u64 = 1_048_576;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u32,
    pub issuer: String,
    pub account: String,
    pub totp_secret_base32: String,
    pub approval_ttl_seconds: i64,
    pub event_ttl_seconds: i64,
    pub max_auth_failures: u32,
    pub auth_lock_seconds: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthState {
    pub failed_attempts: u32,
    pub locked_until_unix: Option<i64>,
    pub last_accepted_counter: Option<u64>,
}

impl Config {
    pub fn new(issuer: String, account: String) -> Result<Self> {
        validate_label("issuer", &issuer, 64)?;
        validate_label("account", &account, 128)?;
        let mut secret = [0_u8; 20];
        rand::rng().fill_bytes(&mut secret);
        let config = Self {
            schema_version: 1,
            issuer,
            account,
            totp_secret_base32: data_encoding::BASE32_NOPAD.encode(&secret),
            approval_ttl_seconds: 30,
            event_ttl_seconds: 600,
            max_auth_failures: 5,
            auth_lock_seconds: 60,
        };
        secret.zeroize();
        Ok(config)
    }

    pub fn totp_uri(&self) -> String {
        let label = format!("{}:{}", self.issuer, self.account);
        format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
            urlencoding::encode(&label),
            self.totp_secret_base32,
            urlencoding::encode(&self.issuer)
        )
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(OnyxError::InvalidState(format!(
                "unsupported configuration schema version: {}",
                self.schema_version
            )));
        }
        validate_label("issuer", &self.issuer, 64)?;
        validate_label("account", &self.account, 128)?;
        let secret = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(self.totp_secret_base32.as_bytes())
                .map_err(|error| {
                    OnyxError::InvalidState(format!("invalid TOTP secret: {error}"))
                })?,
        );
        if secret.len() < 20 {
            return Err(OnyxError::InvalidState(
                "TOTP secret must contain at least 160 bits".to_owned(),
            ));
        }
        if !(1..=300).contains(&self.approval_ttl_seconds)
            || !(30..=86_400).contains(&self.event_ttl_seconds)
            || !(1..=100).contains(&self.max_auth_failures)
            || !(1..=3_600).contains(&self.auth_lock_seconds)
        {
            return Err(OnyxError::InvalidState(
                "configuration limits are outside supported safety bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_label(name: &str, value: &str, maximum: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(OnyxError::InvalidState(format!(
            "{name} must be 1-{maximum} bytes without control characters"
        )));
    }
    Ok(())
}

impl Drop for Config {
    fn drop(&mut self) {
        self.totp_secret_base32.zeroize();
    }
}

pub fn state_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = env::var_os("ONYX_STATE_DIR") {
        return Ok(PathBuf::from(path));
    }
    if unsafe { libc::geteuid() } == 0 {
        return Ok(PathBuf::from("/var/lib/onyx"));
    }
    if let Some(path) = env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(path).join("onyx"));
    }
    let home =
        env::var_os("HOME").ok_or_else(|| OnyxError::InvalidState("HOME is not set".to_owned()))?;
    Ok(PathBuf::from(home).join(".local/state/onyx"))
}

pub fn initialize(root: &Path, config: &Config) -> Result<()> {
    if root.exists() {
        reject_symlink(root)?;
        if root.join(CONFIG_FILE).exists() {
            return Err(OnyxError::AlreadyInitialized(root.display().to_string()));
        }
    } else {
        fs::create_dir_all(root)?;
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let events = root.join(EVENTS_DIR);
    if events.exists() {
        reject_symlink(&events)?;
    } else {
        fs::create_dir_all(&events)?;
    }
    fs::set_permissions(&events, fs::Permissions::from_mode(0o700))?;
    atomic_write_json(&root.join(CONFIG_FILE), config)?;
    atomic_write_json(&root.join(AUTH_STATE_FILE), &AuthState::default())?;
    atomic_write_json(
        &root.join(POLICY_FILE),
        &crate::policy::PolicyFile::default(),
    )?;
    create_private_file(&root.join(AUDIT_FILE))?;
    create_private_file(&root.join(LOCK_FILE))?;
    Ok(())
}

pub fn load_config(root: &Path) -> Result<Config> {
    let path = root.join(CONFIG_FILE);
    if !path.exists() {
        return Err(OnyxError::NotInitialized);
    }
    validate_state_root(root)?;
    let config: Config = load_private_json(&path)?;
    config.validate()?;
    Ok(config)
}

pub fn load_auth_state(root: &Path) -> Result<AuthState> {
    validate_state_root(root)?;
    load_private_json(&root.join(AUTH_STATE_FILE))
}

pub fn save_auth_state(root: &Path, state: &AuthState) -> Result<()> {
    atomic_write_json(&root.join(AUTH_STATE_FILE), state)
}

pub fn load_private_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    validate_private_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if file.metadata()?.len() > MAX_STATE_JSON_BYTES {
        return Err(OnyxError::InvalidState(format!(
            "state file exceeds 1 MiB: {}",
            path.display()
        )));
    }
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if path.exists() {
        reject_symlink(path)?;
    }
    let parent = path
        .parent()
        .ok_or_else(|| OnyxError::UnsafePath(path.display().to_string()))?;
    validate_state_root(parent)?;
    let temporary = parent.join(format!(".onyx-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_private_file(path: &Path) -> Result<()> {
    if path.exists() {
        validate_private_path(path)?;
        return Ok(());
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    Ok(())
}

pub fn reject_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(OnyxError::UnsafePath(format!(
            "{} is a symbolic link",
            path.display()
        )));
    }
    Ok(())
}

pub fn validate_state_root(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_dir() {
        return Err(OnyxError::UnsafePath(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    validate_owner_and_mode(path, &metadata)
}

pub fn validate_private_path(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(OnyxError::UnsafePath(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    validate_owner_and_mode(path, &metadata)
}

fn validate_owner_and_mode(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(OnyxError::UnsafePath(format!(
            "{} must not be accessible by group or others (mode {:o})",
            path.display(),
            mode & 0o777
        )));
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        return Err(OnyxError::UnsafePath(format!(
            "{} must be owned by effective uid {}",
            path.display(),
            effective_uid
        )));
    }
    Ok(())
}
