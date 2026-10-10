use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::{self, EVENTS_DIR, LOCK_FILE};
use crate::policy::{Finding, RiskLevel};
use crate::{OsmanthusError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Pending,
    Approved,
    Consumed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvent {
    pub schema_version: u32,
    pub id: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub command_digest: String,
    pub command: Vec<String>,
    pub risk: RiskLevel,
    pub rule_ids: Vec<String>,
    pub status: EventStatus,
    pub approved_at_unix: Option<i64>,
    pub approved_until_unix: Option<i64>,
    pub consumed_at_unix: Option<i64>,
}

impl GuardEvent {
    pub fn new(
        now: i64,
        ttl_seconds: i64,
        command_digest: String,
        command: Vec<String>,
        findings: &[Finding],
    ) -> Self {
        let risk = findings
            .iter()
            .map(|finding| finding.risk)
            .find(|risk| *risk == RiskLevel::Critical)
            .unwrap_or(RiskLevel::High);
        Self {
            schema_version: 1,
            id: Uuid::new_v4().to_string(),
            created_at_unix: now,
            expires_at_unix: now + ttl_seconds,
            command_digest,
            command,
            risk,
            rule_ids: findings
                .iter()
                .map(|finding| finding.rule_id.to_owned())
                .collect(),
            status: EventStatus::Pending,
            approved_at_unix: None,
            approved_until_unix: None,
            consumed_at_unix: None,
        }
    }
}

pub struct StateLock {
    file: File,
}

impl StateLock {
    pub fn acquire(root: &Path) -> Result<Self> {
        config::validate_state_root(root)?;
        let path = root.join(LOCK_FILE);
        config::validate_private_path(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { file })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn command_digest(command: &[std::ffi::OsString]) -> String {
    let mut hash = Sha256::new();
    for argument in command {
        let bytes = argument.as_os_str().as_bytes();
        hash.update(bytes.len().to_be_bytes());
        hash.update(bytes);
    }
    format!("{:x}", hash.finalize())
}

pub fn save_event(root: &Path, event: &GuardEvent) -> Result<()> {
    validate_event(event, &event.id)?;
    config::atomic_write_json(&event_path(root, &event.id)?, event)
}

pub fn load_event(root: &Path, id: &str) -> Result<GuardEvent> {
    let path = event_path(root, id)?;
    if !path.exists() {
        return Err(OsmanthusError::EventNotFound(id.to_owned()));
    }
    load_event_path(&path)
}

pub fn consume_matching_permit(root: &Path, digest: &str, now: i64) -> Result<Option<GuardEvent>> {
    for path in event_paths(root)? {
        let mut event = load_event_path(&path)?;
        if event.status == EventStatus::Approved
            && event.command_digest == digest
            && event.approved_until_unix.is_some_and(|until| now <= until)
        {
            event.status = EventStatus::Consumed;
            event.consumed_at_unix = Some(now);
            save_event(root, &event)?;
            return Ok(Some(event));
        }
    }
    Ok(None)
}

pub fn list_events(root: &Path) -> Result<Vec<GuardEvent>> {
    let mut events: Vec<GuardEvent> = Vec::new();
    for path in event_paths(root)? {
        events.push(load_event_path(&path)?);
    }
    events.sort_by_key(|event| std::cmp::Reverse(event.created_at_unix));
    Ok(events)
}

fn event_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let events_dir = root.join(EVENTS_DIR);
    config::validate_state_root(&events_dir)?;
    for entry in fs::read_dir(events_dir)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn event_path(root: &Path, id: &str) -> Result<PathBuf> {
    Uuid::parse_str(id)
        .map_err(|_| OsmanthusError::InvalidState(format!("invalid event ID: {id}")))?;
    Ok(root.join(EVENTS_DIR).join(format!("{id}.json")))
}

fn load_event_path(path: &Path) -> Result<GuardEvent> {
    let event: GuardEvent = config::load_private_json(path)?;
    let file_id = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            OsmanthusError::InvalidState(format!("invalid event filename: {}", path.display()))
        })?;
    validate_event(&event, file_id)?;
    Ok(event)
}

fn validate_event(event: &GuardEvent, file_id: &str) -> Result<()> {
    if event.schema_version != 1 {
        return Err(OsmanthusError::InvalidState(format!(
            "unsupported event schema version: {}",
            event.schema_version
        )));
    }
    Uuid::parse_str(&event.id)
        .map_err(|_| OsmanthusError::InvalidState(format!("invalid event ID: {}", event.id)))?;
    if event.id != file_id {
        return Err(OsmanthusError::InvalidState(format!(
            "event ID does not match filename: {file_id}"
        )));
    }
    if event.command_digest.len() != 64
        || !event
            .command_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || event.command.is_empty()
        || event.command.len() > 256
        || event.command.iter().any(|value| value.len() > 256)
        || event.rule_ids.is_empty()
        || event.rule_ids.len() > 1_000
        || event.expires_at_unix < event.created_at_unix
    {
        return Err(OsmanthusError::InvalidState(format!(
            "event contains invalid bounded fields: {}",
            event.id
        )));
    }
    let valid_status = match event.status {
        EventStatus::Pending => {
            event.approved_at_unix.is_none()
                && event.approved_until_unix.is_none()
                && event.consumed_at_unix.is_none()
        }
        EventStatus::Approved => {
            event.approved_at_unix.is_some()
                && event.approved_until_unix.is_some()
                && event.consumed_at_unix.is_none()
        }
        EventStatus::Consumed => {
            event.approved_at_unix.is_some()
                && event.approved_until_unix.is_some()
                && event.consumed_at_unix.is_some()
        }
    };
    if !valid_status {
        return Err(OsmanthusError::InvalidState(format!(
            "event status fields are inconsistent: {}",
            event.id
        )));
    }
    if event
        .approved_at_unix
        .is_some_and(|approved| approved < event.created_at_unix)
        || event
            .approved_until_unix
            .zip(event.approved_at_unix)
            .is_some_and(|(until, approved)| until < approved)
        || event
            .consumed_at_unix
            .zip(event.approved_at_unix)
            .is_some_and(|(consumed, approved)| consumed < approved)
    {
        return Err(OsmanthusError::InvalidState(format!(
            "event timestamps are inconsistent: {}",
            event.id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt;

    use super::*;

    #[test]
    fn digest_preserves_non_utf8_argument_bytes() {
        let first = vec![std::ffi::OsString::from_vec(vec![0x66, 0x80])];
        let second = vec![std::ffi::OsString::from_vec(vec![0x66, 0x81])];
        assert_ne!(command_digest(&first), command_digest(&second));
    }

    #[test]
    fn digest_preserves_argument_boundaries() {
        let split = vec!["ab".into(), "c".into()];
        let joined = vec!["a".into(), "bc".into()];
        assert_ne!(command_digest(&split), command_digest(&joined));
    }
}
