use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::{self, AUDIT_FILE};
use crate::{OsmanthusError, Result};

#[derive(Debug, Serialize)]
pub struct AuditRecord<'a> {
    pub schema_version: u32,
    pub timestamp: String,
    pub action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_ids: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<i32>,
}

impl<'a> AuditRecord<'a> {
    pub fn new(action: &'a str) -> Result<Self> {
        Ok(Self {
            schema_version: 1,
            timestamp: OffsetDateTime::now_utc().format(&Rfc3339)?,
            action,
            event_id: None,
            command_digest: None,
            command: None,
            rule_ids: None,
            result: None,
        })
    }
}

pub fn append(root: &Path, record: &AuditRecord<'_>) -> Result<()> {
    config::validate_state_root(root)?;
    let path = root.join(AUDIT_FILE);
    config::validate_private_path(&path)?;
    let mut file = OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let lock_result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if lock_result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    file.write_all(&line)?;
    file.sync_data().map_err(OsmanthusError::from)
}
