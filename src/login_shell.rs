use std::ffi::{CStr, OsStr};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{OsmanthusError, Result};

pub const OSMANTHUS_SHELL: &str = "/usr/bin/osmanthus-shell";
const USERMOD: &str = "/usr/sbin/usermod";
const SYSTEM_SHELLS: &str = "/etc/shells";
const MAX_NSS_BUFFER: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemAccount {
    pub name: String,
    pub shell: PathBuf,
}

pub fn account(uid: u32) -> Result<SystemAccount> {
    if uid == 0 {
        return Err(OsmanthusError::InvalidState(
            "root cannot be enrolled as a monitored login identity".to_owned(),
        ));
    }
    let initial = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = usize::try_from(initial).unwrap_or(16_384).max(1_024);
    loop {
        let mut record = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; size];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && size < MAX_NSS_BUFFER {
            size = (size * 2).min(MAX_NSS_BUFFER);
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status).into());
        }
        if result.is_null() {
            return Err(OsmanthusError::InvalidState(format!(
                "operating-system UID does not exist: {uid}"
            )));
        }
        let name = unsafe { CStr::from_ptr(record.pw_name) }
            .to_str()
            .map_err(|_| OsmanthusError::InvalidState("account name is not UTF-8".to_owned()))?
            .to_owned();
        let shell = unsafe { CStr::from_ptr(record.pw_shell) }.to_bytes();
        return Ok(SystemAccount {
            name,
            shell: PathBuf::from(OsStr::from_bytes(shell)),
        });
    }
}

pub fn validate_osmanthus_shell() -> Result<()> {
    validate_executable(Path::new(OSMANTHUS_SHELL), "Osmanthus login shell")
}

pub fn validate_real_shell(path: &Path) -> Result<()> {
    validate_executable(path, "real login shell")
}

pub fn ensure_registered() -> Result<()> {
    let path = Path::new(SYSTEM_SHELLS);
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() > 65_536
    {
        return Err(OsmanthusError::UnsafePath(format!(
            "{SYSTEM_SHELLS} must be a root-owned, non-writable regular file of at most 64 KiB"
        )));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    if contents.lines().any(|line| line.trim() == OSMANTHUS_SHELL) {
        return Ok(());
    }
    if !contents.ends_with('\n') && !contents.is_empty() {
        file.write_all(b"\n")?;
    }
    writeln!(file, "{OSMANTHUS_SHELL}")?;
    file.sync_data()?;
    Ok(())
}

pub fn set_shell(uid: u32, expected: &Path, replacement: &Path) -> Result<()> {
    let before = account(uid)?;
    if before.shell == replacement {
        return Ok(());
    }
    if before.shell != expected {
        return Err(OsmanthusError::InvalidState(format!(
            "UID {uid} login shell changed concurrently: expected {}, found {}",
            expected.display(),
            before.shell.display()
        )));
    }
    validate_executable(replacement, "replacement login shell")?;
    validate_executable(Path::new(USERMOD), "usermod")?;
    let output = Command::new(USERMOD)
        .arg("--shell")
        .arg(replacement)
        .arg(&before.name)
        .output()?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(OsmanthusError::Execution(format!(
            "usermod failed for UID {uid}{}",
            if message.is_empty() {
                String::new()
            } else {
                format!(": {message}")
            }
        )));
    }
    let after = account(uid)?;
    if after.shell != replacement {
        return Err(OsmanthusError::InvalidState(format!(
            "UID {uid} login shell was not updated to {}",
            replacement.display()
        )));
    }
    Ok(())
}

fn validate_executable(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || mode & 0o111 == 0
        || mode & 0o022 != 0
    {
        return Err(OsmanthusError::UnsafePath(format!(
            "{label} must be a root-owned, non-writable executable file: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_current_non_root_account_without_mutating_it() {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return;
        }
        let account = account(uid).unwrap();
        assert!(!account.name.is_empty());
        assert!(account.shell.is_absolute());
    }

    #[test]
    fn refuses_root_enrollment() {
        assert!(account(0).is_err());
    }
}
