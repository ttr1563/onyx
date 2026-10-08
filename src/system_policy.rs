use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::{self, Config};
use crate::policy::PolicyFile;
use crate::{OsmanthusError, Result};

pub const SYSTEM_POLICY_DIR: &str = "/etc/osmanthus";
pub const SYSTEM_POLICY_FILE: &str = "policy.json";
pub const SYSTEM_POLICY_DIGEST_FILE: &str = "policy.sha256";
pub const ADMIN_STATE_DIR: &str = "/etc/osmanthus/admin";

const MAX_POLICY_BYTES: u64 = 1_048_576;
const SYSTEM_DIRECTORY_MODE: u32 = 0o755;
const SYSTEM_FILE_MODE: u32 = 0o444;

pub fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(OsmanthusError::RootRequired);
    }
    Ok(())
}

pub fn admin_state_dir() -> &'static Path {
    Path::new(ADMIN_STATE_DIR)
}

pub fn load() -> Result<Option<PolicyFile>> {
    PolicyStore::new(Path::new(SYSTEM_POLICY_DIR), 0).load()
}

pub fn initialize(admin_config: &Config) -> Result<()> {
    require_root()?;
    let target = Path::new(SYSTEM_POLICY_DIR);
    if path_exists_without_following(target)? {
        return Err(OsmanthusError::AlreadyInitialized(
            SYSTEM_POLICY_DIR.to_owned(),
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| OsmanthusError::UnsafePath(SYSTEM_POLICY_DIR.to_owned()))?;
    let temporary = parent.join(format!(".osmanthus-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        fs::create_dir(&temporary)?;
        fs::set_permissions(
            &temporary,
            fs::Permissions::from_mode(SYSTEM_DIRECTORY_MODE),
        )?;
        PolicyStore::new(&temporary, 0).write(&PolicyFile::default())?;
        config::initialize(&temporary.join("admin"), admin_config)?;
        fs::rename(&temporary, target)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

pub fn save(policy: &PolicyFile) -> Result<()> {
    require_root()?;
    let store = PolicyStore::new(Path::new(SYSTEM_POLICY_DIR), 0);
    if store.load()?.is_none() {
        return Err(OsmanthusError::SystemPolicyNotInitialized);
    }
    store.write(policy)
}

struct PolicyStore {
    directory: PathBuf,
    expected_uid: u32,
}

impl PolicyStore {
    fn new(directory: &Path, expected_uid: u32) -> Self {
        Self {
            directory: directory.to_path_buf(),
            expected_uid,
        }
    }

    fn policy_path(&self) -> PathBuf {
        self.directory.join(SYSTEM_POLICY_FILE)
    }

    fn digest_path(&self) -> PathBuf {
        self.directory.join(SYSTEM_POLICY_DIGEST_FILE)
    }

    fn ensure_directory(&self) -> Result<()> {
        if path_exists_without_following(&self.directory)? {
            return self.validate_directory();
        }
        fs::create_dir(&self.directory)?;
        fs::set_permissions(
            &self.directory,
            fs::Permissions::from_mode(SYSTEM_DIRECTORY_MODE),
        )?;
        self.validate_directory()
    }

    fn validate_directory(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(OsmanthusError::UnsafePath(format!(
                "{} must be a real directory",
                self.directory.display()
            )));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != self.expected_uid || mode != SYSTEM_DIRECTORY_MODE {
            return Err(OsmanthusError::UnsafePath(format!(
                "{} must be owned by uid {} with mode 755",
                self.directory.display(),
                self.expected_uid
            )));
        }
        Ok(())
    }

    fn load(&self) -> Result<Option<PolicyFile>> {
        let directory_exists = path_exists_without_following(&self.directory)?;
        let policy_exists = path_exists_without_following(&self.policy_path())?;
        let digest_exists = path_exists_without_following(&self.digest_path())?;
        if !directory_exists && !policy_exists && !digest_exists {
            return Ok(None);
        }
        self.validate_directory()?;
        if !policy_exists || !digest_exists {
            return Err(OsmanthusError::InvalidState(
                "system policy or its digest is missing".to_owned(),
            ));
        }

        let policy_bytes = self.read_file(&self.policy_path(), MAX_POLICY_BYTES)?;
        let digest_bytes = self.read_file(&self.digest_path(), 128)?;
        let expected = std::str::from_utf8(&digest_bytes)
            .map_err(|_| {
                OsmanthusError::InvalidState("system policy digest is not UTF-8".to_owned())
            })?
            .trim_end();
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(OsmanthusError::InvalidState(
                "system policy digest is invalid".to_owned(),
            ));
        }
        let actual = format!("{:x}", Sha256::digest(&policy_bytes));
        if expected != actual {
            return Err(OsmanthusError::InvalidState(
                "system policy digest does not match policy.json".to_owned(),
            ));
        }

        let policy: PolicyFile = serde_json::from_slice(&policy_bytes)?;
        policy.validate()?;
        Ok(Some(policy))
    }

    fn read_file(&self, path: &Path, maximum: u64) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        let mode = metadata.permissions().mode() & 0o777;
        if !metadata.is_file() || metadata.uid() != self.expected_uid || mode != SYSTEM_FILE_MODE {
            return Err(OsmanthusError::UnsafePath(format!(
                "{} must be a regular file owned by uid {} with mode 444",
                path.display(),
                self.expected_uid
            )));
        }
        if metadata.len() > maximum {
            return Err(OsmanthusError::InvalidState(format!(
                "system policy file is too large: {}",
                path.display()
            )));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn write(&self, policy: &PolicyFile) -> Result<()> {
        self.ensure_directory()?;
        policy.validate()?;
        for path in [self.policy_path(), self.digest_path()] {
            if path_exists_without_following(&path)? {
                self.read_file(&path, MAX_POLICY_BYTES)?;
            }
        }

        let mut policy_bytes = serde_json::to_vec_pretty(policy)?;
        policy_bytes.push(b'\n');
        let digest_bytes = format!("{:x}\n", Sha256::digest(&policy_bytes)).into_bytes();
        let policy_temporary = self.temporary_path(SYSTEM_POLICY_FILE);
        let digest_temporary = self.temporary_path(SYSTEM_POLICY_DIGEST_FILE);
        let result = (|| -> Result<()> {
            self.write_temporary(&policy_temporary, &policy_bytes)?;
            self.write_temporary(&digest_temporary, &digest_bytes)?;
            fs::rename(&policy_temporary, self.policy_path())?;
            fs::rename(&digest_temporary, self.digest_path())?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&policy_temporary);
            let _ = fs::remove_file(&digest_temporary);
        }
        result
    }

    fn temporary_path(&self, name: &str) -> PathBuf {
        self.directory
            .join(format!(".{name}.{}.tmp", Uuid::new_v4()))
    }

    fn write_temporary(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SYSTEM_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(SYSTEM_FILE_MODE))?;
        Ok(())
    }
}

fn path_exists_without_following(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use tempfile::TempDir;

    use super::*;
    use crate::policy::{CustomRule, RiskLevel};

    fn store(temp: &TempDir) -> PolicyStore {
        PolicyStore::new(&temp.path().join("etc-osmanthus"), unsafe {
            libc::geteuid()
        })
    }

    fn rule() -> CustomRule {
        CustomRule {
            id: "production-terraform".to_owned(),
            executable: "terraform".to_owned(),
            argument_contains: vec!["apply".to_owned(), "production".to_owned()],
            risk: RiskLevel::Critical,
            reason: "production change".to_owned(),
        }
    }

    #[test]
    fn writes_and_loads_read_only_policy_with_digest() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        let mut policy = PolicyFile::default();
        policy.add(rule()).unwrap();
        store.write(&policy).unwrap();

        assert_eq!(store.load().unwrap().unwrap().rules.len(), 1);
        assert_eq!(
            fs::metadata(store.policy_path()).unwrap().mode() & 0o777,
            SYSTEM_FILE_MODE
        );
        assert_eq!(fs::metadata(store.digest_path()).unwrap().uid(), unsafe {
            libc::geteuid()
        });
    }

    #[test]
    fn rejects_digest_mismatch() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        store.write(&PolicyFile::default()).unwrap();
        fs::set_permissions(
            store.policy_path(),
            fs::Permissions::from_mode(SYSTEM_FILE_MODE | 0o200),
        )
        .unwrap();
        fs::write(store.policy_path(), b"{}\n").unwrap();
        fs::set_permissions(
            store.policy_path(),
            fs::Permissions::from_mode(SYSTEM_FILE_MODE),
        )
        .unwrap();

        assert!(
            matches!(store.load(), Err(OsmanthusError::InvalidState(message)) if message.contains("digest does not match"))
        );
    }

    #[test]
    fn rejects_writable_or_symlinked_system_files() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        store.write(&PolicyFile::default()).unwrap();
        fs::set_permissions(store.policy_path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(store.load(), Err(OsmanthusError::UnsafePath(_))));

        fs::remove_file(store.policy_path()).unwrap();
        std::os::unix::fs::symlink(store.digest_path(), store.policy_path()).unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn incomplete_policy_fails_closed() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        store.write(&PolicyFile::default()).unwrap();
        fs::remove_file(store.digest_path()).unwrap();
        assert!(
            matches!(store.load(), Err(OsmanthusError::InvalidState(message)) if message.contains("missing"))
        );
    }

    #[test]
    fn existing_empty_directory_fails_closed() {
        let temp = TempDir::new().unwrap();
        let store = store(&temp);
        store.ensure_directory().unwrap();

        assert!(
            matches!(store.load(), Err(OsmanthusError::InvalidState(message)) if message.contains("missing"))
        );
    }
}
