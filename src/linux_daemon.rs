use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use libbpf_rs::{MapHandle, RingBufferBuilder};
use time::OffsetDateTime;

use crate::daemon::{
    DaemonAuditRecord, DaemonAuditSink, DaemonCore, JsonlDaemonAudit, PeerIdentity,
    SystemAdministratorAuthenticator,
};
use crate::enforcement::EnforcementPolicy;
use crate::linux_bpf::{
    KernelEvent, KernelEventKind, PersistentLinuxBpfBackend, parse_kernel_event,
};
use crate::protocol::{self, PROTOCOL_VERSION, Response, ResponseBody};
use crate::{OsmanthusError, Result, system_policy};

pub const RUNTIME_DIRECTORY: &str = "/run/osmanthus";
pub const SOCKET_PATH: &str = "/run/osmanthus/osmanthusd.sock";
const LOCK_PATH: &str = "/run/osmanthus/osmanthusd.lock";
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(2);

pub fn run() -> Result<()> {
    system_policy::require_root()?;
    let _lock = acquire_process_lock()?;
    let policy_file = system_policy::load()?.ok_or(OsmanthusError::SystemPolicyNotInitialized)?;
    let policy = EnforcementPolicy::from_parts_with_maintenance(
        policy_file.protected_roots,
        policy_file.monitored_uids,
        policy_file.maintenance,
    )?;
    let audit = JsonlDaemonAudit::production()?;

    let backend = PersistentLinuxBpfBackend::install_or_open(&policy)?;
    let event_map = backend.event_map_handle()?;
    let audit_failures = spawn_kernel_audit(event_map, JsonlDaemonAudit::production()?);
    let mut core =
        DaemonCore::new_with_backend(&policy, backend, SystemAdministratorAuthenticator, audit)?;
    let listener = create_listener()?;

    loop {
        if let Ok(message) = audit_failures.try_recv() {
            return Err(OsmanthusError::InvalidState(format!(
                "kernel audit consumer stopped: {message}"
            )));
        }
        match listener.accept() {
            Ok((mut stream, _address)) => {
                if let Err(error) = handle_connection(&mut core, &mut stream) {
                    eprintln!("osmanthusd: client request failed: {error}");
                }
                if core.shutdown_requested() {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn spawn_kernel_audit(map: MapHandle, mut audit: JsonlDaemonAudit) -> Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let callback_sender = sender.clone();
        let mut builder = RingBufferBuilder::new();
        if let Err(error) = builder.add(&map, move |bytes| {
            let result = parse_kernel_event(bytes).and_then(|event| {
                let record = kernel_audit_record(&event);
                audit.append(&record)
            });
            match result {
                Ok(()) => 0,
                Err(error) => {
                    let _ = callback_sender.send(error.to_string());
                    -1
                }
            }
        }) {
            let _ = sender.send(error.to_string());
            return;
        }
        let ring = match builder.build() {
            Ok(ring) => ring,
            Err(error) => {
                let _ = sender.send(error.to_string());
                return;
            }
        };
        loop {
            if let Err(error) = ring.poll(Duration::from_millis(250)) {
                let _ = sender.send(error.to_string());
                return;
            }
        }
    });
    receiver
}

fn kernel_audit_record(event: &KernelEvent) -> DaemonAuditRecord {
    let process = format!("process.{}.{}", event.tgid, event.pid);
    match event.kind {
        KernelEventKind::ProcessExec => DaemonAuditRecord {
            schema_version: 1,
            timestamp_unix: OffsetDateTime::now_utc().unix_timestamp(),
            action: "process_exec",
            peer_uid: event.uid,
            peer_cgroup_id: None,
            session_id: Some(process),
            target: Some(event.filename.clone()),
            operation: Some(event.command.clone()),
            decision: None,
            lease_id: None,
        },
        KernelEventKind::ResourceBlocked => DaemonAuditRecord {
            schema_version: 1,
            timestamp_unix: OffsetDateTime::now_utc().unix_timestamp(),
            action: "resource_blocked",
            peer_uid: event.uid,
            peer_cgroup_id: None,
            session_id: Some(process),
            target: Some(format!("{}:{}", event.device, event.inode)),
            operation: Some(event.action.map_or("mount_boundary".to_owned(), |action| {
                format!("{action:?}").to_ascii_lowercase()
            })),
            decision: Some("blocked".to_owned()),
            lease_id: None,
        },
    }
}

fn handle_connection<B: crate::daemon::EnforcementBackend>(
    core: &mut DaemonCore<SystemAdministratorAuthenticator, JsonlDaemonAudit, B>,
    stream: &mut UnixStream,
) -> Result<()> {
    stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT))?;
    let peer = peer_identity(stream)?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let Some(request) = protocol::read_request(&mut reader)? else {
        return Ok(());
    };
    let request_id = request.request_id.clone();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let response = match core.handle(peer, request, now) {
        Ok(response) => response,
        Err(error) => Response {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            body: ResponseBody::Error {
                code: error_code(&error).to_owned(),
                message: error.to_string(),
            },
        },
    };
    protocol::write_response(stream, &response)
}

fn create_listener() -> Result<UnixListener> {
    let directory = Path::new(RUNTIME_DIRECTORY);
    validate_runtime_directory(directory)?;
    let socket = Path::new(SOCKET_PATH);
    match fs::symlink_metadata(socket) {
        Ok(metadata) => {
            if metadata.uid() != 0 || !metadata.file_type().is_socket() {
                return Err(OsmanthusError::UnsafePath(format!(
                    "{SOCKET_PATH} must be a root-owned Unix socket"
                )));
            }
            fs::remove_file(socket)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o622))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn acquire_process_lock() -> Result<File> {
    let directory = Path::new(RUNTIME_DIRECTORY);
    if !directory.exists() {
        fs::create_dir(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    validate_runtime_directory(directory)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(LOCK_PATH)?;
    let metadata = lock.metadata()?;
    if metadata.uid() != 0 || !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(OsmanthusError::UnsafePath(format!(
            "{LOCK_PATH} must be a root-owned regular file with mode 600"
        )));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        return Err(OsmanthusError::InvalidState(format!(
            "another osmanthusd process holds {LOCK_PATH}: {error}"
        )));
    }
    lock.set_len(0)?;
    writeln!(&lock, "{}", std::process::id())?;
    lock.sync_data()?;
    Ok(lock)
}

fn validate_runtime_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != 0
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o755
    {
        return Err(OsmanthusError::UnsafePath(format!(
            "{} must be a root-owned directory with mode 755",
            path.display()
        )));
    }
    Ok(())
}

fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(OsmanthusError::InvalidState(
            "daemon peer credentials have an invalid size".to_owned(),
        ));
    }
    let pid = u32::try_from(credentials.pid)
        .map_err(|_| OsmanthusError::InvalidState("daemon peer PID is invalid".to_owned()))?;
    Ok(PeerIdentity {
        uid: credentials.uid,
        cgroup_id: cgroup_id_for_pid(pid)?,
    })
}

pub fn current_cgroup_id() -> Result<u64> {
    cgroup_id_for_pid(std::process::id())
}

fn cgroup_id_for_pid(pid: u32) -> Result<u64> {
    let contents = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let relative = parse_unified_cgroup_path(&contents)?;
    let root = Path::new("/sys/fs/cgroup").canonicalize()?;
    let path = if relative == Path::new("/") {
        root.clone()
    } else {
        root.join(relative.strip_prefix("/").map_err(|_| {
            OsmanthusError::InvalidState("peer cgroup path is not absolute".to_owned())
        })?)
        .canonicalize()?
    };
    if !path.starts_with(&root) {
        return Err(OsmanthusError::UnsafePath(format!(
            "peer cgroup escaped {}",
            root.display()
        )));
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.ino() == 0 {
        return Err(OsmanthusError::UnsafePath(format!(
            "peer cgroup is not a real cgroup directory: {}",
            path.display()
        )));
    }
    Ok(metadata.ino())
}

fn parse_unified_cgroup_path(contents: &str) -> Result<PathBuf> {
    let mut paths = contents.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = paths.next().ok_or_else(|| {
        OsmanthusError::InvalidState("peer is not attached to a cgroup v2 hierarchy".to_owned())
    })?;
    if paths.next().is_some() || value.is_empty() {
        return Err(OsmanthusError::InvalidState(
            "peer has an ambiguous cgroup v2 identity".to_owned(),
        ));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(OsmanthusError::UnsafePath(format!(
            "invalid peer cgroup path: {value}"
        )));
    }
    Ok(path)
}

fn error_code(error: &OsmanthusError) -> &'static str {
    match error {
        OsmanthusError::InvalidCode => "invalid_code",
        OsmanthusError::RootRequired => "root_required",
        OsmanthusError::SystemPolicyNotInitialized => "policy_not_initialized",
        OsmanthusError::UnsafePath(_) => "unsafe_path",
        _ => "request_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_absolute_unified_cgroup_path() {
        assert_eq!(
            parse_unified_cgroup_path("0::/user.slice/session-7.scope\n").unwrap(),
            PathBuf::from("/user.slice/session-7.scope")
        );
        assert!(parse_unified_cgroup_path("2:cpu:/legacy\n").is_err());
        assert!(parse_unified_cgroup_path("0::/one\n0::/two\n").is_err());
        assert!(parse_unified_cgroup_path("0::/one/../two\n").is_err());
    }

    #[test]
    fn resolves_the_current_kernel_cgroup_identity() {
        assert_ne!(current_cgroup_id().unwrap(), 0);
    }
}
